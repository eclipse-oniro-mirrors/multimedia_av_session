/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "migrate_avsession_server.h"

#include <chrono>
#include <thread>

#include "audio_device_manager.h"
#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_log.h"
#include "avsession_service.h"
#include "softbus/softbus_session_utils.h"
#include "migrate_avsession_constant.h"
#include "base64_utils.h"
#include "avsession_pixel_map_adapter.h"
#include "pixel_map.h"
#include "image_packer.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {
void MigrateAVSessionServer::OnConnectProxy(const std::string &deviceId)
{
    SLOGI("OnConnectProxy: %{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    isSoftbusConnecting_ = true;
    deviceId_ = deviceId;
    ObserveControllerChanged(deviceId);
    SendSpecialKeepaliveData();
    SendRemoteControllerList(deviceId);
}

void MigrateAVSessionServer::OnDisconnectProxy(const std::string &deviceId)
{
    SLOGI("OnDisConnectProxy: %{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    isSoftbusConnecting_ = false;
    if (servicePtr_ == nullptr) {
        SLOGE("do NotifyMigrateStop without servicePtr, return");
        return;
    }
    servicePtr_->NotifyMigrateStop(deviceId);
}

int32_t MigrateAVSessionServer::GetCharacteristic()
{
    return MSG_HEAD_MODE;
}

void MigrateAVSessionServer::ObserveControllerChanged(const std::string &deviceId)
{
    std::vector<AVSessionDescriptor> descriptors;
    auto res = servicePtr_->GetAllSessionDescriptors(descriptors);
    if (res != AVSESSION_SUCCESS) {
        SLOGW("GetAllSessionDescriptors fail");
        return;
    }

    for (auto &item : descriptors) {
        if (item.sessionType_ != AVSession::SESSION_TYPE_AUDIO ||
            item.elementName_.GetBundleName().empty() ||
            item.elementName_.GetBundleName() == ANCO_AUDIO_BUNDLE_NAME) {
            continue;
        }
        if (item.isTopSession_) {
            std::lock_guard lockGuard(topSessionLock_);
            topSessionId_ = item.sessionId_;
        }
        CreateController(item.sessionId_);
    }
}

void MigrateAVSessionServer::CreateController(const std::string &sessionId)
{
    std::lock_guard lockGuard(migrateControllerLock_);
    auto it = playerIdToControllerCallbackMap_.find(sessionId);
    if (it != playerIdToControllerCallbackMap_.end()) {
        SLOGW("CreateControlller has registered");
        return;
    }
    sptr<IRemoteObject> proxyObject;
    int32_t ret = servicePtr_->CreateControllerInner(sessionId, proxyObject);
    if (ret != AVSESSION_SUCCESS && !(ret == ERR_CONTROLLER_IS_EXIST && proxyObject != nullptr)) {
        SLOGW("CreateControllerInner fail");
        return;
    }
    sptr<AVControllerItem> controller = iface_cast<AVControllerItem>(proxyObject);
    if (controller == nullptr) {
        SLOGW("controller is null");
        return;
    }
    std::shared_ptr<AVControllerObserver> callback = std::make_shared<AVControllerObserver>(sessionId);
    std::weak_ptr<MigrateAVSessionServer> migrageServerWeak(shared_from_this());
    callback->Init(migrageServerWeak);
    ret = controller->RegisterAVControllerCallback(callback);
    if (ret != AVSESSION_SUCCESS) {
        SLOGW("RegisteAVControllerCallback fail");
        return;
    }
    AVMetaData::MetaMaskType metaDataFilter(METADATA_MASK_ALL);
    AVPlaybackState::PlaybackStateMaskType playFilter(PLAYBACK_MASK_ALL);
    controller->SetMetaFilter(metaDataFilter);
    controller->SetPlaybackFilter(playFilter);
    UpdateCache(sessionId, controller, callback, true);
}

void MigrateAVSessionServer::ClearCacheBySessionId(const std::string &sessionId)
{
    std::lock_guard lockGuard(migrateControllerLock_);
    auto it = playerIdToControllerMap_.find(sessionId);
    if (it != playerIdToControllerMap_.end()) {
        if (std::count(sortControllerList_.begin(), sortControllerList_.end(), it->second) > 0) {
            SLOGI("ClearCacheBySessionId in and remove controller in sortList");
            sortControllerList_.remove(it->second);
        }
        playerIdToControllerMap_.erase(it);
    }

    auto item = playerIdToControllerCallbackMap_.find(sessionId);
    if (item != playerIdToControllerCallbackMap_.end()) {
        playerIdToControllerCallbackMap_.erase(item);
    }
}

// LCOV_EXCL_START
void MigrateAVSessionServer::UpdateCache(const std::string &sessionId, sptr<AVControllerItem> avcontroller,
    std::shared_ptr<AVControllerObserver> callback, bool isAdd)
{
    if (isAdd) {
        if (avcontroller == nullptr) {
            return;
        }
        std::lock_guard lockGuard(migrateControllerLock_);
        playerIdToControllerMap_.insert({sessionId, avcontroller});
        playerIdToControllerCallbackMap_.insert({sessionId, callback});
        sortControllerList_.push_back(avcontroller);
    } else {
        ClearCacheBySessionId(sessionId);
    }
}
// LCOV_EXCL_STOP

void MigrateAVSessionServer::StopObserveControllerChanged(const std::string &deviceId)
{
    SLOGI("StopObserveControllerChanged with id %{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    std::lock_guard lockGuard(migrateControllerLock_);
    for (auto it = sortControllerList_.begin(); it != sortControllerList_.end(); it++) {
        (*it)->Destroy();
        SLOGI("Controller destroy");
    }
    deviceId_ = "";
    playerIdToControllerMap_.clear();
    sortControllerList_.clear();
    playerIdToControllerCallbackMap_.clear();
}

// LCOV_EXCL_START
void MigrateAVSessionServer::OnBytesReceived(const std::string &deviceId, const std::string &data)
{
    SLOGI("OnBytesReceived: %{public}s", data.c_str());
    if (data.length() < MSG_HEAD_LENGTH) {
        SLOGW("OnBytesReceived: invalid data");
        return;
    }
    if (data[1] == SYNC_COMMAND) {
        ProcControlCommand(data);
    } else if (data[1] == COLD_START) {
        SLOGW("COLD_START not support");
    }
}
// LCOV_EXCL_STOP

void MigrateAVSessionServer::ProcControlCommand(const std::string &data)
{
    std::string jsonStr = data.substr(MSG_HEAD_LENGTH);
    SLOGI("ProcControlCommand: %{public}s", jsonStr.c_str());
    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(jsonStr, root)) {
        SLOGE("json parse fail");
        return;
    }
    if (!root.isMember(PLAYER_ID) || !root.isMember(MEDIA_COMMAND) ||
        !root.isMember(COMMAND)) {
        SLOGE("json parse with error member");
        return;
    }
    std::string playerId = root[PLAYER_ID].isString() ?
        root[PLAYER_ID].asString() : "ERROR_PLAYER_ID";
    sptr<AVControllerItem> avcontroller{nullptr};
    auto res = GetControllerById(playerId, avcontroller);
    if (res != AVSESSION_SUCCESS || avcontroller == nullptr) {
        SLOGW("GetControllerById fail");
        return;
    }
    int mediaCommand = root[MEDIA_COMMAND].isInt() ? root[MEDIA_COMMAND].asInt() : -1;
    std::string command = root[COMMAND].isString() ? root[COMMAND].asString() : "ERROR_COMMAND";
    SLOGI("ProcContolCommand mediaCommand: %{public}d", mediaCommand);
    std::string extras = (root.isMember(EXTRAS) && root[EXTRAS].isString()) ? root[EXTRAS].asString() : "ERROR_EXTRAS";
    switch (mediaCommand) {
        case SYNC_MEDIASESSION_CALLBACK_ON_COMMAND:
            SendCommandProc(command, avcontroller);
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_MEDIABUTTON_EVENT:
            MediaButtonEventProc(command, avcontroller);
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_PLAY_FROM_SEARCH:
        case SYNC_MEDIASESSION_CALLBACK_ON_PLAY_FROM_MEDIAID:
        case SYNC_MEDIASESSION_CALLBACK_ON_CUSTOMACTION:
            CommandWithExtrasProc(mediaCommand, command, extras, avcontroller);
            break;
        default:
            PlaybackCommandDataProc(mediaCommand, command, avcontroller);
            break;
    }
}

// LCOV_EXCL_START
int32_t MigrateAVSessionServer::GetControllerById(const std::string &sessionId, sptr<AVControllerItem> &controller)
{
    if (sessionId.empty()) {
        SLOGW("empty sessionId");
        return AVSESSION_ERROR;
    }

    std::lock_guard lockGuard(migrateControllerLock_);
    for (auto it = playerIdToControllerMap_.begin(); it != playerIdToControllerMap_.end(); it++) {
        std::string foundId = it->first;
        if (it->first == sessionId) {
            controller = it->second;
            return AVSESSION_SUCCESS;
        }
    }
    SLOGW("controller not found");
    return AVSESSION_ERROR;
}

int32_t MigrateAVSessionServer::GetAllControllers(std::vector<sptr<AVControllerItem>> &controller)
{
    std::lock_guard lockGuard(migrateControllerLock_);
    for (auto it = playerIdToControllerMap_.begin(); it != playerIdToControllerMap_.end(); it++) {
        controller.push_back(it->second);
    }
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

void MigrateAVSessionServer::Init(AVSessionService *ptr)
{
    servicePtr_ = ptr;
}

// LCOV_EXCL_START
void MigrateAVSessionServer::OnSessionCreate(const AVSessionDescriptor &descriptor)
{
    SLOGI("OnSessionCreate");
    std::string sessionId = descriptor.sessionId_;
    if (sessionId.empty()) {
        SLOGW("no valid avsession");
        return;
    }
    if (descriptor.sessionType_ != AVSession::SESSION_TYPE_AUDIO ||
        descriptor.elementName_.GetBundleName().empty() ||
        descriptor.elementName_.GetBundleName() == ANCO_AUDIO_BUNDLE_NAME) {
        SLOGI("not audio avsession or anco audio");
        return;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    CreateController(sessionId);
    IPCSkeleton::SetCallingIdentity(identity);
}

void MigrateAVSessionServer::OnSessionRelease(const AVSessionDescriptor &descriptor)
{
    std::string sessionId = descriptor.sessionId_;
    if (sessionId.empty()) {
        SLOGW("no valid avsession");
        return;
    }
    SLOGI("OnSessionRelease : %{public}s", sessionId.c_str());
    if (sessionId.compare(topSessionId_) == 0) {
        std::string msg = AudioDeviceManager::GetInstance().GenerateEmptySession();
        AudioDeviceManager::GetInstance().SendRemoteAudioMsg(deviceId_, msg);
    }
    ClearCacheBySessionId(sessionId);
}

void MigrateAVSessionServer::OnTopSessionChange(const AVSessionDescriptor &descriptor)
{
    SLOGI("OnTopSessionChange sessionId_: %{public}s", descriptor.sessionId_.c_str());
    {
        std::lock_guard lockGuard(topSessionLock_);
        if (descriptor.sessionType_ != AVSession::SESSION_TYPE_AUDIO ||
            descriptor.elementName_.GetBundleName().empty() ||
            descriptor.elementName_.GetBundleName() == ANCO_AUDIO_BUNDLE_NAME) {
            SLOGI("not audio avsession or anco audio");
            return;
        }
        if (topSessionId_ == descriptor.sessionId_) {
            return;
        }
        lastSessionId_ = topSessionId_;
        topSessionId_ = descriptor.sessionId_;
        auto it = playerIdToControllerMap_.find(descriptor.sessionId_);
        if (it == playerIdToControllerMap_.end()) {
            CreateController(descriptor.sessionId_);
        }
    }
    SendRemoteControllerList(deviceId_);
}

void MigrateAVSessionServer::SortControllers(std::list<sptr<AVControllerItem>> controllers)
{
    SLOGI("SortControllers");
    std::lock_guard topSessionLockGuard(topSessionLock_);
    if (topSessionId_.empty()) {
        SLOGE("SortControllers topSessionId is null");
        return;
    }
    std::lock_guard lockGuard(migrateControllerLock_);
    for (auto iter = controllers.begin(); iter != controllers.end(); iter++) {
        if ((*iter)->GetSessionId() == topSessionId_) {
            controllers.splice(controllers.begin(), controllers, iter);
            break;
        }
    }
}

void MigrateAVSessionServer::SendRemoteControllerList(const std::string &deviceId)
{
    SLOGI("SendRemoteControllerList");
    SortControllers(sortControllerList_);
    std::vector<sptr<AVControllerItem>> avcontroller;
    std::lock_guard lockGuard(topSessionLock_);
    auto res = GetAllControllers(avcontroller);
    if (res != AVSESSION_SUCCESS) {
        SLOGE("SendRemoteControllerList no top session");
        return;
    }
    if (avcontroller.empty()) {
        SLOGE("SendRemoteControllerList avcontroller is null");
        return;
    }
    std::string msg = ConvertControllersToStr(avcontroller);

    if (!deviceId.empty()) {
        SendByte(deviceId, msg);
    } else {
        SendByteToAll(msg);
    }
    AVSessionEventHandler::GetInstance().AVSessionPostTask([this]() {
        DelaySendMetaData();
        }, "DelaySendMetaData", DELAY_TIME);
}

void MigrateAVSessionServer::SendRemoteControllerInfo(const std::string &deviceId, std::string msg)
{
    if (!deviceId.empty()) {
        SendByte(deviceId, msg);
    }
}

void MigrateAVSessionServer::DelaySendMetaData()
{
    sptr<AVControllerItem> avcontroller{nullptr};
    GetControllerById(topSessionId_, avcontroller);
    if (avcontroller != nullptr) {
        AVMetaData resultMetaData;
        resultMetaData.Reset();
        avcontroller->GetAVMetaData(resultMetaData);
        AVMetaData metaDataInfo = resultMetaData;
        std::shared_ptr<AVSessionPixelMap> pixelImage = resultMetaData.GetMediaImage();
        std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
        if (pixelImage != nullptr) {
            SLOGI("ready to copy image");
            mediaImage->SetInnerImgBuffer(pixelImage->GetInnerImgBuffer());
            metaDataInfo.SetMediaImage(mediaImage);
            std::string metaDataStr = ConvertMetadataInfoToStr(topSessionId_,
                SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED, metaDataInfo);
            SendByte(deviceId_, metaDataStr);
        }
    }
}

std::string MigrateAVSessionServer::ConvertControllersToStr(
    std::vector<sptr<AVControllerItem>> avcontrollers)
{
    SLOGI("ConvertControllersToStr");
    Json::Value jsonArray(Json::arrayValue);
    int32_t sessionNums = 0;
    for (auto& controller : avcontrollers) {
        if (sessionNums >= MAX_SESSION_NUMS) {
            break;
        }
        if (controller == nullptr) {
            continue;
        }
        std::string playerId = controller->GetSessionId();
        Json::Value jsonObject = ConvertControllerToJson(controller);
        jsonObject[PLAYER_ID] = playerId;
        if (playerId.compare(topSessionId_) == 0) {
            jsonArray[0] = jsonObject;
            sessionNums++;
        } else if (playerId.compare(lastSessionId_) == 0) {
            jsonArray[1] = jsonObject;
            sessionNums++;
        } else {
            SLOGD("session not deal");
        }
    }
    Json::Value jsonData;
    jsonData[MEDIA_CONTROLLER_LIST] = jsonArray;

    Json::FastWriter writer;
    std::string jsonStr = writer.write(jsonData);
    char header[] = {MSG_HEAD_MODE, SYNC_CONTROLLER_LIST, '\0'};
    std::string msg = std::string(header) + jsonStr;
    return msg;
}
// LCOV_EXCL_STOP

Json::Value MigrateAVSessionServer::ConvertControllerToJson(sptr<AVControllerItem> avcontroller)
{
    SLOGI("ConvertControllerToJson");
    Json::Value metadata;
    AVMetaData data;
    if (AVSESSION_SUCCESS == avcontroller->GetAVMetaData(data)) {
        metadata = ConvertMetadataToJson(data);
    }

    AVPlaybackState state;
    if (AVSESSION_SUCCESS == avcontroller->GetAVPlaybackState(state)) {
        metadata[PLAYBACK_STATE] = RebuildPlayState(state);
    }

    metadata[SESSION_INFO] =
        "OAAAAEJOREwBAAAAEwAAAEMAbwBuAHQAcgBvAGwAbABlAHIAVwBoAGkAdABlAEwAaQBzAHQAAAAU\nAAAAAQAAAA==\n";
    metadata[VOLUME_INFO] = VOLUMN_INFO;
    metadata[PACKAGE_NAME] = GetBundleName(avcontroller->GetSessionId());
    return metadata;
}

// LCOV_EXCL_START
std::string MigrateAVSessionServer::GetBundleName(std::string sessionId)
{
    std::vector<AVSessionDescriptor> descriptors;

    auto res = servicePtr_->GetAllSessionDescriptors(descriptors);
    if (res != AVSESSION_SUCCESS) {
        SLOGW("GetAllSessionDescriptors fail");
        return "";
    }
    for (auto iter = descriptors.begin(); iter != descriptors.end(); iter++) {
        if (iter->sessionId_ == sessionId) {
            std::string bundleName = iter->elementName_.GetBundleName();
            std::string abilityName = iter->elementName_.GetAbilityName();
            SLOGI("bundleName: %{public}s abilityName: %{public}s", bundleName.c_str(), abilityName.c_str());
            return bundleName;
        }
    }
    SLOGW("GetBundleName fail");
    return "";
}

int32_t MigrateAVSessionServer::ConvertStateFromSingleToDouble(int32_t state)
{
    switch (state) {
        case AVPlaybackState::PLAYBACK_STATE_PLAY:
            return MEDIA_SESSION_PLAYBACK_STATE_PLAY;
        case AVPlaybackState::PLAYBACK_STATE_PAUSE:
            return MEDIA_SESSION_PLAYBACK_STATE_PAUSE;
        case AVPlaybackState::PLAYBACK_STATE_STOP:
            return MEDIA_SESSION_PLAYBACK_STATE_STOP;
        case AVPlaybackState::PLAYBACK_STATE_ERROR:
            return MEDIA_SESSION_PLAYBACK_STATE_ERROR;
        default:
            SLOGW("unknowState: %{public}d", state);
            break;
    }
    return state;
}

std::string MigrateAVSessionServer::RebuildPlayState(const AVPlaybackState &playbackState)
{
    int64_t actions = 1911;
    Parcel parcel;
    parcel.WriteInt32(ConvertStateFromSingleToDouble(playbackState.GetState()))
        && parcel.WriteInt64(playbackState.GetPosition().elapsedTime_)
        && parcel.WriteFloat(playbackState.GetSpeed())
        && parcel.WriteInt64(playbackState.GetPosition().updateTime_)
        && parcel.WriteInt64(playbackState.GetBufferedTime())
        && parcel.WriteInt64(actions)
        && parcel.WriteInt32(-1)
        && parcel.WriteInt64(playbackState.GetActiveItemId())
        && parcel.WriteInt32(1)
        && parcel.WriteCString("")
        && parcel.WriteInt32(-1);

    uint8_t* pointer = reinterpret_cast<uint8_t*>(parcel.GetData());
    size_t len = parcel.GetDataSize();
    std::vector<uint8_t> vec(len);
    for (size_t i = 0; i < len; ++i) {
        vec[i] = pointer[i];
    }
    std::string str = Base64Utils::Base64Encode(vec);
    return str;
}

Json::Value MigrateAVSessionServer::ConvertMetadataToJson(const AVMetaData &metadata)
{
    Json::Value result;
    if (metadata.IsValid()) {
        SLOGI("ConvertMetadataToJson without img");
        result[METADATA_TITLE] = metadata.GetTitle();
        result[METADATA_ARTIST] = metadata.GetArtist();
        std::string mediaImage = "";
        std::vector<uint8_t> outputData(BUFFER_MAX_SIZE);
        int32_t ret = CompressToJPEG(metadata, outputData);
        mediaImage = ((ret == true) && (!outputData.empty())) ? Base64Utils::Base64Encode(outputData) : "";
        result[METADATA_IMAGE] = mediaImage;
    } else {
        result[METADATA_TITLE] = "";
        result[METADATA_ARTIST] = "";
        result[METADATA_IMAGE] = "";
    }
    return result;
}

bool MigrateAVSessionServer::CompressToJPEG(const AVMetaData &metadata, std::vector<uint8_t> &outputData)
{
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = metadata.GetMediaImage();
    std::shared_ptr<Media::PixelMap> pixelMap;
    if (innerPixelMap == nullptr) {
        return false;
    } else {
        pixelMap = AVSessionPixelMapAdapter::ConvertFromInner(innerPixelMap);
    }
    
    Media::ImagePacker imagePacker;
    Media::PackOption option;
    option.format = "image/jpeg";
    option.quality = DEFAULT_QUALITY;
    uint32_t maxSize = outputData.size();
    uint32_t ret = imagePacker.StartPacking(outputData.data(), maxSize, option);
    if (ret != 0) {
        SLOGI("Failed to start packing");
        return false;
    }
    if (pixelMap == nullptr) {
        SLOGE("CompressToJPEG with pixel get null");
        return false;
    }
    ret = imagePacker.AddImage(*pixelMap);
    if (ret != 0) {
        SLOGI("Failed to add image");
        return false;
    }
    int64_t packedSize = 0;
    ret = imagePacker.FinalizePacking(packedSize);
    if (ret != 0) {
        SLOGI("Failed to finalize packing");
        return false;
    }

    outputData.resize(packedSize);
    return true;
}

std::string MigrateAVSessionServer::ConvertMetadataInfoToStr(
    const std::string playerId, int32_t controlCommand, const AVMetaData &metadata)
{
    SLOGI("ConvertMetadataInfoToStr");
    Json::Value metaDataJson = ConvertMetadataToJson(metadata);
    metaDataJson[PLAYER_ID] = playerId;
    metaDataJson[MEDIA_INFO] = controlCommand;
    Json::FastWriter writer;
    std::string msg = writer.write(metaDataJson);
    char header[] = {MSG_HEAD_MODE, SYNC_CONTROLLER, '\0'};
    return std::string(header) + msg;
}

void MigrateAVSessionServer::SendSpecialKeepaliveData()
{
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(HEART_BEAT_TIME));
        if (this->isSoftbusConnecting_) {
            char header[] = {MSG_HEAD_MODE, SYNC_HEARTBEAT, '\0'};
            std::string data = std::string(header);
            SendByteToAll(data);
            SendSpecialKeepaliveData();
            SLOGI("send special mediamession data to proxy connection");
        } else {
            SLOGI("send special mediamession data to proxy exit");
        }
    }).detach();
}

void MigrateAVSessionServer::SendCommandProc(const std::string &command, sptr<AVControllerItem> controller)
{
    if (command == EVENT_COMMAND_UNLOCK_LYRIC || command == EVENT_COMMAND_SHOW_LYRIC ||
       command == EVENT_COMMAND_HIDE_LYRIC) {
    } else {
        SLOGW("command is not support: %{public}s", command.c_str());
    }
}

void MigrateAVSessionServer::MediaButtonEventProc(const std::string &command, sptr<AVControllerItem> controller)
{
    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    if (keyEvent == nullptr) {
        SLOGE("MediaButtonEventProc with key event null");
        return;
    }
    keyEvent->SetKeyCode(atoi(command.c_str()));
    controller->SendAVKeyEvent(*keyEvent.get());
}

void MigrateAVSessionServer::CommandWithExtrasProc(int mediaCommand, const std::string &extrasCommand,
    const std::string &extras, sptr<AVControllerItem> controller)
{
    SLOGI("CommandWithExtrasProc mediaCommand is: %{public}d", mediaCommand);
    switch (mediaCommand) {
        case SYNC_MEDIASESSION_CALLBACK_ON_PLAY_FROM_SEARCH:
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_PLAY_FROM_MEDIAID:
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_CUSTOMACTION:
            break;
        default:
            SLOGW("mediaCommand is not support: %{public}d", mediaCommand);
            break;
    }
}

void MigrateAVSessionServer::PlaybackCommandDataProc(int mediaCommand, const std::string &command,
    sptr<AVControllerItem> controller)
{
    SLOGI("PlaybackComandDataProc Command is: %{public}d", mediaCommand);
    AVControlCommand cmd;
    switch (mediaCommand) {
        case SYNC_MEDIASESSION_CALLBACK_ON_PLAY:
            AVSessionEventHandler::GetInstance().AVSessionPostTask([=]() {
                AVControlCommand cmd;
                cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
                controller->SendControlCommand(cmd);
                }, "DelaySendPlayCom", DELAY_PLAY_COM_TIME);
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_PAUSE:
            cmd.SetCommand(AVControlCommand::SESSION_CMD_PAUSE);
            controller->SendControlCommand(cmd);
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_STOP:
            cmd.SetCommand(AVControlCommand::SESSION_CMD_STOP);
            controller->SendControlCommand(cmd);
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_SKIP_TO_PREVIOUS:
            cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
            controller->SendControlCommand(cmd);
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_SKIP_TO_NEXT:
            cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
            controller->SendControlCommand(cmd);
            break;
        case SYNC_MEDIASESSION_CALLBACK_ON_SET_RATING:
            break;
        case SYNC_CONTROLLER_CALLBACK_ON_AUDIOINFO_CHANGED:
            break;
        default:
            SLOGI("mediaCommand is not support: %{public}s", command.c_str());
            break;
    }
}

void MigrateAVSessionServer::OnMetaDataChange(const std::string & playerId, const AVMetaData &data)
{
    std::string metaDataStr = ConvertMetadataInfoToStr(playerId, SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED, data);
    SLOGI("MigrateAVSessionServer OnMetaDataChange: %{public}s", metaDataStr.c_str());

    SendByte(deviceId_, metaDataStr);
}
// LCOV_EXCL_STOP

void MigrateAVSessionServer::OnPlaybackStateChanged(const std::string &playerId, const AVPlaybackState &state)
{
    Json::Value value;
    value[PLAYER_ID] = playerId;
    value[MEDIA_INFO] = SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED;
    value[CALLBACK_INFO] = RebuildPlayState(state);
    char header[] = {MSG_HEAD_MODE, SYNC_CONTROLLER, '\0'};
    Json::FastWriter writer;
    std::string msg = writer.write(value);
    std::string result = std::string(header) + msg;
    SendByte(deviceId_, result);
}

// LCOV_EXCL_START
void AVControllerObserver::OnSessionDestroy()
{
    SLOGI("OnSessionDestroy");
}

void AVControllerObserver::OnPlaybackStateChange(const AVPlaybackState &state)
{
    std::shared_ptr<MigrateAVSessionServer> server = migrateServer_.lock();
    if (server != nullptr && state.GetState() != AVPlaybackState::PLAYBACK_STATE_INITIAL) {
        server->OnPlaybackStateChanged(playerId_, state);
    }
}

void AVControllerObserver::OnMetaDataChange(const AVMetaData &data)
{
    SLOGI("OnMetaDataChange");
    std::shared_ptr<MigrateAVSessionServer> server = migrateServer_.lock();
    if (server != nullptr) {
        server->OnMetaDataChange(playerId_, data);
    }
}

void AVControllerObserver::Init(std::weak_ptr<MigrateAVSessionServer> migrateServer)
{
    migrateServer_ = migrateServer;
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession