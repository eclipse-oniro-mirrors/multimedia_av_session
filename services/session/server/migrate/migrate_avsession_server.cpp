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
MigrateAVSessionServer::MigrateAVSessionServer(int32_t migrateMode)
{
    SLOGI("server start with:%{public}d", migrateMode);
    migrateMode_ = migrateMode;
}

MigrateAVSessionServer::~MigrateAVSessionServer()
{
    {
        std::lock_guard lockGuard(migrateControllerLock_);
        for (auto& pair : playerIdToControllerCallbackMap_) {
            std::shared_ptr<AVControllerObserver> controllerObserver = pair.second;
            CHECK_AND_CONTINUE(controllerObserver != nullptr);
            controllerObserver->Release();
        }
    }
    {
        std::lock_guard lockGuard(cacheJsonLock_);
        if (metaDataCache_ != nullptr) {
            cJSON_Delete(metaDataCache_);
            metaDataCache_ = nullptr;
        }
        if (playbackStateCache_ != nullptr) {
            cJSON_Delete(playbackStateCache_);
            playbackStateCache_ = nullptr;
        }
    }
    SLOGI("MigrateAVSessionServer quit");
}

void MigrateAVSessionServer::OnConnectProxy(const std::string &deviceId)
{
    SLOGI("OnConnectProxy: %{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    if (deviceId_ != deviceId && !deviceId_.empty()) {
        SLOGI("onConnect but already:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId_).c_str());
        return;
    }
    isSoftbusConnecting_ = true;
    deviceId_ = deviceId;
    if (migrateMode_ == MIGRATE_MODE_NEXT) {
        SLOGI("connect process as next behavior");
        LocalFrontSessionArrive(lastSessionId_);
        RegisterAudioCallbackAndTrigger();
        return;
    }
    ObserveControllerChanged(deviceId);
    SendSpecialKeepaliveData();
    SendRemoteHistorySessionList(deviceId);
    SendRemoteControllerList(deviceId);
}

void MigrateAVSessionServer::OnDisconnectProxy(const std::string &deviceId)
{
    SLOGI("OnDisConnectProxy: %{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    if (deviceId_ != deviceId && !deviceId_.empty()) {
        SLOGI("onDisconnect but already:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId_).c_str());
        return;
    }
    UnregisterAudioCallback();
    isSoftbusConnecting_ = false;
    if (servicePtr_ == nullptr) {
        SLOGE("do NotifyMigrateStop without servicePtr, return");
        return;
    }
    if (migrateMode_ == MIGRATE_MODE_NEXT) {
        SLOGI("migrate next should not bother migrate cross");
        return;
    }
    servicePtr_->NotifyMigrateStop(deviceId);
}

void MigrateAVSessionServer::RegisterAudioCallbackAndTrigger()
{
    AudioAdapter::GetInstance().RegisterVolumeKeyEventCallback(volumeKeyEventCallbackFunc_);
    volumeKeyEventCallbackFunc_(AudioAdapter::GetInstance().GetVolume());

    AudioAdapter::GetInstance().SetAvailableDeviceChangeCallback(availableDeviceChangeCallbackFunc_);
    availableDeviceChangeCallbackFunc_(AudioAdapter::GetInstance().GetAvailableDevices());

    AudioAdapter::GetInstance().SetPreferredOutputDeviceChangeCallback(preferredDeviceChangeCallbackFunc_);
    preferredDeviceChangeCallbackFunc_(AudioAdapter::GetInstance().GetPreferredOutputDeviceForRendererInfo());
}

void MigrateAVSessionServer::UnregisterAudioCallback()
{
    if (migrateMode_ == MIGRATE_MODE_NEXT) {
        AudioAdapter::GetInstance().UnregisterVolumeKeyEventCallback();
        AudioAdapter::GetInstance().UnsetAvailableDeviceChangeCallback();
        AudioAdapter::GetInstance().UnsetPreferredOutputDeviceChangeCallback();
    }
}

int32_t MigrateAVSessionServer::GetCharacteristic()
{
    if (migrateMode_ == MIGRATE_MODE_NEXT) {
        return MSG_HEAD_MODE_FOR_NEXT;
    }
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
    {
        std::lock_guard lockGuard(migrateControllerLock_);
        auto it = playerIdToControllerCallbackMap_.find(sessionId);
        if (it != playerIdToControllerCallbackMap_.end()) {
            SLOGW("CreateControlller has registered");
            return;
        }
    }
    sptr<IRemoteObject> proxyObject;
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "createController without servicePtr");
    int32_t ret = servicePtr_->CreateControllerInner(sessionId, proxyObject, migrateMode_);
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
    callback->Init(migrageServerWeak, migrateMode_);
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
    SLOGD("OnBytesReceived: %{public}s", data.c_str());
    if (data.length() < MSG_HEAD_LENGTH) {
        SLOGW("OnBytesReceived: invalid data");
        return;
    }
    if (migrateMode_ == MIGRATE_MODE_NEXT) {
        ProcFromNext(deviceId, data);
        return;
    }
    if (data[1] == SYNC_COMMAND) {
        ProcControlCommand(data);
    } else if (data[1] == COLD_START) {
        StartConfigHistorySession(data);
    }
}
// LCOV_EXCL_STOP

void MigrateAVSessionServer::ProcControlCommand(const std::string &data)
{
    std::string jsonStr = data.substr(MSG_HEAD_LENGTH);
    SLOGI("ProcControlCommand: %{public}s", jsonStr.c_str());
    cJSON* root = nullptr;
    if (!SoftbusSessionUtils::TransferStrToJson(jsonStr, root)) {
        SLOGE("json parse fail");
        return;
    }
    if (!cJSON_HasObjectItem(root, PLAYER_ID) || !cJSON_HasObjectItem(root, MEDIA_COMMAND) ||
        !cJSON_HasObjectItem(root, COMMAND)) {
        SLOGE("json parse with error member");
        cJSON_Delete(root);
        return;
    }
    std::string playerId = SoftbusSessionUtils::GetStringFromJson(root, PLAYER_ID);
    playerId = playerId.empty() ? "ERROR_PLAYER_ID" : playerId;
    sptr<AVControllerItem> avcontroller{nullptr};
    auto res = GetControllerById(playerId, avcontroller);
    if (res != AVSESSION_SUCCESS || avcontroller == nullptr) {
        SLOGW("GetControllerById fail");
        cJSON_Delete(root);
        return;
    }
    int mediaCommand = SoftbusSessionUtils::GetIntFromJson(root, MEDIA_COMMAND);
    std::string command = SoftbusSessionUtils::GetStringFromJson(root, COMMAND);
    command = command.empty() ? "ERROR_COMMAND" : command;
    SLOGI("ProcContolCommand mediaCommand: %{public}d", mediaCommand);
    std::string extras = SoftbusSessionUtils::GetStringFromJson(root, EXTRAS);
    if (extras.empty()) {
        extras = "ERROR_EXTRAS";
    }
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
    cJSON_Delete(root);
}

void MigrateAVSessionServer::StartConfigHistorySession(const std::string &data)
{
    std::string jsonStr = data.substr(MSG_HEAD_LENGTH);
    SLOGI("StartConfigHistorySession: %{public}s", jsonStr.c_str());
    cJSON* jsonData = nullptr;
    if (!SoftbusSessionUtils::TransferStrToJson(jsonStr, jsonData)) {
        SLOGE("jStartConfigHistorySession: parse json failed");
        return;
    }

    if (!cJSON_HasObjectItem(jsonData, PLAYER_ID)) {
        SLOGE("StartConfigHistorySession: json parse with error member");
        cJSON_Delete(jsonData);
        return;
    }
    std::string playerId = SoftbusSessionUtils::GetStringFromJson(jsonData, PLAYER_ID);
    if (playerId.empty()) {
        playerId = "ERROR_PLAYER_ID";
    }

    int32_t ret = servicePtr_->StartAVPlayback(playerId, "");
    SLOGI("StartConfigHistorySession StartAVPlayback %{public}s, ret=%{public}d", playerId.c_str(), ret);
    cJSON_Delete(jsonData);
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
    std::vector<AVSessionDescriptor> descriptors;
    auto res = servicePtr_->GetAllSessionDescriptors(descriptors);
    if (res != AVSESSION_SUCCESS) {
        SLOGW("GetAllSessionDescriptors failed");
        return AVSESSION_ERROR;
    }
    std::lock_guard lockGuard(migrateControllerLock_);
    for (auto iter = descriptors.begin(); iter != descriptors.end(); iter++) {
        if (iter->sessionType_ != AVSession::SESSION_TYPE_AUDIO ||
            iter->elementName_.GetBundleName().empty() ||
            iter->elementName_.GetBundleName() == ANCO_AUDIO_BUNDLE_NAME ||
            releaseSessionId_.compare(iter->sessionId_) == 0) {
            continue;
        }
        auto it = playerIdToControllerMap_.find(iter->sessionId_);
        controller.push_back(it->second);
    }
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

void MigrateAVSessionServer::Init(AVSessionService *ptr)
{
    servicePtr_ = ptr;
    supportCrossMediaPlay_ = false;
}

void MigrateAVSessionServer::ResetSupportCrossMediaPlay(const std::string &extraInfo)
{
    cJSON* jsonData = nullptr;
    if (!SoftbusSessionUtils::TransferStrToJson(extraInfo, jsonData)) {
        SLOGE("json parse fail");
        return;
    }
    bool isSupportSingleFrameMediaPlay = SoftbusSessionUtils::GetBoolFromJson(jsonData,
        IS_SUPPORT_SINGLE_FRAME_MEDIA_PLAY);

    SLOGI("SuperLauncher: isSupportSingleFrameMediaPlay=%{public}d", isSupportSingleFrameMediaPlay);
    supportCrossMediaPlay_ = isSupportSingleFrameMediaPlay;
}

// LCOV_EXCL_START
void MigrateAVSessionServer::OnSessionCreate(const AVSessionDescriptor &descriptor)
{
    if (migrateMode_ == MIGRATE_MODE_NEXT) {
        return;
    }
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
    if (migrateMode_ == MIGRATE_MODE_NEXT) {
        return;
    }
    std::string sessionId = descriptor.sessionId_;
    if (sessionId.empty()) {
        SLOGW("no valid avsession");
        return;
    }
    SLOGI("OnSessionRelease : %{public}s", sessionId.c_str());
    ClearCacheBySessionId(sessionId);
    releaseSessionId_ = sessionId;
    releaseSessionBundleName_ = descriptor.elementName_.GetBundleName();
    SendRemoteHistorySessionList(deviceId_);
    SendRemoteControllerList(deviceId_);
    releaseSessionId_ = "";
    releaseSessionBundleName_ = "";
}

void MigrateAVSessionServer::OnTopSessionChange(const AVSessionDescriptor &descriptor)
{
    if (migrateMode_ == MIGRATE_MODE_NEXT) {
        return;
    }
    SLOGI("OnTopSessionChange sessionId_: %{public}s***",
        descriptor.sessionId_.substr(0, UNMASK_CHAR_NUM).c_str());
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
    SendRemoteHistorySessionList(deviceId_);
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
    std::vector<sptr<AVControllerItem>> avcontroller;
    auto res = GetAllControllers(avcontroller);
    SortControllers(sortControllerList_);
    if (res != AVSESSION_SUCCESS) {
        SLOGE("SendRemoteControllerList no top session");
        return;
    }
    if (avcontroller.empty()) {
        SLOGE("SendRemoteControllerList avcontroller is null");
        ClearRemoteControllerList(deviceId);
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

void MigrateAVSessionServer::SendRemoteHistorySessionList(const std::string &deviceId)
{
    if (!supportCrossMediaPlay_) {
        SLOGI("SendRemoteHistorySessionList, Remote does not support cross media play");
        return;
    }

    std::vector<AVSessionDescriptor> descriptors;
    auto res = servicePtr_->GetAllSessionDescriptors(descriptors);
    if (res != AVSESSION_SUCCESS) {
        SLOGW("GetAllSessionDescriptors fail");
        return;
    }

    std::vector<AVSessionDescriptor> hisDescriptors;
    auto hisRes = servicePtr_->GetHistoricalSessionDescriptors(MAX_HISTORY_SESSION_NUMS, hisDescriptors);
    if (hisRes != AVSESSION_SUCCESS) {
        SLOGW("GetHistoricalSessionDescriptors fail");
        return;
    }

    std::string msg = ConvertHistorySessionListToStr(descriptors, hisDescriptors);
    if (!deviceId.empty()) {
        SendByte(deviceId, msg);
    } else {
        SendByteToAll(msg);
    }
}

bool MigrateAVSessionServer::ConvertSessionDescriptorsToCJSON(cJSON* jsonArray, int32_t& descriptorNums)
{
    cJSON* releaseData = SoftbusSessionUtils::GetNewCJSONObject();
    if (releaseData == nullptr) {
        SLOGE("get releaseData json with nullptr");
        return false;
    }

    std::string supportModule;
    std::string profile;
    if (BundleStatusAdapter::GetInstance().IsSupportPlayIntent(releaseSessionBundleName_, supportModule, profile)) {
        if (!SoftbusSessionUtils::AddStringToJson(releaseData, PLAYER_ID, releaseSessionId_)) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                PLAYER_ID, releaseSessionId_.c_str());
            cJSON_Delete(releaseData);
            return false;
        }
        if (!SoftbusSessionUtils::AddStringToJson(releaseData, PACKAGE_NAME, releaseSessionBundleName_)) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                PACKAGE_NAME, releaseSessionBundleName_.c_str());
            cJSON_Delete(releaseData);
            return false;
        }
        if (!SoftbusSessionUtils::AddJsonToJsonArray(jsonArray, descriptorNums, releaseData)) {
            SLOGE("AddJsonToJsonArray with index:%{public}d fail", descriptorNums);
            return false;
        }
        descriptorNums++;
    }
    return true;
}

bool MigrateAVSessionServer::ConvertReleaseSessionToCJSON(cJSON* jsonArray,
    std::vector<AVSessionDescriptor>& sessionDescriptors, int32_t& descriptorNums)
{
    for (auto iter = sessionDescriptors.begin(); iter != sessionDescriptors.end(); iter++) {
        if (iter->sessionType_ != AVSession::SESSION_TYPE_AUDIO ||
            iter->elementName_.GetBundleName().empty() ||
            iter->elementName_.GetBundleName() == ANCO_AUDIO_BUNDLE_NAME ||
            releaseSessionId_.compare(iter->sessionId_) == 0) {
            continue;
        }

        cJSON* jsonData = SoftbusSessionUtils::GetNewCJSONObject();
        if (jsonData == nullptr) {
            SLOGE("get jsonData json with nullptr");
            return false;
        }
        if (!SoftbusSessionUtils::AddStringToJson(jsonData, PLAYER_ID, iter->sessionId_)) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                PLAYER_ID, iter->sessionId_.c_str());
            cJSON_Delete(jsonData);
            return false;
        }
        if (!SoftbusSessionUtils::AddStringToJson(jsonData, PACKAGE_NAME, iter->elementName_.GetBundleName())) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                PACKAGE_NAME, iter->elementName_.GetBundleName().c_str());
            cJSON_Delete(jsonData);
            return false;
        }
        if (!SoftbusSessionUtils::AddJsonToJsonArray(jsonArray, descriptorNums, jsonData)) {
            SLOGE("AddJsonToJsonArray with index:%{public}d fail", descriptorNums);
            return false;
        }
        descriptorNums++;
    }
    return true;
}

bool MigrateAVSessionServer::ConvertHisSessionDescriptorsToCJSON(cJSON* jsonArray,
    std::vector<AVSessionDescriptor>& hisSessionDescriptors, int32_t& descriptorNums)
{
    for (auto iter = hisSessionDescriptors.begin(); iter != hisSessionDescriptors.end(); iter++) {
        if (iter->sessionType_ != AVSession::SESSION_TYPE_AUDIO ||
            iter->elementName_.GetBundleName().empty() ||
            iter->elementName_.GetBundleName() == ANCO_AUDIO_BUNDLE_NAME ||
            releaseSessionId_.compare(iter->sessionId_) == 0) {
            continue;
        }

        cJSON* jsonData = SoftbusSessionUtils::GetNewCJSONObject();
        if (jsonData == nullptr) {
            SLOGE("get jsonData json with nullptr");
            return false;
        }
        if (!SoftbusSessionUtils::AddStringToJson(jsonData, PLAYER_ID, iter->sessionId_)) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                PLAYER_ID, iter->sessionId_.c_str());
            cJSON_Delete(jsonData);
            return false;
        }
        if (!SoftbusSessionUtils::AddStringToJson(jsonData, PACKAGE_NAME, iter->elementName_.GetBundleName())) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                PACKAGE_NAME, iter->elementName_.GetBundleName().c_str());
            cJSON_Delete(jsonData);
            return false;
        }
        if (!SoftbusSessionUtils::AddJsonToJsonArray(jsonArray, descriptorNums, jsonData)) {
            SLOGE("AddJsonToJsonArray with index:%{public}d fail", descriptorNums);
            return false;
        }
        descriptorNums++;
    }
    return true;
}

std::string MigrateAVSessionServer::ConvertHistorySessionListToStr(std::vector<AVSessionDescriptor> sessionDescriptors,
    std::vector<AVSessionDescriptor> hisSessionDescriptors)
{
    cJSON* jsonArray = SoftbusSessionUtils::GetNewCJSONArray();
    CHECK_AND_RETURN_RET_LOG(jsonArray != nullptr, "", "get jsonArray with nullptr");
    int32_t descriptorNums = 0;
    if (!releaseSessionId_.empty()) {
        if (!ConvertSessionDescriptorsToCJSON(jsonArray, descriptorNums)) {
            SLOGE("ConvertSessionDescriptorsToCJSON fail");
        }
    }
    if (!ConvertReleaseSessionToCJSON(jsonArray, sessionDescriptors, descriptorNums)) {
        SLOGE("ConvertReleaseSessionToCJSON fail");
    }
    if (!ConvertHisSessionDescriptorsToCJSON(jsonArray, hisSessionDescriptors, descriptorNums)) {
        SLOGE("ConvertHisSessionDescriptorsToCJSON fail");
    }
    cJSON* jsonData = SoftbusSessionUtils::GetNewCJSONObject();
    if (jsonData == nullptr) {
        SLOGE("get jsonData json with nullptr");
        cJSON_Delete(jsonArray);
        return "";
    }
    if (!SoftbusSessionUtils::AddJsonArrayToJson(jsonData, HISTORY_MEDIA_PLAYER_INFO, jsonArray)) {
        SLOGE("add jsonArray into jsonData fail");
        cJSON_Delete(jsonData);
        return "";
    }
    std::string jsonStr;
    SoftbusSessionUtils::TransferJsonToStr(jsonData, jsonStr);
    char header[] = {MSG_HEAD_MODE, GET_HISTORY_MEDIA_INFO, '\0'};
    std::string msg = std::string(header) + jsonStr;
    cJSON_Delete(jsonData);
    return msg;
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
        if (mediaImage != nullptr) {
            mediaImage->Clear();
        }
    }
}

std::string MigrateAVSessionServer::GenerateClearAVSessionMsg()
{
    cJSON* jsonArray = SoftbusSessionUtils::GetNewCJSONArray();
    CHECK_AND_RETURN_RET_LOG(jsonArray != nullptr, "", "get jsonArray with nullptr");
    cJSON* jsonData = SoftbusSessionUtils::GetNewCJSONObject();
    if (jsonData == nullptr) {
        SLOGE("get jsonData json with nullptr");
        cJSON_Delete(jsonArray);
        return "";
    }
    if (!SoftbusSessionUtils::AddJsonArrayToJson(jsonData, MEDIA_CONTROLLER_LIST, jsonArray)) {
        SLOGE("add jsonArray into jsonData fail");
        cJSON_Delete(jsonData);
        return "";
    }
    std::string jsonStr;
    SoftbusSessionUtils::TransferJsonToStr(jsonData, jsonStr);

    char header[] = {MSG_HEAD_MODE, SYNC_CONTROLLER_LIST, '\0'};
    std::string msg = std::string(header) + jsonStr;
    cJSON_Delete(jsonData);
    return msg;
}

std::string MigrateAVSessionServer::GenerateClearHistorySessionMsg()
{
    SLOGI("GenerateClearHistorySessionMsg");
    cJSON* jsonArray = SoftbusSessionUtils::GetNewCJSONArray();
    CHECK_AND_RETURN_RET_LOG(jsonArray != nullptr, "", "get jsonArray with nullptr");
    cJSON* jsonData = SoftbusSessionUtils::GetNewCJSONObject();
    if (jsonData == nullptr) {
        SLOGE("get jsonData json with nullptr");
        cJSON_Delete(jsonArray);
        return "";
    }
    if (!SoftbusSessionUtils::AddJsonArrayToJson(jsonData, HISTORY_MEDIA_PLAYER_INFO, jsonArray)) {
        SLOGE("add jsonArray into jsonData fail");
        cJSON_Delete(jsonData);
        return "";
    }
    std::string jsonStr;
    SoftbusSessionUtils::TransferJsonToStr(jsonData, jsonStr);

    char header[] = {MSG_HEAD_MODE, GET_HISTORY_MEDIA_INFO, '\0'};
    std::string msg = std::string(header) + jsonStr;
    cJSON_Delete(jsonData);
    return msg;
}

void MigrateAVSessionServer::ClearRemoteControllerList(const std::string &deviceId)
{
    std::lock_guard lockGuard(migrateControllerLock_);
    std::string msg = GenerateClearAVSessionMsg();
    if (!deviceId.empty()) {
        SendByte(deviceId, msg);
    }
}

void MigrateAVSessionServer::ClearRemoteHistorySessionList(const std::string &deviceId)
{
    if (!supportCrossMediaPlay_) {
        SLOGI("ClearRemoteHistorySessionList, Remote does not support cross media play");
        return;
    }
    std::lock_guard lockGuard(historySessionLock_);
    std::string msg = GenerateClearHistorySessionMsg();
    if (!deviceId.empty()) {
        SendByte(deviceId, msg);
    }
}

std::string MigrateAVSessionServer::ConvertControllersToStr(
    std::vector<sptr<AVControllerItem>> avcontrollers)
{
    SLOGI("ConvertControllersToStr");
    cJSON* jsonArray = SoftbusSessionUtils::GetNewCJSONArray();
    CHECK_AND_RETURN_RET_LOG(jsonArray != nullptr, "", "get jsonArray with nullptr");
    int32_t sessionNums = 0;
    for (auto& controller : avcontrollers) {
        if (sessionNums >= MAX_SESSION_NUMS) {
            break;
        }
        if (controller == nullptr) {
            continue;
        }
        std::string playerId = controller->GetSessionId();
        cJSON* jsonObject = ConvertControllerToJson(controller);
        CHECK_AND_CONTINUE(jsonObject != nullptr);
        if (cJSON_IsInvalid(jsonObject) || cJSON_IsNull(jsonObject)) {
            SLOGE("get jsonObject from ConvertControllerToJson invalid");
            cJSON_Delete(jsonObject);
            continue;
        }
        if (!SoftbusSessionUtils::AddStringToJson(jsonObject, PLAYER_ID, playerId)) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                PLAYER_ID, playerId.c_str());
            cJSON_Delete(jsonObject);
            continue;
        }
        if (!SoftbusSessionUtils::AddJsonToJsonArray(jsonArray, sessionNums, jsonObject)) {
            SLOGE("AddJsonToJsonArray with index:%{public}d fail", sessionNums);
            continue;
        }
        sessionNums++;
    }
    if (cJSON_IsInvalid(jsonArray) || cJSON_IsNull(jsonArray)) {
        SLOGE("get jsonArray aft add object invalid");
    }
    cJSON* jsonData = SoftbusSessionUtils::GetNewCJSONObject();
    if (jsonData == nullptr) {
        SLOGE("get jsonData json with nullptr");
    }
    if (!SoftbusSessionUtils::AddJsonArrayToJson(jsonData, MEDIA_CONTROLLER_LIST, jsonArray)) {
        SLOGE("add jsonArray into jsonData fail");
    }
    std::string jsonStr;
    SoftbusSessionUtils::TransferJsonToStr(jsonData, jsonStr);

    char header[] = {MSG_HEAD_MODE, SYNC_CONTROLLER_LIST, '\0'};
    std::string msg = std::string(header) + jsonStr;
    cJSON_Delete(jsonData);
    return msg;
}
// LCOV_EXCL_STOP

cJSON* MigrateAVSessionServer::ConvertControllerToJson(sptr<AVControllerItem> avcontroller)
{
    SLOGI("ConvertControllerToJson");
    cJSON* metadata = nullptr;
    AVMetaData data;
    data.Reset();
    avcontroller->GetAVMetaData(data);
    metadata = ConvertMetadataToJson(data);
    CHECK_AND_RETURN_RET_LOG(metadata != nullptr, metadata, "get metadata json with null");
    if (cJSON_IsInvalid(metadata) || cJSON_IsNull(metadata)) {
        SLOGE("get metadata json with invalid");
        cJSON_Delete(metadata);
        return nullptr;
    }

    AVPlaybackState state;
    if (AVSESSION_SUCCESS == avcontroller->GetAVPlaybackState(state)) {
        if (!SoftbusSessionUtils::AddStringToJson(metadata, PLAYBACK_STATE, RebuildPlayState(state))) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                PLAYBACK_STATE, RebuildPlayState(state).c_str());
            cJSON_Delete(metadata);
            return nullptr;
        }
    }
    if (!SoftbusSessionUtils::AddStringToJson(metadata, SESSION_INFO,
        "OAAAAEJOREwBAAAAEwAAAEMAbwBuAHQAcgBvAGwAbABlAHIAVwBoAGkAdABlAEwAaQBzAHQAAAAU\nAAAAAQAAAA==\n")) {
        SLOGE("AddStringToJson with key:%{public}s fail", SESSION_INFO);
        cJSON_Delete(metadata);
        return nullptr;
    }
    if (!SoftbusSessionUtils::AddIntToJson(metadata, VOLUME_INFO, VOLUMN_INFO)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}d fail",
            VOLUME_INFO, VOLUMN_INFO);
        cJSON_Delete(metadata);
        return nullptr;
    }
    if (!SoftbusSessionUtils::AddStringToJson(metadata, PACKAGE_NAME, GetBundleName(avcontroller->GetSessionId()))) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            PACKAGE_NAME, GetBundleName(avcontroller->GetSessionId()).c_str());
        cJSON_Delete(metadata);
        return nullptr;
    }

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

cJSON* MigrateAVSessionServer::ConvertMetadataToJson(const AVMetaData &metadata)
{
    return ConvertMetadataToJson(metadata, true);
}

cJSON* MigrateAVSessionServer::ConvertMetadataToJson(const AVMetaData &metadata, bool includeImage)
{
    cJSON* result = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, result, "get result json with null");
    if (cJSON_IsInvalid(result) || cJSON_IsNull(result)) {
        SLOGE("get result json with invalid");
        cJSON_Delete(result);
        return nullptr;
    }

    if (metadata.IsValid()) {
        SLOGI("ConvertMetadataToJson without img");
        if (!SoftbusSessionUtils::AddStringToJson(result, METADATA_TITLE, metadata.GetTitle())) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                METADATA_TITLE, metadata.GetTitle().c_str());
            cJSON_Delete(result);
            return nullptr;
        }
        if (!SoftbusSessionUtils::AddStringToJson(result, METADATA_ARTIST, metadata.GetArtist())) {
            SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                METADATA_ARTIST, metadata.GetArtist().c_str());
            cJSON_Delete(result);
            return nullptr;
        }
        if (includeImage) {
            std::string mediaImage = "";
            std::vector<uint8_t> outputData(BUFFER_MAX_SIZE);
            bool ret = CompressToJPEG(metadata, outputData);
            mediaImage = ((ret == true) && (!outputData.empty())) ? Base64Utils::Base64Encode(outputData) : "";
            if (!SoftbusSessionUtils::AddStringToJson(result, METADATA_IMAGE, mediaImage)) {
                SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
                    METADATA_IMAGE, mediaImage.c_str());
                cJSON_Delete(result);
                return nullptr;
            }
        }
    } else {
        if (!SoftbusSessionUtils::AddStringToJson(result, METADATA_TITLE, "") ||
            !SoftbusSessionUtils::AddStringToJson(result, METADATA_ARTIST, "") ||
            !SoftbusSessionUtils::AddStringToJson(result, METADATA_IMAGE, "")) {
            cJSON_Delete(result);
            return nullptr;
        }
    }
    return result;
}

void MigrateAVSessionServer::UpdateLatestTitleAndArtist(const AVMetaData &metadata)
{
    if (latestAssetId_ != metadata.GetAssetId()) {
        latestTitle_ = "";
        latestArtist_ = "";
    }
    if (!metadata.GetTitle().empty()) {
        latestTitle_ = metadata.GetTitle();
    }
    if (!metadata.GetArtist().empty()) {
        latestArtist_ = metadata.GetArtist();
    }
    latestAssetId_ = metadata.GetAssetId();
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
    cJSON* metaDataJson = ConvertMetadataToJson(metadata);
    CHECK_AND_RETURN_RET_LOG(metaDataJson != nullptr, "", "get metaDataJson from ConvertMetadataToJson nullptr");
    if (cJSON_IsInvalid(metaDataJson) || cJSON_IsNull(metaDataJson)) {
        SLOGE("get metaDataJson from ConvertMetadataToJson invalid");
        cJSON_Delete(metaDataJson);
        return "";
    }
    if (!SoftbusSessionUtils::AddStringToJson(metaDataJson, PLAYER_ID, playerId)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            PLAYER_ID, playerId.c_str());
        cJSON_Delete(metaDataJson);
        return "";
    }
    if (!SoftbusSessionUtils::AddIntToJson(metaDataJson, MEDIA_INFO, controlCommand)) {
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail",
            MEDIA_INFO, controlCommand);
        cJSON_Delete(metaDataJson);
        return "";
    }

    std::string msg;
    SoftbusSessionUtils::TransferJsonToStr(metaDataJson, msg);
    cJSON_Delete(metaDataJson);
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

void MigrateAVSessionServer::OnHistoricalRecordChange()
{
    SendRemoteHistorySessionList(deviceId_);
}

void MigrateAVSessionServer::OnMetaDataChange(const std::string & playerId, const AVMetaData &data)
{
    SLOGI("MigrateAVSessionServer OnMetaDataChange: %{public}s", playerId.c_str());
    AVSessionEventHandler::GetInstance().AVSessionPostTask([this]() {
        DelaySendMetaData();
        }, "DelaySendMetaData", DELAY_METADATA_TIME);
}
// LCOV_EXCL_STOP

void MigrateAVSessionServer::OnPlaybackStateChanged(const std::string &playerId, const AVPlaybackState &state)
{
    cJSON* value = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_LOG(value != nullptr, "get value nullptr");
    if (cJSON_IsInvalid(value) || cJSON_IsNull(value)) {
        SLOGE("get value invalid");
        cJSON_Delete(value);
        return;
    }
    if (!SoftbusSessionUtils::AddStringToJson(value, PLAYER_ID, playerId)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            PLAYER_ID, playerId.c_str());
        cJSON_Delete(value);
        return;
    }
    if (!SoftbusSessionUtils::AddIntToJson(value, MEDIA_INFO,
        SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED)) {
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail",
            MEDIA_INFO, SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED);
        cJSON_Delete(value);
        return;
    }
    if (!SoftbusSessionUtils::AddStringToJson(value, CALLBACK_INFO, RebuildPlayState(state))) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            CALLBACK_INFO, RebuildPlayState(state).c_str());
        cJSON_Delete(value);
        return;
    }

    char header[] = {MSG_HEAD_MODE, SYNC_CONTROLLER, '\0'};
    std::string msg;
    SoftbusSessionUtils::TransferJsonToStr(value, msg);
    cJSON_Delete(value);
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
    if (server != nullptr && migrateMode_ == MIGRATE_MODE_NEXT) {
        server->HandleFocusPlaybackStateChange(playerId_, state);
        return;
    }
    if (server != nullptr && state.GetState() != AVPlaybackState::PLAYBACK_STATE_INITIAL) {
        server->OnPlaybackStateChanged(playerId_, state);
    }
}

void AVControllerObserver::OnMetaDataChange(const AVMetaData &data)
{
    SLOGI("OnMetaDataChange check migrateMode:%{public}d", migrateMode_);
    std::shared_ptr<MigrateAVSessionServer> server = migrateServer_.lock();
    if (server != nullptr && migrateMode_ == MIGRATE_MODE_NEXT) {
        server->HandleFocusMetaDataChange(playerId_, data);
        return;
    }
    if (server != nullptr) {
        server->OnMetaDataChange(playerId_, data);
    }
}

void AVControllerObserver::OnValidCommandChange(const std::vector<int32_t> &cmds)
{
    std::shared_ptr<MigrateAVSessionServer> server = migrateServer_.lock();
    if (server != nullptr && migrateMode_ == MIGRATE_MODE_NEXT) {
        server->HandleFocusValidCommandChange(playerId_, cmds);
        return;
    }
}

void AVControllerObserver::Init(std::weak_ptr<MigrateAVSessionServer> migrateServer, int32_t migrateMode)
{
    migrateServer_ = migrateServer;
    migrateMode_ = migrateMode;
}

void AVControllerObserver::Release()
{
    migrateServer_.reset();
    migrateMode_ = 0;
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession