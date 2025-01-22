/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <chrono>
#include <thread>

#include "migrate_avsession_proxy.h"

#include "avsession_log.h"
#include "avsession_service.h"
#include "softbus/softbus_session_utils.h"

namespace OHOS::AVSession {

MigrateAVSessionProxy::MigrateAVSessionProxy(AVSessionService *ptr, int32_t mode)
{
    mMode_ = mode;
    servicePtr_ = ptr;
}

MigrateAVSessionProxy::~MigrateAVSessionProxy()
{
    SLOGI("MigrateAVSessionProxy destruct");
}

void MigrateAVSessionProxy::OnConnectServer(const std::string &deviceId)
{
    SLOGI("MigrateAVSessionProxy OnConnectServer:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    deviceId_ = deviceId;
    SendSpecialKeepAliveData();
    PrepareSessionFromRemote();
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "OnConnectServer find service ptr null!");
    std::vector<sptr<IRemoteObject>> sessionControllers;
    sessionControllers.push_back(preSetController_);
    servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
}

void MigrateAVSessionProxy::OnDisconnectServer(const std::string &deviceId)
{
    SLOGI("MigrateAVSessionProxy OnDisconnectServer:%{public}s",
        SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    deviceId_ = "";
    std::vector<sptr<IRemoteObject>> sessionControllers;
    servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
}

int32_t MigrateAVSessionProxy::GetCharacteristic()
{
    return mMode_;
}

//LCOV_EXCL_START
void MigrateAVSessionProxy::OnBytesReceived(const std::string &deviceId, const std::string &data)
{
    if (data.length() <= MSG_HEAD_LENGTH) {
        SLOGE("OnBytesReceived too short to process");
        return;
    }
    int32_t infoType = data[1];
    SLOGI("OnBytesReceived with infoType: %{public}d", infoType);
    std::string jsonStr = data.substr(MSG_HEAD_LENGTH);
    if (infoType == SYNC_FOCUS_MEDIA_IMAGE) {
        ProcessMediaImage(jsonStr);
        return;
    } else if (infoType == SYNC_FOCUS_BUNDLE_IMG) {
        ProcessBundleImg(jsonStr);
        return;
    }

    Json::Value jsonValue;
    if (!SoftbusSessionUtils::TransferStrToJson(jsonStr, jsonValue)) {
        SLOGE("OnBytesReceived parse json fail");
        return;
    }

    switch (infoType) {
        case SYNC_FOCUS_SESSION_INFO:
            ProcessSessionInfo(jsonValue);
            break;
        case SYNC_FOCUS_META_INFO:
            ProcessMetaData(jsonValue);
            break;
        case SYNC_FOCUS_PLAY_STATE:
            ProcessPlaybackState(jsonValue);
            break;
        case SYNC_FOCUS_VALID_COMMANDS:
            ProcessValidCommands(jsonValue);
            break;
        default:
            SLOGE("OnBytesReceived with unknow infoType:%{public}d", infoType);
            break;
    }
}
//LCOV_EXCL_STOP

void MigrateAVSessionProxy::HandlePlay()
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_PLAY, DEFAULT_STRING);
}

void MigrateAVSessionProxy::HandlePause()
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_PAUSE, DEFAULT_STRING);
}

void MigrateAVSessionProxy::HandlePlayNext()
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_PLAY_NEXT, DEFAULT_STRING);
}

void MigrateAVSessionProxy::HandlePlayPrevious()
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS, DEFAULT_STRING);
}

void MigrateAVSessionProxy::HandleToggleFavorite(const std::string& mediaId)
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE, mediaId);
}

void MigrateAVSessionProxy::HandleCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    SLOGI("HandleCommonCommand with command:%{public}s", commonCommand.c_str());
}

void MigrateAVSessionProxy::GetDistributedSessionControllerList(std::vector<sptr<IRemoteObject>>& controllerList)
{
    CHECK_AND_RETURN_LOG(preSetController_ != nullptr, "GetDistributedSessionControllerList with controller null");
    controllerList.insert(controllerList.begin(), preSetController_);
}

void MigrateAVSessionProxy::PrepareSessionFromRemote()
{
    SLOGI("PrepareSessionFromRemote in");
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = DEFAULT_STRING;
    descriptor.sessionTag_ = DEFAULT_STRING;
    descriptor.sessionType_ = AVSession::SESSION_TYPE_AUDIO;
    descriptor.elementName_.SetBundleName(DEFAULT_STRING);
    descriptor.elementName_.SetAbilityName(DEFAULT_STRING);
    descriptor.isThirdPartyApp_ = false;

    remoteSession_ = new(std::nothrow) AVSessionItem(descriptor);
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "create avsession but get nullptr");
    remoteSession_->SetPid(DEFAULT_NUM);
    remoteSession_->SetUid(DEFAULT_NUM);

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = AVCastCategory::CATEGORY_REMOTE;
    deviceInfo.deviceId_ = DEFAULT_STRING;
    deviceInfo.deviceName_ = DEFAULT_STRING;
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    remoteSession_->SetOutputDevice(outputDeviceInfo);

    std::weak_ptr<MigrateAVSessionProxy> migrateProxyWeak(shared_from_this());
    std::shared_ptr<AVSessionObserver> callback =
        std::make_shared<AVSessionObserver>(remoteSession_->GetSessionId(), migrateProxyWeak);
    remoteSession_->RegisterAVSessionCallback(callback);
    PrepareControllerOfRemoteSession(remoteSession_);
    SLOGI("PrepareSessionFromRemote done");
}

void MigrateAVSessionProxy::PrepareControllerOfRemoteSession(sptr<AVSessionItem> sessionItem)
{
    CHECK_AND_RETURN_LOG(sessionItem != nullptr, "PrepareControllerOfRemoteSession with remote session null");
    preSetController_ = new(std::nothrow) AVControllerItem(DEFAULT_NUM, sessionItem);\
    CHECK_AND_RETURN_LOG(preSetController_ != nullptr, "PrepareControllerOfRemoteSession with controller create null");
    sessionItem->AddController(DEFAULT_NUM, preSetController_);
}

void MigrateAVSessionProxy::ProcessSessionInfo(Json::Value jsonValue)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessSessionInfo with remote session null");
    std::string sessionId;
    AppExecFwk::ElementName elementName;

    if (jsonValue.isMember(MIGRATE_SESSION_ID)) {
        sessionId = jsonValue[MIGRATE_SESSION_ID].isString() ?
            jsonValue[MIGRATE_SESSION_ID].asString() : DEFAULT_STRING;
    }
    if (jsonValue.isMember(MIGRATE_BUNDLE_NAME)) {
        std::string bundleName = jsonValue[MIGRATE_BUNDLE_NAME].isString() ?
            jsonValue[MIGRATE_BUNDLE_NAME].asString() : DEFAULT_STRING;
        elementName.SetBundleName(bundleName);
    }
    if (jsonValue.isMember(MIGRATE_ABILITY_NAME)) {
        std::string abilityName = jsonValue[MIGRATE_ABILITY_NAME].isString() ?
            jsonValue[MIGRATE_ABILITY_NAME].asString() : DEFAULT_STRING;
        elementName.SetAbilityName(abilityName);
    }
    SLOGI("ProcessMetaData with sessionId:%{public}s|bundleName:%{public}s",
        sessionId.c_str(), elementName.GetBundleName().c_str());
    if (sessionId.empty() || sessionId == DEFAULT_STRING || sessionId == EMPTY_SESSION) {
        remoteSession_->Deactivate();
    } else {
        remoteSession_->Activate();
    }
}

void MigrateAVSessionProxy::ProcessMetaData(Json::Value jsonValue)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessMetaData with remote session null");
    AVMetaData metaData;
    if (AVSESSION_SUCCESS != remoteSession_->GetAVMetaData(metaData)) {
        SLOGE("ProcessMetaData GetAVMetaData fail");
    }
    metaData.SetAssetId(DEFAULT_STRING);
    if (jsonValue.isMember(METADATA_TITLE)) {
        std::string title = jsonValue[METADATA_TITLE].isString() ?
            jsonValue[METADATA_TITLE].asString() : DEFAULT_STRING;
        metaData.SetTitle(title);
    }
    if (jsonValue.isMember(METADATA_ARTIST)) {
        std::string artist = jsonValue[METADATA_ARTIST].isString() ?
            jsonValue[METADATA_ARTIST].asString() : DEFAULT_STRING;
        metaData.SetArtist(artist);
    }
    remoteSession_->SetAVMetaData(metaData);
    SLOGI("ProcessMetaData set title:%{public}s", metaData.GetTitle().c_str());
}

void MigrateAVSessionProxy::ProcessPlaybackState(Json::Value jsonValue)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessPlaybackState with remote session null");
    AVPlaybackState playbackState;
    if (AVSESSION_SUCCESS != remoteSession_->GetAVPlaybackState(playbackState)) {
        SLOGE("ProcessPlaybackState GetAVPlaybackState fail");
    }
    if (jsonValue.isMember(PLAYBACK_STATE)) {
        int state = jsonValue[PLAYBACK_STATE].isInt() ?
            jsonValue[PLAYBACK_STATE].asInt() : DEFAULT_NUM;
        playbackState.SetState(state);
    }
    if (jsonValue.isMember(FAVOR_STATE)) {
        int isFavor = jsonValue[FAVOR_STATE].isBool() ?
            jsonValue[FAVOR_STATE].asBool() : false;
        playbackState.SetFavorite(isFavor);
    }
    remoteSession_->SetAVPlaybackState(playbackState);
    SLOGI("ProcessPlaybackState set state:%{public}d | isFavor:%{public}d",
        playbackState.GetState(), playbackState.GetFavorite());
}

void MigrateAVSessionProxy::ProcessValidCommands(Json::Value jsonValue)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessValidCommands with remote session null");
    std::vector<int32_t> commands;
    if (jsonValue.isMember(VALID_COMMANDS)) {
        std::string commandsStr = jsonValue[VALID_COMMANDS].isString() ?
            jsonValue[VALID_COMMANDS].asString() : "";
        for (int8_t i = 0; i < commandsStr.length(); i++) {
            commands.insert(commands.begin(), static_cast<int>(commandsStr[i] - '0'));
        }
        remoteSession_->SetSupportCommand(commands);
    }
    SLOGI("ProcessValidCommands set cmd size:%{public}d", static_cast<int>(commands.size()));
}

void MigrateAVSessionProxy::ProcessBundleImg(std::string bundleIconStr)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessBundleImg with remote session null");
    AVMetaData metaData;
    if (AVSESSION_SUCCESS != remoteSession_->GetAVMetaData(metaData)) {
        SLOGE("ProcessBundleImg GetAVMetaData fail");
    }
    metaData.SetAssetId(DEFAULT_STRING);
    std::vector<uint8_t> imgVec(bundleIconStr.begin(), bundleIconStr.end());
    if (imgVec.size() <= 0) {
        SLOGE("ProcessBundleImg with empty img, return");
        return;
    } else {
        std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
        innerPixelMap->SetInnerImgBuffer(imgVec);
        metaData.SetBundleIcon(innerPixelMap);
    }
    remoteSession_->SetAVMetaData(metaData);
    SLOGI("ProcessBundleImg set img size:%{public}d", static_cast<int>(metaData.GetBundleIcon() == nullptr ?
        -1 : metaData.GetBundleIcon()->GetInnerImgBuffer().size()));
}

void MigrateAVSessionProxy::ProcessMediaImage(std::string mediaImageStr)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessMediaImage with remote session null");
    AVMetaData metaData;
    if (AVSESSION_SUCCESS != remoteSession_->GetAVMetaData(metaData)) {
        SLOGE("ProcessMediaImage GetAVMetaData fail");
    }
    metaData.SetAssetId(DEFAULT_STRING);
    std::vector<uint8_t> imgVec(mediaImageStr.begin(), mediaImageStr.end());
    if (imgVec.size() <= 0) {
        metaData.SetMediaImageUri(DEFAULT_STRING);
        metaData.SetMediaImage(nullptr);
    } else {
        std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
        innerPixelMap->SetInnerImgBuffer(imgVec);
        metaData.SetMediaImageUri("");
        metaData.SetMediaImage(innerPixelMap);
    }
    remoteSession_->SetAVMetaData(metaData);
    SLOGI("ProcessMediaImage set img size:%{public}d", static_cast<int>(metaData.GetMediaImage() == nullptr ?
        -1 : metaData.GetMediaImage()->GetInnerImgBuffer().size()));
}

void MigrateAVSessionProxy::SendControlCommandMsg(int32_t commandCode, std::string commandArgsStr)
{
    SLOGI("SendControlCommandMsg with code:%{public}d", commandCode);
    std::string msg = std::string({MSG_HEAD_MODE, SYNC_COMMAND});
    Json::Value controlMsg;
    controlMsg[COMMAND_CODE] = commandCode;
    controlMsg[COMMAND_ARGS] = commandArgsStr;
    SoftbusSessionUtils::TransferJsonToStr(controlMsg, msg);
    SendByte(deviceId_, msg);
}

void MigrateAVSessionProxy::SendSpecialKeepAliveData()
{
    std::thread([this]() {
        while (!this->deviceId_.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(HEART_BEAT_TIME_FOR_NEXT));
            SLOGI("send keep alive data for deviceId:%{public}s",
                SoftbusSessionUtils::AnonymizeDeviceId(deviceId_).c_str());
            std::string data = std::string({MSG_HEAD_MODE, SYNC_HEARTBEAT});
            SendByteToAll(data);
        }
        SLOGI("SendSpecialKeepAliveData exit");
    }).detach();
}

AVSessionObserver::AVSessionObserver(const std::string &playerId, std::weak_ptr<MigrateAVSessionProxy> migrateProxy)
{
    playerId_ = playerId;
    migrateProxy_ = migrateProxy;
}

void AVSessionObserver::OnPlay()
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandlePlay();
}

void AVSessionObserver::OnPause()
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandlePause();
}

void AVSessionObserver::OnPlayNext()
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandlePlayNext();
}

void AVSessionObserver::OnPlayPrevious()
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandlePlayPrevious();
}

void AVSessionObserver::OnToggleFavorite(const std::string& mediaId)
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandleToggleFavorite(mediaId);
}

void AVSessionObserver::OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandleCommonCommand(commonCommand, commandArgs);
}
} // namespace OHOS::AVSession