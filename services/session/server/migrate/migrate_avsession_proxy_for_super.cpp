/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "avsession_utils.h"
#include "avsession_service.h"
#include "avsession_pixel_map_adapter.h"
#include "softbus/softbus_session_utils.h"
#include "migrate_avsession_constant.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "bool_wrapper.h"
#include "base64_utils.h"
#include "pixel_map.h"
#include "image_packer.h"

namespace OHOS::AVSession {

int32_t MigrateAVSessionProxy::HandlePlayForSuper(const std::string& playerId)
{
    CHECK_AND_RETURN_RET_LOG(
        SendControlCommandMsgForSuper(SYNC_MEDIASESSION_CALLBACK_ON_PLAY, playerId) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "HandlePlayForSuper%{public}s fail", SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::HandlePauseForSuper(const std::string& playerId)
{
    CHECK_AND_RETURN_RET_LOG(
        SendControlCommandMsgForSuper(SYNC_MEDIASESSION_CALLBACK_ON_PAUSE, playerId) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "HandlePauseForSuper:%{public}s fail",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::HandlePlayNextForSuper(const std::string& playerId)
{
    CHECK_AND_RETURN_RET_LOG(
        SendControlCommandMsgForSuper(SYNC_MEDIASESSION_CALLBACK_ON_SKIP_TO_NEXT, playerId) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "HandlePlayNextForSuper:%{public}s fail",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::HandlePlayPreviousForSuper(const std::string& playerId)
{
    CHECK_AND_RETURN_RET_LOG(
        SendControlCommandMsgForSuper(SYNC_MEDIASESSION_CALLBACK_ON_SKIP_TO_PREVIOUS, playerId) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "HandlePlayPreviousForSuper:%{public}s fail",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::HandleToggleFavoriteForSuper(const std::string& playerId, const std::string& mediaId)
{
    SLOGI("HandleToggleFavoriteForSuper:%{public}s|%{public}s pass",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str(), mediaId.c_str());
    CHECK_AND_RETURN_RET_LOG(
        SendControlCommandMsgForSuper(SYNC_MEDIASESSION_CALLBACK_ON_TOGGLE_FAVORITE,
        playerId, mediaId) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "HandleToggleFavoriteForSuper:%{public}s fail",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::HandleSeekForSuper(const std::string& playerId, const int64_t time)
{
    SLOGI("HandleSeekForSuper:%{public}s|%{public}lld pass",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str(), (long long)time);

    std::string timeStr = SoftbusSessionUtils::TransformInt64ToStr(time);
    CHECK_AND_RETURN_RET_LOG(
        SendControlCommandMsgForSuper(SYNC_MEDIASESSION_CALLBACK_ON_SEEK, playerId, timeStr) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "HandleSeekForSuper:%{public}s fail",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::HandleSetLoopModeForSuper(const std::string& playerId, const int32_t loopMode)
{
    SLOGI("HandleSetLoopModeForSuper:%{public}s|%{public}d pass",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str(), loopMode);

    CHECK_AND_RETURN_RET_LOG(SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_SET_LOOP_MODE, playerId, std::to_string('0' + loopMode)) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "HandleSetLoopModeForSuper:%{public}s fail",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::GetControllerListForSuper(std::vector<sptr<IRemoteObject>>& controllerList)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    for (const auto& pair : controllerStackForMigrateIn_) {
        controllerList.push_back(pair.second);
    }
    SLOGI("GetControllerListForSuper size:%{public}d", static_cast<int>(controllerList.size()));
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::OnConnectForSuper()
{
    SLOGI("OnConnectForSuper in");
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::OnDisconnectForSuper()
{
    SLOGI("OnDisconnectForSuper in");
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::OnBytesRecvForSuper(const std::string &deviceId, const std::string &data)
{
    if (data.length() <= MSG_HEAD_LENGTH) {
        SLOGE("OnBytesReceived too short to process");
        return AVSESSION_ERROR;
    }
    int32_t infoType = data[1];
    SLOGI("OnBytesRecvForSuper with infoType: %{public}d", infoType);
    std::string jsonStr = data.substr(MSG_HEAD_LENGTH);
    cJSON* jsonValue = nullptr;
    CHECK_AND_RETURN_RET_LOG(SoftbusSessionUtils::TransferStrToJson(jsonStr, jsonValue),
        AVSESSION_ERROR, "OnBytes err parse json");
    int32_t ret = 0;
    switch (infoType) {
        case GET_HISTORY_MEDIA_INFO:
            ret = ProcessHistoryMediaInfoListForSuper(jsonValue);
            break;
        case SYNC_CONTROLLER_LIST:
            ret = ProcessControllerListForSuper(jsonValue);
            break;
        case SYNC_CONTROLLER:
            ret = ProcessControllerForSuper(jsonValue);
            break;
        default:
            SLOGE("unknow infoType");
            break;
    }
    SLOGD("OnBytesRecvForSuper ret:%{public}d", ret);
    cJSON_Delete(jsonValue);
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessHistoryMediaInfoListForSuper(cJSON* jsonValue)
{
    cJSON* mediaInfoListObj = nullptr;
    CHECK_AND_RETURN_RET_LOG(
        SoftbusSessionUtils::GetArrayFromJson(jsonValue, mediaInfoListObj, HISTORY_MEDIA_PLAYER_INFO),
        AVSESSION_ERROR, "get mediaInfoListObj fail");
    if (cJSON_GetArraySize(mediaInfoListObj) <= 0) {
        std::lock_guard lockGuard(migrateProxySessionIdLock_);
        sessionStackForMigrateIn_.clear();
        controllerStackForMigrateIn_.clear();
        std::vector<sptr<IRemoteObject>> sessionControllers;
        CHECK_AND_RETURN_RET_LOG(servicePtr_ != nullptr, AVSESSION_ERROR,
            "ProcessHistoryMediaInfoListForSuper but servicePtr null!");
        servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
        SLOGE("clear session & controller stack for list empty");
        return AVSESSION_SUCCESS;
    }
    cJSON* mediaInfoObj = nullptr;
    sessionRefreshList_.clear();
    cJSON_ArrayForEach(mediaInfoObj, mediaInfoListObj) {
        CHECK_AND_RETURN_RET_LOG(ProcessSessionInfoForSuper(mediaInfoObj) == AVSESSION_SUCCESS,
            AVSESSION_ERROR, "ProcessSessionInfoForSuper fail");
        SLOGI("ProcessBundleIconForSuper ret:%{public}d", ProcessBundleIconForSuper(mediaInfoObj));
    }
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    for (auto it = sessionStackForMigrateIn_.begin(); it != sessionStackForMigrateIn_.end();) {
        if (std::find(sessionRefreshList_.begin(), sessionRefreshList_.end(), it->first) == sessionRefreshList_.end()) {
            SLOGI("remove session:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(it->first).c_str());
            controllerStackForMigrateIn_.erase(it->first);
            it = sessionStackForMigrateIn_.erase(it);
        } else {
            ++it;
        }
    }
    std::vector<sptr<IRemoteObject>> sessionControllers;
    for (const auto& pair : controllerStackForMigrateIn_) {
        sessionControllers.push_back(pair.second);
    }
    CHECK_AND_RETURN_RET_LOG(servicePtr_ != nullptr, AVSESSION_ERROR,
        "NotifyRemoteDistributed but servicePtr null!");
    servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
    SLOGI("ProcessHistoryMediaInfoListForSuper with size:%{public}d done",
        static_cast<int>(sessionControllers.size()));
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessControllerListForSuper(cJSON* jsonValue)
{
    cJSON* controllerListObj = nullptr;
    CHECK_AND_RETURN_RET_LOG(SoftbusSessionUtils::GetArrayFromJson(jsonValue, controllerListObj, MEDIA_CONTROLLER_LIST),
        AVSESSION_ERROR, "get controllerList fail");
    if (cJSON_GetArraySize(controllerListObj) <= 0) {
        std::lock_guard lockGuard(migrateProxySessionIdLock_);
        sessionStackForMigrateIn_.clear();
        controllerStackForMigrateIn_.clear();
        std::vector<sptr<IRemoteObject>> sessionControllers;
        CHECK_AND_RETURN_RET_LOG(servicePtr_ != nullptr, AVSESSION_ERROR,
            "ProcessControllerListForSuper but servicePtr null!");
        servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
        SLOGE("clear session & controller stack for controller list empty");
        return AVSESSION_SUCCESS;
    }
    cJSON* controllerInfoObj = nullptr;
    cJSON_ArrayForEach(controllerInfoObj, controllerListObj) {
        CHECK_AND_RETURN_RET_LOG(ProcessSessionInfoForSuper(controllerInfoObj) == AVSESSION_SUCCESS,
            AVSESSION_ERROR, "ProcessSessionInfoForSuper fail");
        int32_t retForProcessMeta = ProcessMetaDataForSuper(controllerInfoObj);
        int32_t retForProcessState = ProcessPlaybackStateForSuper(controllerInfoObj);
        int32_t retForProcessCmd = ProcessValidCommandsForSuper(controllerInfoObj);
        SLOGD("Process media info ret:%{public}d|%{public}d|%{public}d",
            retForProcessMeta, retForProcessState, retForProcessCmd);
    }
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::vector<sptr<IRemoteObject>> sessionControllers;
    for (const auto& pair : controllerStackForMigrateIn_) {
        sessionControllers.push_back(pair.second);
    }
    CHECK_AND_RETURN_RET_LOG(servicePtr_ != nullptr, AVSESSION_ERROR,
        "NotifyRemoteDistributed but servicePtr null!");
    servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
    SLOGI("ProcessControllerListForSuper with size:%{public}d done", static_cast<int>(sessionControllers.size()));
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessControllerForSuper(cJSON* jsonValue)
{
    int mediaInfoNum = SoftbusSessionUtils::GetIntFromJson(jsonValue, MEDIA_INFO);
    CHECK_AND_RETURN_RET_LOG(mediaInfoNum > 0, AVSESSION_ERROR, "error mediainfo:%{public}d", mediaInfoNum);
    int32_t ret = 0;
    switch (mediaInfoNum) {
        case SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED:
            ret = ProcessMetaDataForSuper(jsonValue);
            break;
        case SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED:
            ret = ProcessPlaybackStateForSuper(jsonValue);
            break;
        case SYNC_FOCUS_VALID_COMMANDS:
            ret = ProcessValidCommandsForSuper(jsonValue);
            break;
        default:
            SLOGE("unknow mediainfo:%{public}d", mediaInfoNum);
            break;
    }
    SLOGD("Process mediaInfo ret:%{public}d", ret);
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessSessionInfoForSuper(cJSON* jsonValue)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYER_ID);
    sessionRefreshList_.emplace_back(sessionId);
    CHECK_AND_RETURN_RET_LOG(
        !sessionId.empty() && sessionStackForMigrateIn_.find(sessionId) == sessionStackForMigrateIn_.end(),
        AVSESSION_SUCCESS, "session already exist or empty:%{public}s.",
        SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    std::string bundleName = SoftbusSessionUtils::GetStringFromJson(jsonValue, PACKAGE_NAME);

    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = sessionId;
    descriptor.sessionTag_ = DEFAULT_STRING;
    descriptor.sessionType_ = AVSession::SESSION_TYPE_AUDIO;
    descriptor.elementName_.SetBundleName(bundleName);
    descriptor.elementName_.SetAbilityName(DEFAULT_STRING);
    descriptor.isThirdPartyApp_ = false;

    sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    CHECK_AND_RETURN_RET_LOG(sessionItem != nullptr, AVSESSION_ERROR, "get avsession nullptr");
    sessionItem->SetPid(DEFAULT_NUM);
    sessionItem->SetUid(DEFAULT_NUM);
    sessionItem->Activate();
    sessionItem->SetSupportCommand(defaultValidCommands);
    std::weak_ptr<MigrateAVSessionProxy> migrateProxyWeak(shared_from_this());
    std::shared_ptr<AVSessionObserver> callback = std::make_shared<AVSessionObserver>(sessionId, migrateProxyWeak);
    sessionItem->RegisterAVSessionCallback(callback);
    sessionStackForMigrateIn_[sessionId] = sessionItem;
    SLOGI("ProcessSessionInfoForSuper:%{public}s done", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    CHECK_AND_RETURN_RET_LOG(ProcessControllerInfoForSuper(jsonValue) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "controller get fail");

    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessBundleIconForSuper(cJSON* jsonValue)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYER_ID);
    auto iter = sessionStackForMigrateIn_.find(sessionId);
    CHECK_AND_RETURN_RET_LOG(
        !sessionId.empty() && iter != sessionStackForMigrateIn_.end(), AVSESSION_ERROR,
        "session invalid:%{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    sptr<AVSessionItem> sessionItem = iter->second;
    CHECK_AND_RETURN_RET_LOG(sessionItem != nullptr, AVSESSION_ERROR, "ProcessBundleIconForSuper avsession nullptr");

    std::string bundleIconStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, BUNDLE_ICON);
    CHECK_AND_RETURN_RET_LOG(!bundleIconStr.empty(), AVSESSION_ERROR, "no bundleIcon");
    AVMetaData metaData;
    CHECK_AND_RETURN_RET_LOG(AVSESSION_SUCCESS == sessionItem->GetAVMetaData(metaData),
        AVSESSION_ERROR, "ProcessBundleIcon get metadata fail");
    metaData.SetAssetId(metaData.GetAssetId().empty() ? DEFAULT_STRING : metaData.GetAssetId());

    std::vector<uint8_t> imgVec = Base64Utils::Base64Decode(bundleIconStr);
    CHECK_AND_RETURN_RET_LOG(imgVec.size() > 0, AVSESSION_ERROR, "ProcessBundleIcon but empty");
    std::shared_ptr<AVSessionPixelMap> bundleIconPixelMap = nullptr;
    CHECK_AND_RETURN_RET_LOG(CompressFromJPEG(imgVec, bundleIconPixelMap) == AVSESSION_SUCCESS, AVSESSION_ERROR,
        "CompressFromJPEG fail:%{public}zu", imgVec.size());
    CHECK_AND_RETURN_RET_LOG(bundleIconPixelMap != nullptr, AVSESSION_ERROR, "ProcessBundleIcon but nullptr");

    metaData.SetBundleIcon(bundleIconPixelMap);
    metaData.SetWriter(sessionItem->GetBundleName());
    sessionItem->SetAVMetaData(metaData);
    SLOGI("ProcessBundleImg set img size:%{public}d for bundleName:%{public}s",
        static_cast<int>(imgVec.size()), sessionItem->GetBundleName().c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessControllerInfoForSuper(cJSON* jsonValue)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYER_ID);
    CHECK_AND_RETURN_RET_LOG(
        !sessionId.empty() && controllerStackForMigrateIn_.find(sessionId) == controllerStackForMigrateIn_.end(),
        AVSESSION_SUCCESS, "controller already exist or empty:%{public}d", sessionId.empty());
    auto iter = sessionStackForMigrateIn_.find(sessionId);
    CHECK_AND_RETURN_RET_LOG(iter != sessionStackForMigrateIn_.end(),
        AVSESSION_ERROR, "create controller but session no found:%{public}s",
        SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    sptr<AVSessionItem> sessionItem = iter->second;
    sptr<AVControllerItem> controllerItem = new(std::nothrow) AVControllerItem(DEFAULT_NUM, sessionItem, userId_);
    CHECK_AND_RETURN_RET_LOG(controllerItem != nullptr, AVSESSION_ERROR, "get controller null");
    MigrateAVSessionProxyControllerCallbackFunc migrateProxyCallback = MigrateAVSessionProxyControllerCallback();
    controllerItem->RegisterMigrateAVSessionProxyCallback(migrateProxyCallback);
    sessionItem->AddController(DEFAULT_NUM, controllerItem);
    controllerStackForMigrateIn_[sessionId] = controllerItem;

    SLOGI("ProcessControllerInfoForSuper:%{public}s done", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessMetaDataForSuper(cJSON* jsonValue)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYER_ID);
    auto iter = sessionStackForMigrateIn_.find(sessionId);
    CHECK_AND_RETURN_RET_LOG(
        !sessionId.empty() && iter != sessionStackForMigrateIn_.end(), AVSESSION_ERROR,
        "session invalid:%{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    sptr<AVSessionItem> sessionItem = iter->second;
    CHECK_AND_RETURN_RET_LOG(sessionItem != nullptr, AVSESSION_ERROR, "ProcessMetaDataForSuper get avsession nullptr");
    AVMetaData metaData;
    CHECK_AND_RETURN_RET_LOG(AVSESSION_SUCCESS == sessionItem->GetAVMetaData(metaData),
        AVSESSION_ERROR, "ProcessMetaDataForSuper get metadata fail");
    std::string assetId = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_ASSET_ID);
    metaData.SetAssetId(assetId.empty() ? DEFAULT_STRING : assetId);
    std::string title = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_TITLE);
    metaData.SetTitle(title);
    std::string artist = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_ARTIST);
    metaData.SetArtist(artist);
    std::string lyric = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_LYRIC);
    metaData.SetLyric(lyric);
    int32_t duration = SoftbusSessionUtils::GetIntFromJson(jsonValue, METADATA_DURATION);
    metaData.SetDuration(duration);
    std::string jpegImgAftEncodeStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_IMAGE);
    std::vector<uint8_t> jpegImgVec = Base64Utils::Base64Decode(jpegImgAftEncodeStr);
    std::shared_ptr<AVSessionPixelMap> mediaImagePixelMap = nullptr;
    SLOGI("CompressFromJPEG ret:%{public}d", CompressFromJPEG(jpegImgVec, mediaImagePixelMap, true));

    metaData.SetMediaImageUri("");
    metaData.SetMediaImage(mediaImagePixelMap);
    SLOGI("ProcessMediaImage set img size:%{public}d", static_cast<int>(mediaImagePixelMap == nullptr ?
        -1 : jpegImgVec.size()));
    CHECK_AND_RETURN_RET_LOG(sessionItem->SetAVMetaData(metaData) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "SetAVMetaData fail:%{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(title).c_str());
    SLOGI("ProcessMetaDataForSuper done:%{public}s|%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(title).c_str(),
        SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessValidCommandsForSuper(cJSON* jsonValue)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYER_ID);
    auto iter = sessionStackForMigrateIn_.find(sessionId);
    CHECK_AND_RETURN_RET_LOG(
        !sessionId.empty() && iter != sessionStackForMigrateIn_.end(), AVSESSION_ERROR,
        "session invalid:%{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    sptr<AVSessionItem> sessionItem = iter->second;
    CHECK_AND_RETURN_RET_LOG(sessionItem != nullptr, AVSESSION_ERROR,
        "ProcessValidCommandsForSuper get avsession nullptr");

    std::vector<int32_t> commands;
    std::string commandsStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, VALID_COMMANDS);
    if (commandsStr.empty()) {
        commandsStr = DEFAULT_STRING;
    }
    for (unsigned long i = 0; i < commandsStr.length(); i++) {
        commands.push_back(static_cast<int32_t>(commandsStr[i] - '0'));
    }
    sessionItem->SetSupportCommand(commands);

    SLOGI("ProcessValidCommandsForSuper set cmd size:%{public}d", static_cast<int>(commands.size()));
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessPlaybackStateForSuper(cJSON* jsonValue)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYER_ID);
    auto iter = sessionStackForMigrateIn_.find(sessionId);
    CHECK_AND_RETURN_RET_LOG(
        !sessionId.empty() && iter != sessionStackForMigrateIn_.end(), AVSESSION_ERROR,
        "session invalid:%{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    sptr<AVSessionItem> sessionItem = iter->second;
    CHECK_AND_RETURN_RET_LOG(sessionItem != nullptr, AVSESSION_ERROR,
        "ProcessPlaybackStateForSuper get avsession nullptr");
    std::string stateEncodeStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYBACK_STATE);
    stateEncodeStr = (stateEncodeStr.empty()) ?
        SoftbusSessionUtils::GetStringFromJson(jsonValue, CALLBACK_INFO) : stateEncodeStr;
    CHECK_AND_RETURN_RET_LOG(!stateEncodeStr.empty(), AVSESSION_ERROR,
        "stateEncodeStr empty:%{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    std::vector<uint8_t> stateVec = Base64Utils::Base64Decode(stateEncodeStr);
    Parcel parcel;
    parcel.WriteBuffer(stateVec.data(), stateVec.size());
    parcel.RewindRead(0);
    AVPlaybackState playbackState;
    CHECK_AND_RETURN_RET_LOG(AVSESSION_SUCCESS == sessionItem->GetAVPlaybackState(playbackState), AVSESSION_ERROR,
        "ProcessPlaybackStateForSuper GetAVPlaybackState fail");
    playbackState.SetState(ConvertStateFromDoubleToSingle(parcel.ReadInt32()));
    AVPlaybackState::Position position;
    position.elapsedTime_ = parcel.ReadInt64();
    playbackState.SetSpeed(parcel.ReadFloat());
    position.updateTime_ = parcel.ReadInt64();
    playbackState.SetPosition(position);
    playbackState.SetBufferedTime(parcel.ReadInt64());
    int64_t actions = parcel.ReadInt64();
    SLOGD("actions read:%{public}d", static_cast<int32_t>(actions));
    int32_t checkNum = parcel.ReadInt32();
    SLOGD("checkNum read:%{public}d", static_cast<int32_t>(checkNum));
    playbackState.SetActiveItemId(parcel.ReadInt64());
    checkNum = parcel.ReadInt32();
    SLOGD("checkNum read:%{public}d", static_cast<int32_t>(checkNum));
    std::string checkStr = parcel.ReadCString();
    checkNum = parcel.ReadInt32();
    SLOGD("checkNum again read:%{public}d", static_cast<int32_t>(checkNum));
    playbackState.SetFavorite(parcel.ReadBool());
    playbackState.SetLoopMode(parcel.ReadInt32());
    CHECK_AND_RETURN_RET_LOG(sessionItem->SetAVPlaybackState(playbackState) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "SetAVPlaybackState fail:%{public}d.", playbackState.GetState());
    SLOGI("ProcessPlaybackStateForSuper set state:%{public}d|%{public}d|%{public}d",
        playbackState.GetState(), playbackState.GetFavorite(), playbackState.GetLoopMode());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::SendControlCommandMsgForSuper(int32_t commandCode, const std::string& sessionId,
    std::string commandArgsStr)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    CHECK_AND_RETURN_RET_LOG(
        !sessionId.empty() && sessionStackForMigrateIn_.find(sessionId) != sessionStackForMigrateIn_.end(),
        AVSESSION_ERROR, "session invalid:%{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());

    cJSON* controlMsg = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_RET_LOG(controlMsg != nullptr, AVSESSION_ERROR, "get controlMsg fail");
    if (!SoftbusSessionUtils::AddStringToJson(controlMsg, PLAYER_ID, sessionId)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail", PLAYER_ID,
            SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
        cJSON_Delete(controlMsg);
        return AVSESSION_ERROR;
    }
    if (!SoftbusSessionUtils::AddIntToJson(controlMsg, MEDIA_COMMAND, commandCode)) {
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail", MEDIA_COMMAND, commandCode);
        cJSON_Delete(controlMsg);
        return AVSESSION_ERROR;
    }
    if (!SoftbusSessionUtils::AddStringToJson(controlMsg, COMMAND, commandArgsStr)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail", COMMAND, commandArgsStr.c_str());
        cJSON_Delete(controlMsg);
        return AVSESSION_ERROR;
    }

    std::string msg = std::string({mMode_, SYNC_COMMAND});
    SoftbusSessionUtils::TransferJsonToStr(controlMsg, msg);
    cJSON_Delete(controlMsg);
    SendByteForNext(deviceId_, msg);
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ColdStartForSuper(AAFwk::WantParams& extras)
{
    CHECK_AND_RETURN_RET_LOG(extras.HasParam(MIGRATE_BUNDLE_NAME), AVSESSION_ERROR, "extras not have bundleName key");
    auto value = extras.GetParam(MIGRATE_BUNDLE_NAME);
    AAFwk::IString* stringValue = AAFwk::IString::Query(value);
    CHECK_AND_RETURN_RET_LOG(stringValue != nullptr, AVSESSION_ERROR, "extras have no bundleName value");
    std::string bundleName = AAFwk::String::Unbox(stringValue);
    cJSON* controlMsg = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_RET_LOG(controlMsg != nullptr, AVSESSION_ERROR, "get controlMsg fail");
    if (!SoftbusSessionUtils::AddStringToJson(controlMsg, PLAYER_ID, bundleName)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail", PLAYER_ID,
            bundleName.c_str());
        cJSON_Delete(controlMsg);
        return AVSESSION_ERROR;
    }

    std::string msg = std::string({mMode_, COLD_START});
    SoftbusSessionUtils::TransferJsonToStr(controlMsg, msg);
    cJSON_Delete(controlMsg);
    SendByteForNext(deviceId_, msg);
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::CompressFromJPEG(const std::vector<uint8_t> &inputData,
    std::shared_ptr<AVSessionPixelMap>& outputData, bool isMediaImage)
{
    CHECK_AND_RETURN_RET_LOG(!inputData.empty(), AVSESSION_ERROR, "CompressFromJPEG with empty");
    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    auto imageSource = Media::ImageSource::CreateImageSource(inputData.data(), inputData.size(), opts, errorCode);
    CHECK_AND_RETURN_RET_LOG(errorCode == 0, AVSESSION_ERROR, "CreateImageSource errorCode:%{public}u", errorCode);
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, AVSESSION_ERROR,
        "CreateImageSource with nullptr, errorCode:%{public}u", errorCode);
    Media::DecodeOptions decodeOpts;
    decodeOpts.allocatorType = Media::AllocatorType::DMA_ALLOC;
    std::shared_ptr<Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    CHECK_AND_RETURN_RET_LOG(errorCode == 0, AVSESSION_ERROR, "CreatePixelMap with errorCode 0");
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, AVSESSION_ERROR,
        "CreatePixelMap with nullptr, errorCode:%{public}u", errorCode);

    outputData = isMediaImage ? AVSessionPixelMapAdapter::ConvertToInner(pixelMap) :
        AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    CHECK_AND_RETURN_RET_LOG(outputData != nullptr, AVSESSION_ERROR,
        "ConvertToInnerWithLimitedSize with nullptr");
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ConvertStateFromDoubleToSingle(int32_t state)
{
    switch (state) {
        case MEDIA_SESSION_PLAYBACK_STATE_PLAY:
            return AVPlaybackState::PLAYBACK_STATE_PLAY;
        case MEDIA_SESSION_PLAYBACK_STATE_PAUSE:
            return AVPlaybackState::PLAYBACK_STATE_PAUSE;
        case MEDIA_SESSION_PLAYBACK_STATE_STOP:
            return AVPlaybackState::PLAYBACK_STATE_STOP;
        case MEDIA_SESSION_PLAYBACK_STATE_ERROR:
            return AVPlaybackState::PLAYBACK_STATE_ERROR;
        default:
            SLOGW("unknowState: %{public}d", state);
            break;
    }
    return state;
}

void MigrateAVSessionProxy::NotifyControllerGone(pid_t pid)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    for (const auto& pair : controllerStackForMigrateIn_) {
        sptr<AVControllerItem> controllerItem = pair.second;
        CHECK_AND_CONTINUE(controllerItem != nullptr);
        controllerItem->RemoveCallbackForMigrate(pid);
    }
}
} // namespace OHOS::AVSession