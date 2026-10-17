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
#include "bundle_status_adapter.h"

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
    CHECK_AND_RETURN_RET_LOG(loopMode >= AVPlaybackState::LOOP_MODE_UNDEFINED &&
        loopMode <= AVPlaybackState::LOOP_MODE_CUSTOM,
        AVSESSION_ERROR, "HandleSetLoopModeForSuper: invalid loopMode:%{public}d", loopMode);
    std::string loopModeStr(1, '0' + loopMode);
    SLOGI("HandleSetLoopModeForSuper:%{public}s|%{public}d pass",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str(), loopMode);
    CHECK_AND_RETURN_RET_LOG(SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_SET_LOOP_MODE, playerId, loopModeStr) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "HandleSetLoopModeForSuper:%{public}s fail",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::GetControllerListForSuper(std::vector<sptr<IRemoteObject>>& controllerList)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    for (const auto& sessionId : orderedSessionRefreshList_) {
        auto it = controllerStackForMigrateIn_.find(sessionId);
        CHECK_AND_CONTINUE(it != controllerStackForMigrateIn_.end());
        controllerList.push_back(it->second);
    }
    SLOGI("GetControllerListForSuper size:%{public}d.", static_cast<int>(controllerList.size()));
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::OnConnectForSuper()
{
    SLOGI("OnConnectForSuper in");
    return AVSESSION_SUCCESS;
}

void MigrateAVSessionProxy::ReleaseAllSessionsForSuper()
{
    SLOGI("ReleaseAllSessionsForSuper in");
    std::vector<sptr<AVControllerItem>> controllersToRelease;
    {
        std::lock_guard lockGuard(migrateProxySessionIdLock_);
        for (auto& pair : controllerStackForMigrateIn_) {
            controllersToRelease.push_back(pair.second);
        }
        sessionStackForMigrateIn_.clear();
        controllerStackForMigrateIn_.clear();
        orderedSessionRefreshList_.clear();
        sessionRefreshList_.clear();
    }
    for (auto& controllerItem : controllersToRelease) {
        controllerItem->RegisterMigrateAVSessionProxyCallback(nullptr);
        controllerItem->DestroyWithoutReply();
    }
    SLOGI("ReleaseAllSessionsForSuper done");
}

int32_t MigrateAVSessionProxy::OnDisconnectForSuper()
{
    SLOGI("OnDisconnectForSuper in");
    ReleaseAllSessionsForSuper();
    CHECK_AND_RETURN_RET_LOG(servicePtr_ != nullptr, AVSESSION_SUCCESS, "servicePtr null");
    servicePtr_->GetUsersManager().GetContainerFromAll().PostReclaimMemoryTask();
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
    CHECK_AND_RETURN_RET_LOG(SoftbusSessionUtils::GetArrayFromJson(jsonValue, mediaInfoListObj,
        HISTORY_MEDIA_PLAYER_INFO), AVSESSION_ERROR, "get mediaInfoListObj fail");
    CHECK_AND_RETURN_RET_LOG(servicePtr_ != nullptr, AVSESSION_ERROR, "servicePtr null!");
    if (cJSON_GetArraySize(mediaInfoListObj) <= 0) {
        ReleaseAllSessionsForSuper();
        std::lock_guard lockGuard(migrateProxySessionIdLock_);
        servicePtr_->NotifyRemoteDistributedSessionControllersChanged({});
        return AVSESSION_SUCCESS;
    }
    cJSON* mediaInfoObj = nullptr;
    {
        std::lock_guard lockGuard(migrateProxySessionIdLock_);
        orderedSessionRefreshList_.clear();
    }
    cJSON_ArrayForEach(mediaInfoObj, mediaInfoListObj) {
        CHECK_AND_RETURN_RET_LOG(ProcessSessionInfoForSuper(mediaInfoObj) == AVSESSION_SUCCESS,
            AVSESSION_ERROR, "ProcessSessionInfoForSuper fail");
        SLOGI("ProcessBundleIconForSuper ret:%{public}d", ProcessBundleIconForSuper(mediaInfoObj));
    }
    std::vector<sptr<AVControllerItem>> controllersToRelease;
    {
        std::lock_guard lockGuard(migrateProxySessionIdLock_);
        for (auto it = sessionStackForMigrateIn_.begin(); it != sessionStackForMigrateIn_.end();) {
            if (std::find(orderedSessionRefreshList_.begin(), orderedSessionRefreshList_.end(), it->first) ==
                orderedSessionRefreshList_.end()) {
                SLOGI("remove session:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(it->first).c_str());
                auto ctrlIt = controllerStackForMigrateIn_.find(it->first);
                if (ctrlIt != controllerStackForMigrateIn_.end()) {
                    controllersToRelease.push_back(ctrlIt->second);
                    controllerStackForMigrateIn_.erase(ctrlIt);
                }
                it = sessionStackForMigrateIn_.erase(it);
            } else {
                ++it;
            }
        }
        std::vector<sptr<IRemoteObject>> sessionControllers;
        GetControllerListForSuper(sessionControllers);
        servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
        SLOGI("ProcessHistoryMediaInfoListForSuper done size:%{public}d", static_cast<int>(sessionControllers.size()));
    }
    for (auto& controllerItem : controllersToRelease) {
        controllerItem->RegisterMigrateAVSessionProxyCallback(nullptr);
        controllerItem->DestroyWithoutReply();
    }
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessControllerListForSuper(cJSON* jsonValue)
{
    cJSON* controllerListObj = nullptr;
    CHECK_AND_RETURN_RET_LOG(SoftbusSessionUtils::GetArrayFromJson(jsonValue, controllerListObj, MEDIA_CONTROLLER_LIST),
        AVSESSION_ERROR, "get controllerList fail");
    cJSON* controllerInfoObj = nullptr;
    {
        std::lock_guard lockGuard(migrateProxySessionIdLock_);
        sessionRefreshList_.clear();
    }
    cJSON_ArrayForEach(controllerInfoObj, controllerListObj) {
        CHECK_AND_RETURN_RET_LOG(ProcessSessionInfoForSuper(controllerInfoObj, true) == AVSESSION_SUCCESS,
            AVSESSION_ERROR, "ProcessSessionInfoForSuper fail");
        if (isDualFrameMode_) {
            SLOGI("dual connect icon supply ret:%{public}d", ProcessBundleIconForSuper(controllerInfoObj));
        }
        int32_t retForProcessMeta = ProcessMetaDataForSuper(controllerInfoObj);
        int32_t retForProcessState = ProcessPlaybackStateForSuper(controllerInfoObj);
        int32_t retForProcessCmd = ProcessValidCommandsForSuper(controllerInfoObj);
        SLOGD("Process media info ret:%{public}d|%{public}d|%{public}d",
            retForProcessMeta, retForProcessState, retForProcessCmd);
    }
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    for (auto it = sessionStackForMigrateIn_.begin(); it != sessionStackForMigrateIn_.end(); ++it) {
        if (std::find(sessionRefreshList_.begin(), sessionRefreshList_.end(), it->first) == sessionRefreshList_.end()) {
            SLOGI("clear session:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(it->first).c_str());
            CleanMetadataForMigrateSession(it->second);
        }
    }

    std::vector<sptr<IRemoteObject>> sessionControllers;
    for (const auto& sessionId : orderedSessionRefreshList_) {
        auto it = controllerStackForMigrateIn_.find(sessionId);
        CHECK_AND_CONTINUE(it != controllerStackForMigrateIn_.end());
        sessionControllers.push_back(it->second);
    }
    CHECK_AND_RETURN_RET_LOG(servicePtr_ != nullptr, AVSESSION_ERROR,
        "NotifyRemoteDistributed but servicePtr null!");
    servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
    SLOGI("ProcessControllerListForSuper with size:%{public}d done", static_cast<int>(sessionControllers.size()));
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::CleanMetadataForMigrateSession(sptr<AVSessionItem> sessionItem)
{
    CHECK_AND_RETURN_RET_LOG(sessionItem != nullptr, AVSESSION_ERROR, "session null");
    AVMetaData metaData;
    CHECK_AND_RETURN_RET_LOG(AVSESSION_SUCCESS == sessionItem->GetAVMetaData(metaData),
        AVSESSION_ERROR, "CleanMetadataForMigrateSession get metadata fail");
    metaData.SetAssetId(DEFAULT_STRING);
    metaData.SetTitle("");
    return sessionItem->SetAVMetaData(metaData);
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

int32_t MigrateAVSessionProxy::ProcessSessionInfoForSuper(cJSON* jsonValue, bool dedupByBundleName)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYER_ID);
    sessionRefreshList_.emplace_back(sessionId);
    orderedSessionRefreshList_.emplace_back(sessionId);
    CHECK_AND_RETURN_RET_LOG(
        !sessionId.empty() && sessionStackForMigrateIn_.find(sessionId) == sessionStackForMigrateIn_.end(),
        AVSESSION_SUCCESS, "session already exist or empty:%{public}s.",
        SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    std::string bundleName = SoftbusSessionUtils::GetStringFromJson(jsonValue, PACKAGE_NAME);

    // Dual-frame: remove old session with same bundleName before creating new one
    if (isDualFrameMode_ && dedupByBundleName) {
        auto oldIt = std::find_if(sessionStackForMigrateIn_.begin(), sessionStackForMigrateIn_.end(),
            [&bundleName](const auto& pair) { return pair.second->GetBundleName() == bundleName; });
        if (oldIt != sessionStackForMigrateIn_.end()) {
            SLOGI("remove oldId:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(oldIt->first).c_str());
            auto ctrlIt = controllerStackForMigrateIn_.find(oldIt->first);
            if (ctrlIt != controllerStackForMigrateIn_.end()) {
                ctrlIt->second->RegisterMigrateAVSessionProxyCallback(nullptr);
                ctrlIt->second->DestroyWithoutReply();
                controllerStackForMigrateIn_.erase(ctrlIt);
            }
            orderedSessionRefreshList_.erase(std::remove(orderedSessionRefreshList_.begin(),
                orderedSessionRefreshList_.end(), oldIt->first), orderedSessionRefreshList_.end());
            sessionStackForMigrateIn_.erase(oldIt);
        }
    }

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
    sessionItem->SetSupportCommand(isDualFrameMode_ ? defaultValidCommandsDual: defaultValidCommands);
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

    AVMetaData metaData;
    CHECK_AND_RETURN_RET_LOG(AVSESSION_SUCCESS == sessionItem->GetAVMetaData(metaData),
        AVSESSION_ERROR, "ProcessBundleIcon get metadata fail");
    metaData.SetAssetId(metaData.GetAssetId().empty() ? DEFAULT_STRING : metaData.GetAssetId());

    std::shared_ptr<AVSessionPixelMap> bundleIconPixelMap = nullptr;

    // 1. Try to get bundle icon from remote (phone)
    std::string bundleIconStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, BUNDLE_ICON);
    if (!bundleIconStr.empty()) {
        std::vector<uint8_t> imgVec = Base64Utils::Base64Decode(bundleIconStr);
        if (imgVec.size() > 0) {
            CompressFromJPEG(imgVec, bundleIconPixelMap);
        }
    }

    // 2. Try to get bundle icon from local bundle manager
    if (bundleIconPixelMap == nullptr) {
        std::string bundleName = sessionItem->GetBundleName();
        std::string iconStr;
        if (BundleStatusAdapter::GetInstance().GetBundleIcon(bundleName, "", iconStr) && !iconStr.empty()) {
            std::vector<uint8_t> imgVec(iconStr.begin(), iconStr.end());
            CompressFromJPEG(imgVec, bundleIconPixelMap);
        }
    }

    // 3. Use default image as fallback
    if (bundleIconPixelMap == nullptr) {
        auto defaultPixelMap = AVSessionPixelMapAdapter::ConvertDefaultImage();
        if (defaultPixelMap != nullptr) {
            bundleIconPixelMap = AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(defaultPixelMap);
        }
    }

    CHECK_AND_RETURN_RET_LOG(bundleIconPixelMap != nullptr, AVSESSION_ERROR, "ProcessBundleIcon all methods failed");
    metaData.SetBundleIcon(bundleIconPixelMap);
    metaData.SetWriter(sessionItem->GetBundleName());
    sessionItem->SetAVMetaData(metaData);
    SLOGI("ProcessBundleImg set img size:%{public}d for bundleName:%{public}s",
        static_cast<int>(bundleIconPixelMap->GetInnerImgBuffer().size()), sessionItem->GetBundleName().c_str());
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
    std::string title = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_TITLE);
    metaData.SetTitle(title);
    std::string artist = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_ARTIST);
    metaData.SetArtist(artist);
    std::string assetId;
    if (isDualFrameMode_) {
        std::string hashKey = title + "|" + artist + "|" + sessionId;
        assetId = "SUPER_" + std::to_string(std::hash<std::string>{}(hashKey));
    } else {
        assetId = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_ASSET_ID);
    }
    metaData.SetAssetId(assetId.empty() ? DEFAULT_STRING : assetId);
    std::string lyric = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_LYRIC);
    metaData.SetLyric(lyric);
    int32_t duration = SoftbusSessionUtils::GetIntFromJson(jsonValue, METADATA_DURATION);
    metaData.SetDuration(duration);
    std::string jpegImgAftEncodeStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_IMAGE);
    std::vector<uint8_t> jpegImgVec = Base64Utils::Base64Decode(jpegImgAftEncodeStr);
    if (jpegImgVec.size() > 0) {
        std::shared_ptr<AVSessionPixelMap> mediaImagePixelMap = nullptr;
        int32_t ret = CompressFromJPEG(jpegImgVec, mediaImagePixelMap, true);
        metaData.SetMediaImage(mediaImagePixelMap);
        SLOGI("CompressFromJPEG ret:%{public}d", ret);
    }
    metaData.SetMediaImageUri("");
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

    std::string commandsStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, VALID_COMMANDS);
    if (commandsStr.empty()) {
        SLOGE("ProcessValidCommandsForSuper commandsStr is empty");
        return AVSESSION_ERROR;
    }

    if (commandsStr.length() > MAX_COMMANDS_STR_LENGTH) {
        SLOGE("ProcessValidCommandsForSuper commandsStr too long");
        return AVSESSION_ERROR;
    }

    std::vector<int32_t> commands;
    for (size_t i = 0; i < commandsStr.length(); i++) {
        int32_t cmd = static_cast<int32_t>(commandsStr[i] - '0');
        if (cmd <= AVControlCommand::SESSION_CMD_INVALID || cmd >= AVControlCommand::SESSION_CMD_MAX) {
            SLOGE("invalid cmd:%{public}d", cmd);
            continue;
        }
        commands.push_back(cmd);
    }

    if (commands.empty()) {
        SLOGE("ProcessValidCommandsForSuper no valid commands");
        return AVSESSION_ERROR;
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
    CHECK_AND_RETURN_RET_LOG(ParsePlaybackStateFromParcel(parcel, playbackState) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "ParsePlaybackStateFromParcel fail");
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

static int32_t JavaStringHashCode(const std::string& str)
{
    int32_t hash = 0;
    for (size_t i = 0; i < str.length(); i++) {
        hash = 31 * hash + static_cast<int32_t>(static_cast<uint8_t>(str[i]));
    }
    return hash;
}

int32_t MigrateAVSessionProxy::ColdStartForSuper(AAFwk::WantParams& extras)
{
    CHECK_AND_RETURN_RET_LOG(extras.HasParam(MIGRATE_BUNDLE_NAME), AVSESSION_ERROR, "extras not have bundleName key");
    auto value = extras.GetParam(MIGRATE_BUNDLE_NAME);
    AAFwk::IString* stringValue = AAFwk::IString::Query(value);
    CHECK_AND_RETURN_RET_LOG(stringValue != nullptr, AVSESSION_ERROR, "extras have no bundleName value");
    std::string bundleName = AAFwk::String::Unbox(stringValue);
    std::string playerId = isDualFrameMode_ ? std::to_string(JavaStringHashCode(bundleName)) : bundleName;
    cJSON* controlMsg = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_RET_LOG(controlMsg != nullptr, AVSESSION_ERROR, "get controlMsg fail");
    if (!SoftbusSessionUtils::AddStringToJson(controlMsg, PLAYER_ID, playerId)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail", PLAYER_ID, playerId.c_str());
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

int32_t MigrateAVSessionProxy::ParsePlaybackStateFromParcel(Parcel& parcel, AVPlaybackState& playbackState)
{
    playbackState.SetState(ConvertStateFromDoubleToSingle(parcel.ReadInt32()));
    AVPlaybackState::Position position;
    position.elapsedTime_ = parcel.ReadInt64();
    playbackState.SetSpeed(parcel.ReadFloat());
    position.updateTime_ = parcel.ReadInt64();
    playbackState.SetPosition(position);
    playbackState.SetBufferedTime(parcel.ReadInt64());
    parcel.ReadInt64(); // Field 6: actions
    parcel.ReadInt32(); // Field 7: mCustomActions (writeTypedList): -1=null, 0=empty
    playbackState.SetActiveItemId(parcel.ReadInt64()); // Field 8: mActiveItemId
    int32_t errorType = parcel.ReadInt32(); // Field 9: mErrorMessage (TextUtils.writeToParcel): 0=null, 1=String
    if (errorType == 1 && !isDualFrameMode_) {
        parcel.ReadCString();
    }
    // Dual-frame: mErrorMessage is always null, skip is not needed.
    parcel.ReadInt32(); // Field 10: mExtras (writeBundle): -1=null
    if (!isDualFrameMode_) {
        playbackState.SetFavorite(parcel.ReadBool());
        playbackState.SetLoopMode(parcel.ReadInt32());
    }
    return AVSESSION_SUCCESS;
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