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

int32_t MigrateAVSessionProxy::HandleToggleFavoriteForSuper(const std::string& mediaId, const std::string& playerId)
{
    SLOGI("HandleToggleFavoriteForSuper:%{public}s|%{public}s pass",
        SoftbusSessionUtils::AnonymizeDeviceId(playerId).c_str(), mediaId.c_str());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::GetControllerListForSuper(std::vector<sptr<IRemoteObject>>& controllerList)
{
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
    switch (infoType) {
        case SYNC_CONTROLLER_LIST:
            CHECK_AND_PRINT_LOG(ProcessControllerListForSuper(jsonValue) == AVSESSION_SUCCESS,
                "SYNC_CONTROLLER_LIST fail");
            break;
        case SYNC_CONTROLLER:
            CHECK_AND_PRINT_LOG(ProcessControllerForSuper(jsonValue) == AVSESSION_SUCCESS, "SYNC_CONTROLLER_LIST fail");
            break;
        default:
            break;
    }
    cJSON_Delete(jsonValue);
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessControllerListForSuper(cJSON* jsonValue)
{
    cJSON* controllerListObj = nullptr;
    SoftbusSessionUtils::GetArrayFromJson(jsonValue, controllerListObj, MEDIA_CONTROLLER_LIST);
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
        SLOGE("clear session & controller stack for list empty");
        return AVSESSION_SUCCESS;
    }
    cJSON* controllerInfoObj = nullptr;
    cJSON_ArrayForEach(controllerInfoObj, controllerListObj) {
        CHECK_AND_RETURN_RET_LOG(ProcessSessionInfoForSuper(controllerInfoObj) == AVSESSION_SUCCESS,
            AVSESSION_ERROR, "ProcessSessionInfoForSuper fail");
        CHECK_AND_PRINT_LOG(ProcessMetaDataForSuper(controllerInfoObj) == AVSESSION_SUCCESS,
            "ProcessMetaDataForSuper fail");
        CHECK_AND_PRINT_LOG(ProcessPlaybackStateForSuper(controllerInfoObj) == AVSESSION_SUCCESS,
            "ProcessPlaybackStateForSuper fail");
    }
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
    switch (mediaInfoNum) {
        case SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED:
            CHECK_AND_PRINT_LOG(ProcessMetaDataForSuper(jsonValue) == AVSESSION_SUCCESS,
                "ProcessMetaDataForSuper fail");
            break;
        case SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED:
            CHECK_AND_PRINT_LOG(ProcessPlaybackStateForSuper(jsonValue) == AVSESSION_SUCCESS,
                "ProcessPlaybackStateForSuper fail");
            break;
        default:
            SLOGE("unknow mediainfo:%{public}d", mediaInfoNum);
            break;
    }
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::ProcessSessionInfoForSuper(cJSON* jsonValue)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, PLAYER_ID);
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
    sessionStackForMigrateIn_[sessionId] = sessionItem;
    SLOGI("ProcessSessionInfoForSuper:%{public}s done", SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
    CHECK_AND_RETURN_RET_LOG(ProcessControllerInfoForSuper(jsonValue) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "controller get fail");
    std::string bundleIconStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, BUNDLE_ICON);
    CHECK_AND_RETURN_RET_LOG(!bundleIconStr.empty(), AVSESSION_SUCCESS, "no bundleIcon");
    AVMetaData metaData;
    CHECK_AND_RETURN_RET_LOG(AVSESSION_SUCCESS == sessionItem->GetAVMetaData(metaData),
        AVSESSION_ERROR, "ProcessBundleIcon get metadata fail");
    metaData.SetAssetId(metaData.GetAssetId().empty() ? DEFAULT_STRING : metaData.GetAssetId());

    std::vector<uint8_t> imgVec(bundleIconStr.begin(), bundleIconStr.end());
    CHECK_AND_RETURN_RET_LOG(imgVec.size() > 0, AVSESSION_ERROR, "ProcessBundleIcon but empty");

    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    CHECK_AND_RETURN_RET_LOG(innerPixelMap != nullptr, AVSESSION_ERROR, "ProcessBundleIcon but nullptr");
    innerPixelMap->SetInnerImgBuffer(imgVec);
    metaData.SetBundleIcon(innerPixelMap);

    sessionItem->SetAVMetaData(metaData);
    SLOGI("ProcessBundleImg set img size:%{public}d for bundle:%{public}s",
        static_cast<int>(imgVec.size()), bundleName.c_str());
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
    sptr<AVControllerItem> controllerItem = new(std::nothrow) AVControllerItem(DEFAULT_NUM, sessionItem);
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
    std::string jpegImgAftEncodeStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_IMAGE);
    std::vector<uint8_t> jpegImgVec = Base64Utils::Base64Decode(jpegImgAftEncodeStr);
    CHECK_AND_PRINT_LOG(CompressFromJPEG(metaData, jpegImgVec) == AVSESSION_SUCCESS,
        "CompressFromJPEG fail:%{public}d", static_cast<int>(jpegImgVec.size()));

    CHECK_AND_RETURN_RET_LOG(sessionItem->SetAVMetaData(metaData) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "SetAVMetaData fail:%{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(title).c_str());
    SLOGI("ProcessMetaDataForSuper done:%{public}s|%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(title).c_str(),
        SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str());
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
    CHECK_AND_PRINT_LOG(actions > 0, "actions read fail:%{public}d", static_cast<int32_t>(actions));
    int32_t checkNum = parcel.ReadInt32();
    CHECK_AND_PRINT_LOG(checkNum == -1, "checkNum read fail:%{public}d", static_cast<int32_t>(checkNum));
    playbackState.SetActiveItemId(parcel.ReadInt64());
    checkNum = parcel.ReadInt32();
    CHECK_AND_PRINT_LOG(checkNum == 1, "checkNum read fail:%{public}d", static_cast<int32_t>(checkNum));
    std::string checkStr = parcel.ReadCString();
    checkNum = parcel.ReadInt32();
    CHECK_AND_PRINT_LOG(checkNum == -1, "checkNum again read fail:%{public}d", static_cast<int32_t>(checkNum));
    CHECK_AND_RETURN_RET_LOG(sessionItem->SetAVPlaybackState(playbackState) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "SetAVPlaybackState fail:%{public}d.", playbackState.GetState());
    SLOGI("ProcessPlaybackStateForSuper set state:%{public}d", playbackState.GetState());
    return AVSESSION_SUCCESS;
}

int32_t MigrateAVSessionProxy::SendControlCommandMsgForSuper(int32_t commandCode, const std::string& commandArgsStr)
{
    std::lock_guard lockGuard(migrateProxySessionIdLock_);
    std::string sessionId = commandArgsStr;
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
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}s fail", COMMAND, commandArgsStr.c_str());
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

int32_t MigrateAVSessionProxy::CompressFromJPEG(AVMetaData &metadata, const std::vector<uint8_t> &inputData)
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

    std::shared_ptr<AVSessionPixelMap> avsessionPixelMap =
        AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    CHECK_AND_RETURN_RET_LOG(avsessionPixelMap != nullptr, AVSESSION_ERROR,
        "ConvertToInnerWithLimitedSize with nullptr");
    metadata.SetMediaImageUri("");
    metadata.SetMediaImage(avsessionPixelMap);
    SLOGI("ProcessMediaImage set img size:%{public}d", static_cast<int>(metadata.GetMediaImage() == nullptr ?
        -1 : metadata.GetMediaImage()->GetInnerImgBuffer().size()));
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
} // namespace OHOS::AVSession