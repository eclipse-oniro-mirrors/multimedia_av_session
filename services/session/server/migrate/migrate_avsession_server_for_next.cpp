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
#include "avsession_pixel_map_adapter.h"
#include "pixel_map.h"
#include "image_packer.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {

void MigrateAVSessionServer::RefreshDeviceId(std::string deviceId)
{
    SLOGI("migrate refresh deviceId from:%{public}s to %{public}s.",
        SoftbusSessionUtils::AnonymizeDeviceId(deviceId_).c_str(),
        SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    deviceId_ = deviceId;
}

void MigrateAVSessionServer::LocalFrontSessionArrive(std::string &sessionId)
{
    if (sessionId.empty()) {
        SLOGE("LocalFrontSessionArrive with sessionId EMPTY");
        return;
    }
    lastSessionId_ = sessionId;
    SLOGI("LocalFrontSessionArrive in:%{public}s.", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    MigratePostTask(
        [this, sessionId]() {
            SLOGI("LocalFrontSessionArrive with sessionId:%{public}s.",
                AVSessionUtils::GetAnonySessionId(sessionId).c_str());
            CreateController(sessionId);
            sptr<AVControllerItem> controller = nullptr;
            {
                std::lock_guard lockGuard(migrateControllerLock_);
                controller = playerIdToControllerMap_[sessionId];
                CHECK_AND_RETURN_LOG(controller != nullptr, "LocalFrontSessionArrive but get controller null");
            }

            controller->isFromSession_ = false;
            lastSessionId_ = sessionId;
            if (isSoftbusConnecting_) {
                UpdateFrontSessionInfoToRemote(controller);
            } else {
                SLOGE("LocalFrontSessionArrive without connect");
            }
            SLOGI("LocalFrontSessionArrive finish.");
        },
        "LocalFrontSessionChange");
}

void MigrateAVSessionServer::LocalFrontSessionChange(std::string &sessionId)
{
    SLOGI("LocalFrontSessionChange in:%{public}s.", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    std::lock_guard lockGuard(migrateControllerLock_);
    sptr<AVControllerItem> controller = playerIdToControllerMap_[lastSessionId_];
    if (controller != nullptr) {
        controller->UnregisterAVControllerCallback();
    } else {
        SLOGE("LocalFrontSessionChange but get controller null");
    }
    ClearCacheBySessionId(lastSessionId_);
    auto it = playerIdToControllerMap_.find(lastSessionId_);
    if (it != playerIdToControllerMap_.end()) {
        playerIdToControllerMap_.erase(it);
    } else {
        SLOGE("LocalFrontSessionChange no find sessionId:%{public}s",
            AVSessionUtils::GetAnonySessionId(lastSessionId_).c_str());
    }
    lastSessionId_ = "";
    LocalFrontSessionArrive(sessionId);
}

void MigrateAVSessionServer::LocalFrontSessionLeave(std::string &sessionId)
{
    SLOGI("LocalFrontSessionLeave in:%{public}s.", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    lastSessionId_ = "";
    MigratePostTask(
        [this, sessionId]() {
            std::lock_guard lockGuard(migrateControllerLock_);
            sptr<AVControllerItem> controller = playerIdToControllerMap_[lastSessionId_];
            if (controller != nullptr) {
                controller->UnregisterAVControllerCallback();
            } else {
                SLOGE("LocalFrontSessionLeave but get controller null");
            }
            ClearCacheBySessionId(sessionId);
            auto it = playerIdToControllerMap_.find(sessionId);
            if (it != playerIdToControllerMap_.end()) {
                playerIdToControllerMap_.erase(it);
            } else {
                SLOGE("LocalFrontSessionLeave no find sessionId:%{public}s",
                    AVSessionUtils::GetAnonySessionId(sessionId).c_str());
            }
            UpdateEmptyInfoToRemote();
            lastSessionId_ = "";
            SLOGI("LocalFrontSessionLeave finish.");
        },
        "LocalFrontSessionChange");
}

void MigrateAVSessionServer::HandleFocusPlaybackStateChange(const std::string &sessionId, const AVPlaybackState &state)
{
    DoPlaybackStateSyncToRemote(state);
}

void MigrateAVSessionServer::HandleFocusMetaDataChange(const std::string &sessionId, const AVMetaData &data)
{
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = data.GetMediaImage();
    DoMetaDataSyncToRemote(data);
    if (innerPixelMap != nullptr) {
        DoMediaImageSyncToRemote(innerPixelMap);
    }
}

void MigrateAVSessionServer::HandleFocusValidCommandChange(const std::string &sessionId,
    const std::vector<int32_t> &cmds)
{
    DoValidCommandsSyncToRemote(cmds);
}

void MigrateAVSessionServer::DoMetaDataSyncToRemote(const AVMetaData& data)
{
    std::lock_guard lockGuard(cacheJsonLock_);
    bool needRefresh = false;
    if (data.GetAssetId() != metaDataCache_.GetAssetId()) {
        metaDataCache_.Reset();
        metaDataCache_.SetAssetId(data.GetAssetId());
        curAssetId_ = data.GetAssetId();
        needRefresh = true;
    }
    if (data.GetMetaMask().test(AVMetaData::META_KEY_TITLE) && data.GetTitle() != metaDataCache_.GetTitle()) {
        metaDataCache_.SetTitle(data.GetTitle());
        needRefresh = true;
    }
    if (data.GetMetaMask().test(AVMetaData::META_KEY_ARTIST) && data.GetArtist() != metaDataCache_.GetArtist()) {
        metaDataCache_.SetArtist(data.GetArtist());
        needRefresh = true;
    } else if (data.GetMetaMask().test(AVMetaData::META_KEY_SUBTITLE) &&
        data.GetSubTitle() != metaDataCache_.GetArtist()) {
        metaDataCache_.SetArtist(data.GetSubTitle());
        needRefresh = true;
    }
    CHECK_AND_RETURN_LOG(needRefresh, "metadata no change");

    cJSON* metaDataItem = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_LOG(metaDataItem != nullptr, "get metadata json with nullptr");
    if (!SoftbusSessionUtils::AddStringToJson(metaDataItem, METADATA_TITLE, metaDataCache_.GetTitle().c_str())) {
        SLOGE("AddStringToJson with title value:%{public}s fail", metaDataCache_.GetTitle().c_str());
        cJSON_Delete(metaDataItem);
        return;
    }
    if (!SoftbusSessionUtils::AddStringToJson(metaDataItem, METADATA_ARTIST, metaDataCache_.GetArtist().c_str())) {
        SLOGE("AddStringToJson artist value:%{public}s fail", metaDataCache_.GetArtist().c_str());
        cJSON_Delete(metaDataItem);
        return;
    }
    if (!SoftbusSessionUtils::AddStringToJson(metaDataItem, METADATA_ASSET_ID, metaDataCache_.GetAssetId().c_str())) {
        SLOGE("AddStringToJson assetId value:%{public}s fail", metaDataCache_.GetAssetId().c_str());
        cJSON_Delete(metaDataItem);
        return;
    }

    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_FOCUS_META_INFO});
    SoftbusSessionUtils::TransferJsonToStr(metaDataItem, msg);
    MigratePostTask(
        [this, msg]() {
            SendByteForNext(deviceId_, msg);
        }, "SYNC_FOCUS_META_INFO");
    SLOGI("DoMetaDataSyncToRemote async Title:%{public}s|len:%{public}d done",
        metaDataCache_.GetTitle().c_str(), static_cast<int>(msg.size()));
    cJSON_Delete(metaDataItem);
}

void MigrateAVSessionServer::DoMediaImageSyncToRemote(std::shared_ptr<AVSessionPixelMap> innerPixelMap)
{
    CHECK_AND_RETURN_LOG(innerPixelMap != nullptr, "DoMediaImageSyncToRemote with innerPixelMap null");
    std::vector<uint8_t> imgBuffer = innerPixelMap->GetInnerImgBuffer();
    SLOGI("DoMediaImageSyncToRemote with img size:%{public}d", static_cast<int>(imgBuffer.size()));

    if (imgBuffer.size() <= 0) {
        SLOGE("do mediaImg sync with emptyBuffer, return");
        return;
    }
    std::shared_ptr<Media::PixelMap> pixelMap;
    pixelMap = AVSessionPixelMapAdapter::ConvertFromInner(innerPixelMap);
    CHECK_AND_RETURN_LOG(pixelMap != nullptr, "DoMediaImageSyncToRemote with pixelMap null");
    std::shared_ptr<AVSessionPixelMap> innerPixelMapMin = AVSessionPixelMapAdapter::ConvertToInnerWithMinSize(pixelMap);
    CHECK_AND_RETURN_LOG(innerPixelMapMin != nullptr, "DoMediaImageSyncToRemote with innerPixelMapMin null");
    std::vector<uint8_t> imgBufferMin = innerPixelMapMin->GetInnerImgBuffer();
    std::string assetIdForMediaImg = curAssetId_ + "|";
    std::string imgStrMin(imgBufferMin.begin(), imgBufferMin.end());
    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_FOCUS_MEDIA_IMAGE});
    msg += assetIdForMediaImg;
    msg += imgStrMin;

    MigratePostTask(
        [this, msg]() {
            SendByteForNext(deviceId_, msg);
        },
        "SYNC_FOCUS_MEDIA_IMAGE");
    SLOGI("DoMediaImageSyncToRemote async size:%{public}d", static_cast<int>(msg.size()));
}

void MigrateAVSessionServer::DoPlaybackStateSyncToRemote(const AVPlaybackState& state)
{
    std::lock_guard lockGuard(cacheJsonLock_);
    bool needRefresh = false;
    if (state.GetMask().test(AVPlaybackState::PLAYBACK_KEY_STATE) &&
        state.GetState() != playbackStateCache_.GetState()) {
        playbackStateCache_.SetState(state.GetState());
        needRefresh = true;
    }
    if (state.GetMask().test(AVPlaybackState::PLAYBACK_KEY_IS_FAVORITE) &&
        state.GetFavorite() != playbackStateCache_.GetFavorite()) {
        playbackStateCache_.SetFavorite(state.GetFavorite());
        needRefresh = true;
    }
    CHECK_AND_RETURN_LOG(needRefresh, "playbackstate no change");

    cJSON* playbackStateItem = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_LOG(playbackStateItem != nullptr, "get playbackState json with nullptr");
    if (!SoftbusSessionUtils::AddIntToJson(playbackStateItem, PLAYBACK_STATE, playbackStateCache_.GetState())) {
        SLOGE("AddStringToJson with state value:%{public}d fail", playbackStateCache_.GetState());
        cJSON_Delete(playbackStateItem);
        return;
    }
    if (!SoftbusSessionUtils::AddBoolToJson(playbackStateItem, FAVOR_STATE, playbackStateCache_.GetFavorite())) {
        SLOGE("AddStringToJson with favor value:%{public}d fail", playbackStateCache_.GetFavorite());
        cJSON_Delete(playbackStateItem);
        return;
    }

    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_FOCUS_PLAY_STATE});
    SoftbusSessionUtils::TransferJsonToStr(playbackStateItem, msg);
    MigratePostTask(
        [this, msg]() {
            SendByteForNext(deviceId_, msg);
        }, "SYNC_FOCUS_PLAY_STATE");
    SLOGI("DoPlaybackStateSyncToRemote sync state:%{public}d|Favor:%{public}d|len:%{public}d done.",
        playbackStateCache_.GetState(), playbackStateCache_.GetFavorite(), static_cast<int>(msg.size()));
    cJSON_Delete(playbackStateItem);
}

void MigrateAVSessionServer::DoValidCommandsSyncToRemote(const std::vector<int32_t>& commands)
{
    cJSON* validCommands = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_LOG(validCommands != nullptr, "get validCommands json with nullptr");
    std::string commandsStr;
    for (int32_t cmd : commands) {
        commandsStr.push_back(static_cast<char>(cmd + '0'));
    }
    if (!SoftbusSessionUtils::AddStringToJson(validCommands, VALID_COMMANDS, commandsStr.c_str())) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail", VALID_COMMANDS, commandsStr.c_str());
        cJSON_Delete(validCommands);
        return;
    }

    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_FOCUS_VALID_COMMANDS});
    SoftbusSessionUtils::TransferJsonToStr(validCommands, msg);
    MigratePostTask(
        [this, msg]() {
            SendByteForNext(deviceId_, msg);
        },
        "SYNC_FOCUS_VALID_COMMANDS");
    SLOGI("DoValidCommandsSyncToRemote async commands num:%{public}d|content:%{public}s|len:%{public}d done",
        static_cast<int>(commands.size()), commandsStr.c_str(), static_cast<int>(msg.size()));
    cJSON_Delete(validCommands);
}

void MigrateAVSessionServer::DoBundleInfoSyncToRemote(sptr<AVControllerItem> controller)
{
    CHECK_AND_RETURN_LOG(controller != nullptr, "DoBundleInfoSyncToRemote with controller null");
    AppExecFwk::ElementName elementName = controller->GetElementOfSession();
    std::string bundleName = elementName.GetBundleName();
    std::string abilityName = elementName.GetAbilityName();
    std::string iconStr;
    if (!BundleStatusAdapter::GetInstance().GetBundleIcon(bundleName, abilityName, iconStr)) {
        SLOGE("DoBundleInfoSyncToRemote get bundle icon fail for bundleName:%{public}s", bundleName.c_str());
    }

    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    auto imageSource = Media::ImageSource::CreateImageSource(reinterpret_cast<const uint8_t*>(iconStr.c_str()),
        iconStr.length(), opts, errorCode);
    CHECK_AND_RETURN_LOG(imageSource != nullptr,
        "DoBundleInfoSyncToRemote CreateImageSource fail for bundleName:%{public}s", bundleName.c_str());
    Media::DecodeOptions decodeOpts;
    decodeOpts.allocatorType = Media::AllocatorType::HEAP_ALLOC;
    std::shared_ptr<Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    CHECK_AND_RETURN_LOG(pixelMap != nullptr,
        "DoBundleInfoSyncToRemote CreatePixelMap fail for bundleName:%{public}s", bundleName.c_str());

    std::shared_ptr<AVSessionPixelMap> innerPixelMapMin = AVSessionPixelMapAdapter::ConvertToInnerWithMinSize(pixelMap);
    CHECK_AND_RETURN_LOG(innerPixelMapMin != nullptr, "DoBundleInfoSyncToRemote with innerPixelMapMin null");
    std::vector<uint8_t> imgBufferMin = innerPixelMapMin->GetInnerImgBuffer();
    std::string imgStrMin(imgBufferMin.begin(), imgBufferMin.end());
    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_FOCUS_BUNDLE_IMG});
    msg += imgStrMin;

    MigratePostTask(
        [this, msg]() {
            SendByteForNext(deviceId_, msg);
        },
        "SYNC_FOCUS_BUNDLE_IMG");
    SLOGI("DoBundleInfoSyncToRemote async size:%{public}d", static_cast<int>(msg.size()));
}

void MigrateAVSessionServer::UpdateFrontSessionInfoToRemote(sptr<AVControllerItem> controller)
{
    CHECK_AND_RETURN_LOG(controller != nullptr, "UpdateFrontSessionInfoToRemote get controller null");
    SLOGI("UpdateFrontSessionInfoToRemote with sessionId clearCache:%{public}s",
        AVSessionUtils::GetAnonySessionId(controller->GetSessionId()).c_str());

    UpdateSessionInfoToRemote(controller);
    {
        std::lock_guard lockGuard(cacheJsonLock_);
        metaDataCache_.Reset();
        playbackStateCache_.SetState(0);
        playbackStateCache_.SetFavorite(0);
    }
    AVMetaData metaData;
    int32_t ret = controller->GetAVMetaData(metaData);
    if (AVSESSION_SUCCESS == ret || ERR_INVALID_PARAM == ret) {
        DoMetaDataSyncToRemote(metaData);
        std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData.GetMediaImage();
        if (innerPixelMap != nullptr) {
            DoMediaImageSyncToRemote(innerPixelMap);
        }
    } else {
        SLOGE("UpdateFrontSessionInfoToRemote get metadata fail:%{public}d", ret);
    }

    AVPlaybackState playbackState;
    ret = controller->GetAVPlaybackState(playbackState);
    if (AVSESSION_SUCCESS == ret) {
        DoPlaybackStateSyncToRemote(playbackState);
    } else {
        SLOGE("UpdateFrontSessionInfoToRemote get playbackstate fail:%{public}d", ret);
    }

    std::vector<int32_t> commands;
    controller->GetValidCommands(commands);
    DoValidCommandsSyncToRemote(commands);
    DoBundleInfoSyncToRemote(controller);
    SLOGI("UpdateFrontSessionInfoToRemote done");
}

void MigrateAVSessionServer::UpdateSessionInfoToRemote(sptr<AVControllerItem> controller)
{
    CHECK_AND_RETURN_LOG(controller != nullptr, "controller get nullptr");
    cJSON* sessionInfo = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_LOG(sessionInfo != nullptr, "get sessionInfo json with nullptr");
    if (!SoftbusSessionUtils::AddStringToJson(sessionInfo, MIGRATE_SESSION_ID, controller->GetSessionId().c_str())) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            MIGRATE_SESSION_ID, controller->GetSessionId().c_str());
        cJSON_Delete(sessionInfo);
        return;
    }
    AppExecFwk::ElementName elementName = controller->GetElementOfSession();
    std::string bundleNameForMigrate = elementName.GetBundleName() + "|" + controller->GetSessionType();
    if (!SoftbusSessionUtils::AddStringToJson(sessionInfo, MIGRATE_BUNDLE_NAME, bundleNameForMigrate.c_str())) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            MIGRATE_BUNDLE_NAME, bundleNameForMigrate.c_str());
        cJSON_Delete(sessionInfo);
        return;
    }
    if (!SoftbusSessionUtils::AddStringToJson(sessionInfo, MIGRATE_ABILITY_NAME,
        elementName.GetAbilityName().c_str())) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            MIGRATE_ABILITY_NAME, elementName.GetAbilityName().c_str());
        cJSON_Delete(sessionInfo);
        return;
    }

    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_FOCUS_SESSION_INFO});
    SoftbusSessionUtils::TransferJsonToStr(sessionInfo, msg);
    MigratePostTask(
        [this, msg]() {
            SendByteForNext(deviceId_, msg);
        },
        "SYNC_FOCUS_SESSION_INFO");
    cJSON_Delete(sessionInfo);
}

void MigrateAVSessionServer::UpdateEmptyInfoToRemote()
{
    SLOGI("UpdateEmptyInfoToRemote in async");
    cJSON* sessionInfo = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_LOG(sessionInfo != nullptr, "get sessionInfo json with nullptr");
    if (!SoftbusSessionUtils::AddStringToJson(sessionInfo, MIGRATE_SESSION_ID, EMPTY_SESSION)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            MIGRATE_SESSION_ID, EMPTY_SESSION);
        cJSON_Delete(sessionInfo);
        return;
    }

    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_FOCUS_SESSION_INFO});
    SoftbusSessionUtils::TransferJsonToStr(sessionInfo, msg);
    MigratePostTask(
        [this, msg]() {
            SendByteForNext(deviceId_, msg);
        },
        "SYNC_FOCUS_SESSION_INFO");
    cJSON_Delete(sessionInfo);
}

void MigrateAVSessionServer::ProcFromNext(const std::string &deviceId, const std::string &data)
{
    if (data.length() <= MSG_HEAD_LENGTH) {
        SLOGE("ProcFromNext with data too short:%{public}s", data.c_str());
        return;
    }
    int32_t messageType = data[1];
    std::string commandStr = data.substr(MSG_HEAD_LENGTH);
    cJSON* commandJsonValue = nullptr;
    if (!SoftbusSessionUtils::TransferStrToJson(commandStr, commandJsonValue)) {
        SLOGE("ProcFromNext parse json fail");
        return;
    }

    switch (messageType) {
        case SYNC_COMMAND:
            ProcControlCommandFromNext(commandJsonValue);
            break;
        case SYNC_SET_VOLUME_COMMAND:
            VolumeControlCommand(commandJsonValue);
            break;
        case SYNC_SWITCH_AUDIO_DEVICE_COMMAND:
            SwitchAudioDeviceCommand(commandJsonValue);
            break;
        case COLD_START:
            ProcessColdStartFromNext(commandJsonValue);
            break;
        case SYNC_MEDIA_CONTROL_NEED_STATE:
            ProcessMediaControlNeedStateFromNext(commandJsonValue);
            break;
        default:
            SLOGE("messageType %{public}d not support", messageType);
            break;
    }
    cJSON_Delete(commandJsonValue);
}

void MigrateAVSessionServer::ProcControlCommandFromNext(cJSON* commandJsonValue)
{
    if (commandJsonValue == nullptr || cJSON_IsInvalid(commandJsonValue) || cJSON_IsNull(commandJsonValue)) {
        SLOGE("get commandJsonValue invalid");
        return;
    }

    int32_t commandCode = -1;
    std::string commandArgs;
    if (cJSON_HasObjectItem(commandJsonValue, COMMAND_CODE)) {
        commandCode = SoftbusSessionUtils::GetIntFromJson(commandJsonValue, COMMAND_CODE);
    }
    if (cJSON_HasObjectItem(commandJsonValue, COMMAND_ARGS)) {
        commandArgs = SoftbusSessionUtils::GetStringFromJson(commandJsonValue, COMMAND_ARGS);
    }

    sptr<AVControllerItem> controller = nullptr;
    {
        std::lock_guard lockGuard(migrateControllerLock_);
        controller = playerIdToControllerMap_[lastSessionId_];
        CHECK_AND_RETURN_LOG(controller != nullptr, "ProcControlCommandFromNext but get controller null");
    }
    AVControlCommand command;
    if (AVSESSION_SUCCESS != command.SetCommand(commandCode)) {
        SLOGE("ProcControlCommandFromNext parse invalid command type:%{public}d", commandCode);
        return;
    }
    if (commandCode == AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE) {
        commandArgs = (commandArgs.empty() || commandArgs == DEFAULT_STRING) ? curAssetId_ : commandArgs;
        command.SetAssetId(commandArgs);
        SLOGI("ProcControlCommandFromNext toggle fav for:%{public}s", commandArgs.c_str());
    }
    controller->SendControlCommand(command);
    SLOGI("ProcNextCommand code:%{public}d done", commandCode);
}

void MigrateAVSessionServer::ProcessColdStartFromNext(cJSON* commandJsonValue)
{
    if (commandJsonValue == nullptr || cJSON_IsInvalid(commandJsonValue) || cJSON_IsNull(commandJsonValue)) {
        SLOGE("get commandJsonValue invalid");
        return;
    }

    std::string bundleName;
    if (cJSON_HasObjectItem(commandJsonValue, MIGRATE_BUNDLE_NAME)) {
        bundleName = SoftbusSessionUtils::GetStringFromJson(commandJsonValue, MIGRATE_BUNDLE_NAME);
    }
    SLOGI("ProcessColdStartFromNext with bundleName:%{public}s", bundleName.c_str());
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "ProcessColdStartFromNext without servicePtr, return");
    AVControlCommand cmd;
    cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    servicePtr_->SendSystemControlCommand(cmd);
}

void MigrateAVSessionServer::ProcessMediaControlNeedStateFromNext(cJSON* commandJsonValue)
{
    if (commandJsonValue == nullptr || cJSON_IsInvalid(commandJsonValue) || cJSON_IsNull(commandJsonValue)) {
        SLOGE("get commandJsonValue invalid");
        return;
    }

    if (cJSON_HasObjectItem(commandJsonValue, NEED_STATE)) {
        bool newListenerSetState = SoftbusSessionUtils::GetBoolFromJson(commandJsonValue, NEED_STATE);
        if (!isListenerSet_ && newListenerSetState) {
            isListenerSet_ = true;
            LocalFrontSessionArrive(lastSessionId_);
            RegisterAudioCallbackAndTrigger();
        } else {
            isListenerSet_ = newListenerSetState;
        }
    }
    SLOGI("updateListenerState:%{public}d", isListenerSet_);
}

std::function<void(int32_t)> MigrateAVSessionServer::GetVolumeKeyEventCallbackFunc()
{
    return [this](int32_t volumeNum) {
        std::lock_guard lockGuard(migrateDeviceChangeLock_);
        cJSON* value = SoftbusSessionUtils::GetNewCJSONObject();
        CHECK_AND_RETURN_LOG(value != nullptr, "get value json with nullptr");
        std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_SET_VOLUME_COMMAND});
        if (!SoftbusSessionUtils::AddIntToJson(value, AUDIO_VOLUME, volumeNum)) {
            SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail", AUDIO_VOLUME, volumeNum);
            cJSON_Delete(value);
            return;
        }

        SoftbusSessionUtils::TransferJsonToStr(value, msg);
        SLOGI("server send set volume num async:%{public}d", volumeNum);
        MigratePostTask(
            [this, msg]() {
                SendByteForNext(deviceId_, msg);
            },
            "SYNC_SET_VOLUME_COMMAND");
        cJSON_Delete(value);
    };
}

AudioDeviceDescriptorsCallbackFunc MigrateAVSessionServer::GetAvailableDeviceChangeCallbackFunc()
{
    return [this](const AudioDeviceDescriptors& devices) {
        std::lock_guard lockGuard(migrateDeviceChangeLock_);
        cJSON* value = ConvertAudioDeviceDescriptorsToJson(devices);
        CHECK_AND_RETURN_LOG(value != nullptr, "get value json with nullptr");
        if (cJSON_IsInvalid(value) || cJSON_IsNull(value)) {
            SLOGE("get value from ConvertAudioDeviceDescriptorsToJson invalid");
            cJSON_Delete(value);
            return;
        }
        std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_AVAIL_DEVICES_LIST});
        SoftbusSessionUtils::TransferJsonToStr(value, msg);
        SLOGI("server send get available device change callback async");
        MigratePostTask(
            [this, msg]() {
                SendJsonStringByte(deviceId_, msg);
            },
            "SYNC_AVAIL_DEVICES_LIST");
        cJSON_Delete(value);
    };
}

AudioDeviceDescriptorsCallbackFunc MigrateAVSessionServer::GetPreferredDeviceChangeCallbackFunc()
{
    return [this](const AudioDeviceDescriptors& devices) {
        std::lock_guard lockGuard(migrateDeviceChangeLock_);
        cJSON* value = ConvertAudioDeviceDescriptorsToJson(devices);
        CHECK_AND_RETURN_LOG(value != nullptr, "get value json with nullptr");
        if (cJSON_IsInvalid(value) || cJSON_IsNull(value)) {
            SLOGE("get value from ConvertAudioDeviceDescriptorsToJson invalid");
            cJSON_Delete(value);
            return;
        }
        std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_CURRENT_DEVICE});
        SoftbusSessionUtils::TransferJsonToStr(value, msg);
        SLOGI("server send get preferred device change callback async");
        MigratePostTask(
            [this, msg]() {
                SendJsonStringByte(deviceId_, msg);
            },
            "SYNC_CURRENT_DEVICE");
        volumeKeyEventCallbackFunc_(AudioAdapter::GetInstance().GetVolume());
        cJSON_Delete(value);
    };
}

cJSON* MigrateAVSessionServer::ConvertAudioDeviceDescriptorsToJson(
    const AudioDeviceDescriptors& devices)
{
    cJSON* jsonArray = SoftbusSessionUtils::GetNewCJSONArray();
    CHECK_AND_RETURN_RET_LOG(jsonArray != nullptr, nullptr, "get jsonArray with nullptr");

    int32_t deviceNum = 0;
    for (auto& device : devices) {
        if (device == nullptr) {
            continue;
        }
        cJSON* jsonObject = ConvertAudioDeviceDescriptorToJson(device);
        cJSON_InsertItemInArray(jsonArray, deviceNum++, jsonObject);
    }
    cJSON* jsonData = SoftbusSessionUtils::GetNewCJSONObject();
    if (jsonData == nullptr) {
        SLOGE("get jsonData json with nullptr");
        cJSON_Delete(jsonArray);
        return nullptr;
    }
    if (!SoftbusSessionUtils::AddJsonArrayToJson(jsonData, MEDIA_AVAILABLE_DEVICES_LIST, jsonArray)) {
        SLOGE("add jsonArray into jsonData fail");
        cJSON_Delete(jsonData);
        return nullptr;
    }

    return jsonData;
}

cJSON* MigrateAVSessionServer::ConvertAudioDeviceDescriptorToJson(
    const AudioDeviceDescriptorWithSptr& desc)
{
    cJSON* device = SoftbusSessionUtils::GetNewCJSONObject();
    CHECK_AND_RETURN_RET_LOG(device != nullptr, nullptr, "get device with nullptr");
    CHECK_AND_RETURN_RET_LOG(desc != nullptr, nullptr, "get desc with nullptr");

    if (!SoftbusSessionUtils::AddIntToJson(device, AUDIO_DEVICE_TYPE, static_cast<int32_t>(desc->deviceType_))) {
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail",
            AUDIO_DEVICE_TYPE, static_cast<int32_t>(desc->deviceType_));
        cJSON_Delete(device);
        return nullptr;
    }
    if (!SoftbusSessionUtils::AddStringToJson(device, AUDIO_MAC_ADDRESS, desc->macAddress_)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            AUDIO_MAC_ADDRESS, desc->macAddress_.c_str());
        cJSON_Delete(device);
        return nullptr;
    }
    if (!SoftbusSessionUtils::AddStringToJson(device, AUDIO_NETWORK_ID, desc->networkId_)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            AUDIO_NETWORK_ID, desc->networkId_.c_str());
        cJSON_Delete(device);
        return nullptr;
    }
    if (!SoftbusSessionUtils::AddIntToJson(device, AUDIO_DEVICE_ROLE, static_cast<int32_t>(desc->deviceRole_))) {
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail",
            AUDIO_DEVICE_ROLE, static_cast<int32_t>(desc->deviceRole_));
        cJSON_Delete(device);
        return nullptr;
    }
    if (!SoftbusSessionUtils::AddIntToJson(device, AUDIO_DEVICE_CATEGORY,
        static_cast<int32_t>(desc->deviceCategory_))) {
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail",
            AUDIO_DEVICE_CATEGORY, static_cast<int32_t>(desc->deviceCategory_));
        cJSON_Delete(device);
        return nullptr;
    }
    if (!SoftbusSessionUtils::AddStringToJson(device, AUDIO_DEVICE_NAME, desc->deviceName_)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail",
            AUDIO_DEVICE_NAME, desc->deviceName_.c_str());
        cJSON_Delete(device);
        return nullptr;
    }

    return device;
}

void MigrateAVSessionServer::VolumeControlCommand(cJSON* commandJsonValue)
{
    if (commandJsonValue == nullptr || cJSON_IsInvalid(commandJsonValue) || cJSON_IsNull(commandJsonValue)) {
        SLOGE("get commandJsonValue invalid");
        return;
    }

    SLOGI("server recv in VolumeControlCommand case");
    if (!cJSON_HasObjectItem(commandJsonValue, AUDIO_VOLUME)) {
        SLOGE("json parse with error member");
        return;
    }

    int32_t audioVolume = SoftbusSessionUtils::GetIntFromJson(commandJsonValue, AUDIO_VOLUME);
    AudioAdapter::GetInstance().SetVolume(audioVolume);
}

void MigrateAVSessionServer::SwitchAudioDeviceCommand(cJSON* jsonObject)
{
    if (jsonObject == nullptr || cJSON_IsInvalid(jsonObject) || cJSON_IsNull(jsonObject)) {
        SLOGE("get jsonObject invalid");
        return;
    }

    SLOGI("server recv in SwitchAudioDeviceCommand case");
    int deviceCategory = SoftbusSessionUtils::GetIntFromJson(jsonObject, AUDIO_DEVICE_CATEGORY);
    int deviceType = SoftbusSessionUtils::GetIntFromJson(jsonObject, AUDIO_DEVICE_TYPE);
    int deviceRole = SoftbusSessionUtils::GetIntFromJson(jsonObject, AUDIO_DEVICE_ROLE);
    std::string networkId = SoftbusSessionUtils::GetStringFromJson(jsonObject, AUDIO_NETWORK_ID);
    std::string deviceName = SoftbusSessionUtils::GetStringFromJson(jsonObject, AUDIO_DEVICE_NAME);
    std::string macAddress = SoftbusSessionUtils::GetStringFromJson(jsonObject, AUDIO_MAC_ADDRESS);
    
    std::shared_ptr<AudioDeviceDescriptor> device = std::make_shared<AudioDeviceDescriptor>();
    CHECK_AND_RETURN_LOG(device != nullptr, "AudioDeviceDescriptor make shared_ptr is null");
    device->deviceCategory_ = static_cast<AudioStandard::DeviceCategory>(deviceCategory);
    device->deviceType_ = static_cast<AudioStandard::DeviceType>(deviceType);
    device->deviceRole_ = static_cast<AudioStandard::DeviceRole>(deviceRole);
    device->networkId_ = networkId;
    device->deviceName_ = deviceName;
    device->macAddress_ = macAddress;

    AudioAdapter::GetInstance().SelectOutputDevice(device);
}

void MigrateAVSessionServer::DoPostTasksClear()
{
    SLOGI("DoPostTasksClear for migrate:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId_).c_str());
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("LocalFrontSessionArrive");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_FOCUS_MEDIA_IMAGE");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_FOCUS_BUNDLE_IMG");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_FOCUS_META_INFO");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_FOCUS_PLAY_STATE");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_FOCUS_VALID_COMMANDS");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_FOCUS_SESSION_INFO");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_SET_VOLUME_COMMAND");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_AVAIL_DEVICES_LIST");
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("SYNC_CURRENT_DEVICE");
}

bool MigrateAVSessionServer::MigratePostTask(const AppExecFwk::EventHandler::Callback &callback,
    const std::string &name, int64_t delayTime)
{
    if (!isSoftbusConnecting_) {
        SLOGE("MigratePostTask:%{public}s without connect", name.c_str());
        return false;
    }
    SLOGD("MigratePostTask with name:%{public}s.", name.c_str());
    if (!isListenerSet_ && name != "LocalFrontSessionChange" && name != "SYNC_FOCUS_SESSION_INFO") {
        SLOGI("no send task:%{public}s for no listen", name.c_str());
        return false;
    }
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(name);
    return AVSessionEventHandler::GetInstance().AVSessionPostTask(callback, name);
}
}

