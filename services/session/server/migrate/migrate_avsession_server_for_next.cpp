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

void MigrateAVSessionServer::LocalFrontSessionArrive(std::string &sessionId)
{
    if (sessionId.empty()) {
        SLOGE("LocalFrontSessionArrive with sessionId EMPTY");
        return;
    }
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, sessionId]() {
            SLOGI("LocalFrontSessionArrive with sessionId:%{public}s",
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
            SLOGI("LocalFrontSessionArrive finish");
        },
        "LocalFrontSessionArrive");
}

void MigrateAVSessionServer::LocalFrontSessionChange(std::string &sessionId)
{
    SLOGI("LocalFrontSessionChange in");
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
    LocalFrontSessionArrive(sessionId);
}

void MigrateAVSessionServer::LocalFrontSessionLeave(std::string &sessionId)
{
    SLOGI("LocalFrontSessionLeave in");
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
}

void MigrateAVSessionServer::HandleFocusPlaybackStateChange(const std::string &sessionId, const AVPlaybackState &state)
{
    DoPlaybackStateSyncToRemote(state);
}

void MigrateAVSessionServer::HandleFocusMetaDataChange(const std::string &sessionId, const AVMetaData &data)
{
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = data.GetMediaImage();
    if (innerPixelMap != nullptr) {
        DoMediaImageSyncToRemote(innerPixelMap);
    }
    DoMetaDataSyncToRemote(data);
}

void MigrateAVSessionServer::HandleFocusValidCommandChange(const std::string &sessionId,
    const std::vector<int32_t> &cmds)
{
    DoValidCommandsSyncToRemote(cmds);
}

void MigrateAVSessionServer::DoMetaDataSyncToRemote(const AVMetaData& data)
{
    Json::Value metaData;
    curAssetId_ = data.GetAssetId();
    metaData[METADATA_ASSET_ID] = DEFAULT_STRING;
    if (data.GetMetaMask().test(AVMetaData::META_KEY_TITLE)) {
        metaData[METADATA_TITLE] = data.GetTitle();
    }
    if (data.GetMetaMask().test(AVMetaData::META_KEY_ARTIST)) {
        metaData[METADATA_ARTIST] = data.GetArtist();
    }
    {
        std::lock_guard lockGuard(cacheJsonLock_);
        if (metaData == metaDataCache_ || metaData.empty()) {
            SLOGI("DoMetaDataSyncToRemote with repeat title:%{public}s|empty:%{public}d",
                data.GetTitle().c_str(), metaData.empty());
            return;
        }
    }
    std::string msg = std::string({MSG_HEAD_MODE, SYNC_FOCUS_META_INFO});
    SoftbusSessionUtils::TransferJsonToStr(metaData, msg);
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, msg]() {
            SendByte(deviceId_, msg);
        },
        "DoMetaDataSyncToRemote");
    SLOGI("DoMetaDataSyncToRemote async title:%{public}s done", data.GetTitle().c_str());
    {
        std::lock_guard lockGuard(cacheJsonLock_);
        metaDataCache_ = metaData;
    }
}

void MigrateAVSessionServer::DoMediaImageSyncToRemote(std::shared_ptr<AVSessionPixelMap> innerPixelMap)
{
    CHECK_AND_RETURN_LOG(innerPixelMap != nullptr, "DoMediaImageSyncToRemote with innerPixelMap null");
    std::vector<uint8_t> imgBuffer = innerPixelMap->GetInnerImgBuffer();
    SLOGI("DoMediaImageSyncToRemote with img size:%{public}d", static_cast<int>(imgBuffer.size()));

    if (imgBuffer.size() <= 0) {
        std::string msg = std::string({MSG_HEAD_MODE, SYNC_FOCUS_MEDIA_IMAGE});
        SoftbusSessionUtils::TransferJsonToStr(DEFAULT_STRING, msg);
        AVSessionEventHandler::GetInstance().AVSessionPostTask(
            [this, msg]() {
                SendByte(deviceId_, msg);
            },
            "DoMediaImageSyncToRemote_EMPTY");
        return;
    }
    std::shared_ptr<Media::PixelMap> pixelMap;
    pixelMap = AVSessionPixelMapAdapter::ConvertFromInner(innerPixelMap);
    CHECK_AND_RETURN_LOG(pixelMap != nullptr, "DoMediaImageSyncToRemote with pixelMap null");
    std::shared_ptr<AVSessionPixelMap> innerPixelMapMin = AVSessionPixelMapAdapter::ConvertToInnerWithMinSize(pixelMap);
    CHECK_AND_RETURN_LOG(innerPixelMapMin != nullptr, "DoMediaImageSyncToRemote with innerPixelMapMin null");
    std::vector<uint8_t> imgBufferMin = innerPixelMapMin->GetInnerImgBuffer();
    std::string imgStrMin(imgBufferMin.begin(), imgBufferMin.end());
    std::string msg = std::string({MSG_HEAD_MODE, SYNC_FOCUS_MEDIA_IMAGE});
    msg += imgStrMin;

    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, msg]() {
            SendByte(deviceId_, msg);
        },
        "DoMediaImageSyncToRemote");
    SLOGI("DoMediaImageSyncToRemote async size:%{public}d", static_cast<int>(msg.size()));
}

void MigrateAVSessionServer::DoPlaybackStateSyncToRemote(const AVPlaybackState& state)
{
    Json::Value playbackState;
    if (state.GetMask().test(AVPlaybackState::PLAYBACK_KEY_STATE)) {
        playbackState[PLAYBACK_STATE] = state.GetState();
    }
    if (state.GetMask().test(AVPlaybackState::PLAYBACK_KEY_IS_FAVORITE)) {
        playbackState[FAVOR_STATE] = state.GetFavorite();
    }
    {
        std::lock_guard lockGuard(cacheJsonLock_);
        if (playbackState == playbackStateCache_ || playbackState.empty()) {
            SLOGI("DoPlaybackStateSyncToRemote with repeat state:%{public}d|isFavor:%{public}d|empty:%{public}d",
                state.GetState(), state.GetFavorite(), playbackState.empty());
            return;
        }
    }
    std::string msg = std::string({MSG_HEAD_MODE, SYNC_FOCUS_PLAY_STATE});
    SoftbusSessionUtils::TransferJsonToStr(playbackState, msg);
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, msg]() {
            SendByte(deviceId_, msg);
        },
        "DoPlaybackStateSyncToRemote");
    SLOGI("DoPlaybackStateSyncToRemote sync state:%{public}d|isFavor:%{public}d done",
        state.GetState(), state.GetFavorite());
    {
        std::lock_guard lockGuard(cacheJsonLock_);
        playbackStateCache_ = playbackState;
    }
}

void MigrateAVSessionServer::DoValidCommandsSyncToRemote(const std::vector<int32_t>& commands)
{
    SLOGI("DoValidCommandsSyncToRemote async commands num:%{public}d", static_cast<int>(commands.size()));
    Json::Value validCommands;
    std::string commandsStr;
    for (int32_t cmd : commands) {
        commandsStr.push_back(static_cast<char>(cmd + '0'));
    }
    validCommands[VALID_COMMANDS] = commandsStr;
    std::string msg = std::string({MSG_HEAD_MODE, SYNC_FOCUS_VALID_COMMANDS});
    SoftbusSessionUtils::TransferJsonToStr(validCommands, msg);
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, msg]() {
            SendByte(deviceId_, msg);
        },
        "DoValidCommandsSyncToRemote");
}

void MigrateAVSessionServer::DoBundleInfoSyncToRemote(sptr<AVControllerItem> controller)
{
    CHECK_AND_RETURN_LOG(controller != nullptr, "DoBundleInfoSyncToRemote with controller null");
    AppExecFwk::ElementName elementName = controller->GetElementOfSession();
    std::string bundleName = elementName.GetBundleName();
    std::string iconStr;
    if (!BundleStatusAdapter::GetInstance().GetBundleIcon(bundleName, iconStr)) {
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
    std::string msg = std::string({MSG_HEAD_MODE, SYNC_FOCUS_BUNDLE_IMG});
    msg += imgStrMin;

    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, msg]() {
            SendByte(deviceId_, msg);
        },
        "DoBundleInfoSyncToRemote");
    SLOGI("DoBundleInfoSyncToRemote async size:%{public}d", static_cast<int>(msg.size()));
}

void MigrateAVSessionServer::UpdateFrontSessionInfoToRemote(sptr<AVControllerItem> controller)
{
    CHECK_AND_RETURN_LOG(controller != nullptr, "UpdateFrontSessionInfoToRemote get controller null");
    SLOGI("UpdateFrontSessionInfoToRemote with sessionId clearCache:%{public}s",
        AVSessionUtils::GetAnonySessionId(controller->GetSessionId()).c_str());

    Json::Value sessionInfo;
    sessionInfo[MIGRATE_SESSION_ID] = controller->GetSessionId();
    AppExecFwk::ElementName elementName = controller->GetElementOfSession();
    sessionInfo[MIGRATE_BUNDLE_NAME] = elementName.GetBundleName();
    sessionInfo[MIGRATE_ABILITY_NAME] = elementName.GetAbilityName();
    std::string msg = std::string({MSG_HEAD_MODE, SYNC_FOCUS_SESSION_INFO});
    SoftbusSessionUtils::TransferJsonToStr(sessionInfo, msg);
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, msg]() {
            SendByte(deviceId_, msg);
        },
        "UpdateFrontSessionInfoToRemote");

    {
        std::lock_guard lockGuard(cacheJsonLock_);
        metaDataCache_.clear();
        playbackStateCache_.clear();
    }
    AVMetaData metaData;
    int32_t ret = controller->GetAVMetaData(metaData);
    if (AVSESSION_SUCCESS == ret || ERR_INVALID_PARAM == ret) {
        std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData.GetMediaImage();
        if (innerPixelMap != nullptr) {
            DoMediaImageSyncToRemote(innerPixelMap);
        }
        DoMetaDataSyncToRemote(metaData);
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

void MigrateAVSessionServer::UpdateEmptyInfoToRemote()
{
    SLOGI("UpdateEmptyInfoToRemote in async");
    Json::Value sessionInfo;
    sessionInfo[MIGRATE_SESSION_ID] = EMPTY_SESSION;
    std::string msg = std::string({MSG_HEAD_MODE, SYNC_FOCUS_SESSION_INFO});
    SoftbusSessionUtils::TransferJsonToStr(sessionInfo, msg);
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, msg]() {
            SendByte(deviceId_, msg);
        },
        "UpdateEmptyInfoToRemote");
}

void MigrateAVSessionServer::ProcFromNext(const std::string &deviceId, const std::string &data)
{
    if (data.length() <= MSG_HEAD_LENGTH) {
        SLOGE("ProcFromNext with data too short:%{public}s", data.c_str());
        return;
    }
    int32_t messageType = data[1];
    std::string commandStr = data.substr(MSG_HEAD_LENGTH);
    Json::Value commandJsonValue;
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
        default:
            SLOGE("messageType %{public}d not support", messageType);
            break;
    }
}

void MigrateAVSessionServer::ProcControlCommandFromNext(Json::Value commandJsonValue)
{
    int32_t commandCode = -1;
    std::string commandArgs;
    if (commandJsonValue.isMember(COMMAND_CODE)) {
        commandCode = commandJsonValue[COMMAND_CODE].isInt() ?
            commandJsonValue[COMMAND_CODE].asInt() : DEFAULT_NUM;
    }
    if (commandJsonValue.isMember(COMMAND_ARGS)) {
        commandArgs = commandJsonValue[COMMAND_ARGS].isString() ?
            commandJsonValue[COMMAND_ARGS].asString() : "";
    }

    sptr<AVControllerItem> controller = nullptr;
    {
        std::lock_guard lockGuard(migrateControllerLock_);
        controller = playerIdToControllerMap_[lastSessionId_];
        CHECK_AND_RETURN_LOG(controller != nullptr, "ProcControlCommandFromNext but get controller null");
    }
    AVControlCommand command;
    if (AVSESSION_SUCCESS == command.SetCommand(commandCode)) {
        if (commandCode == AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE) {
            commandArgs = (commandArgs.empty() || commandArgs == DEFAULT_STRING) ? curAssetId_ : commandArgs;
            command.SetAssetId(commandArgs);
            SLOGI("ProcControlCommandFromNext toggle fav for:%{public}s", commandArgs.c_str());
        }
        controller->SendControlCommand(command);
        SLOGI("ProcControlCommandFromNext code:%{public}d done", commandCode);
    } else {
        SLOGE("ProcControlCommandFromNext parse invalid command type:%{public}d", commandCode);
        return;
    }
}

void MigrateAVSessionServer::ProcessColdStartFromNext(Json::Value commandJsonValue)
{
    std::string bundleName;
    if (commandJsonValue.isMember(MIGRATE_BUNDLE_NAME)) {
        bundleName = commandJsonValue[MIGRATE_BUNDLE_NAME].isString() ?
            commandJsonValue[MIGRATE_BUNDLE_NAME].asString() : "";
    }
    SLOGI("ProcessColdStartFromNext with bundleName:%{public}s", bundleName.c_str());
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "ProcessColdStartFromNext without servicePtr, return");
    servicePtr_->StartAVPlayback(bundleName, "");
}

std::function<void(int32_t)> MigrateAVSessionServer::GetVolumeKeyEventCallbackFunc()
{
    return [this](int32_t volumeNum) {
        std::lock_guard lockGuard(migrateDeviceChangeLock_);
        Json::Value value;
        std::string msg = std::string({MSG_HEAD_MODE, SYNC_SET_VOLUME_COMMAND});
        value[AUDIO_VOLUME] = volumeNum;
        SoftbusSessionUtils::TransferJsonToStr(value, msg);
        SLOGI("server send set volume num async:%{public}d", volumeNum);
        AVSessionEventHandler::GetInstance().AVSessionPostTask(
            [this, msg]() {
                SendByte(deviceId_, msg);
            },
            "GetVolumeKeyEventCallbackFunc");
    };
}

AudioDeviceDescriptorsCallbackFunc MigrateAVSessionServer::GetAvailableDeviceChangeCallbackFunc()
{
    return [this](const AudioDeviceDescriptorsWithSptr& devices) {
        std::lock_guard lockGuard(migrateDeviceChangeLock_);
        Json::Value value = ConvertAudioDeviceDescriptorsToJson(devices);
        std::string msg = std::string({MSG_HEAD_MODE, SYNC_AVAIL_DEVICES_LIST});
        SoftbusSessionUtils::TransferJsonToStr(value, msg);
        SLOGI("server send get available device change callback async");
        AVSessionEventHandler::GetInstance().AVSessionPostTask(
            [this, msg]() {
                SendJsonStringByte(deviceId_, msg);
            },
            "GetVolumeKeyEventCallbackFunc");
    };
}

AudioDeviceDescriptorsCallbackFunc MigrateAVSessionServer::GetPreferredDeviceChangeCallbackFunc()
{
    return [this](const AudioDeviceDescriptorsWithSptr& devices) {
        std::lock_guard lockGuard(migrateDeviceChangeLock_);
        Json::Value value = ConvertAudioDeviceDescriptorsToJson(devices);
        std::string msg = std::string({MSG_HEAD_MODE, SYNC_CURRENT_DEVICE});
        SoftbusSessionUtils::TransferJsonToStr(value, msg);
        SLOGI("server send get preferred device change callback async");
        AVSessionEventHandler::GetInstance().AVSessionPostTask(
            [this, msg]() {
                SendJsonStringByte(deviceId_, msg);
            },
            "GetPreferredDeviceChangeCallbackFunc");
        volumeKeyEventCallbackFunc_(AudioAdapter::GetInstance().GetVolume());
    };
}

Json::Value MigrateAVSessionServer::ConvertAudioDeviceDescriptorsToJson(
    const AudioDeviceDescriptorsWithSptr& devices)
{
    Json::Value jsonArray(Json::arrayValue);
    int32_t deviceNum = 0;
    for (auto& device : devices) {
        if (device == nullptr) {
            continue;
        }
        Json::Value jsonObject = ConvertAudioDeviceDescriptorToJson(device);
        jsonArray[deviceNum++] = jsonObject;
    }
    Json::Value jsonData;
    jsonData[MEDIA_AVAILABLE_DEVICES_LIST] = jsonArray;

    return jsonData;
}

Json::Value MigrateAVSessionServer::ConvertAudioDeviceDescriptorToJson(
    const AudioDeviceDescriptorWithSptr& desc)
{
    Json::Value device;
    device[AUDIO_DEVICE_TYPE] = static_cast<int32_t>(desc->deviceType_);
    device[AUDIO_MAC_ADDRESS] = desc->macAddress_;
    device[AUDIO_NETWORK_ID] = desc->networkId_;
    device[AUDIO_DEVICE_ROLE] = static_cast<int32_t>(desc->deviceRole_);
    device[AUDIO_DEVICE_CATEGORY] = static_cast<int32_t>(desc->deviceCategory_);
    device[AUDIO_DEVICE_NAME] = desc->deviceName_;

    return device;
}

void MigrateAVSessionServer::VolumeControlCommand(Json::Value commandJsonValue)
{
    SLOGI("server recv in VolumeControlCommand case");
    if (!commandJsonValue.isMember(AUDIO_VOLUME)) {
        SLOGE("json parse with error member");
        return;
    }

    int audioVolume = commandJsonValue[AUDIO_VOLUME].isInt() ? commandJsonValue[AUDIO_VOLUME].asInt() : -1;
    AudioAdapter::GetInstance().SetVolume(audioVolume);
}

void MigrateAVSessionServer::SwitchAudioDeviceCommand(Json::Value jsonObject)
{
    SLOGI("server recv in SwitchAudioDeviceCommand case");
    int deviceCategory = jsonObject[AUDIO_DEVICE_CATEGORY].isInt() ? jsonObject[AUDIO_DEVICE_CATEGORY].asInt() : -1;
    int deviceType = jsonObject[AUDIO_DEVICE_TYPE].isInt() ? jsonObject[AUDIO_DEVICE_TYPE].asInt() : -1;
    int deviceRole = jsonObject[AUDIO_DEVICE_ROLE].isInt() ? jsonObject[AUDIO_DEVICE_ROLE].asInt() : -1;
    std::string networkId = jsonObject[AUDIO_NETWORK_ID].isString() ?
        jsonObject[AUDIO_NETWORK_ID].asString() : "ERROR_VALUE";
    std::string deviceName = jsonObject[AUDIO_DEVICE_NAME].isString() ?
        jsonObject[AUDIO_DEVICE_NAME].asString() : "ERROR_VALUE";
    std::string macAddress = jsonObject[AUDIO_MAC_ADDRESS].isString() ?
        jsonObject[AUDIO_MAC_ADDRESS].asString() : "ERROR_VALUE";
    
    std::shared_ptr<AudioDeviceDescriptor> device = std::make_shared<AudioDeviceDescriptor>();
    device->deviceCategory_ = static_cast<AudioStandard::DeviceCategory>(deviceCategory);
    device->deviceType_ = static_cast<AudioStandard::DeviceType>(deviceType);
    device->deviceRole_ = static_cast<AudioStandard::DeviceRole>(deviceRole);
    device->networkId_ = networkId;
    device->deviceName_ = deviceName;
    device->macAddress_ = macAddress;

    AudioAdapter::GetInstance().SelectOutputDevice(device);
}
}

