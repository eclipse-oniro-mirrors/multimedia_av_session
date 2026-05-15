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

#include "utils.h"
#include <iostream>
#include <unordered_map>
#include "avsession_errors.h"
#include "avplayback_state.h"
#include "avcontrol_command.h"

namespace OHOS::AVSession::Cli {

static const std::unordered_map<int32_t, std::string> errorMap = {
    {AVSESSION_SUCCESS, "Success"},
    {AVSESSION_ERROR, "General error"},
    {ERR_NO_MEMORY, "No memory"},
    {ERR_INVALID_PARAM, "Invalid parameter"},
    {ERR_SERVICE_NOT_EXIST, "Service not exist"},
    {ERR_SESSION_LISTENER_EXIST, "Session listener already exist"},
    {ERR_MARSHALLING, "Marshalling error"},
    {ERR_UNMARSHALLING, "Unmarshalling error"},
    {ERR_IPC_SEND_REQUEST, "IPC send request error"},
    {ERR_SESSION_EXCEED_MAX, "Session exceed maximum"},
    {ERR_SESSION_NOT_EXIST, "Session not exist"},
    {ERR_COMMAND_NOT_SUPPORT, "Command not support"},
    {ERR_CONTROLLER_NOT_EXIST, "Controller not exist"},
    {ERR_NO_PERMISSION, "No permission"},
    {ERR_SESSION_DEACTIVE, "Session deactivated"},
    {ERR_CONTROLLER_IS_EXIST, "Controller already exist"},
    {ERR_START_ABILITY_IS_RUNNING, "Start ability is running"},
    {ERR_ABILITY_NOT_AVAILABLE, "Ability not available"},
    {ERR_START_ABILITY_TIMEOUT, "Start ability timeout"},
    {ERR_COMMAND_SEND_EXCEED_MAX, "Command send exceed maximum"},
    {ERR_RPC_SEND_REQUEST, "RPC send request error"},
    {ERR_DEVICE_CONNECTION_FAILED, "Device connection failed"},
    {ERR_REMOTE_CONNECTION_NOT_EXIST, "Remote connection not exist"},
    {ERR_SESSION_IS_EXIST, "Session already exist"},
    {ERR_PERMISSION_DENIED, "Permission denied"},
    {ERR_DESKTOPLYRIC_NOT_SUPPORT, "Desktop lyric not support"},
    {ERR_DESKTOPLYRIC_NOT_ENABLE, "Desktop lyric not enable"},
};

static const std::unordered_map<int32_t, std::string> playbackStateMap = {
    {AVPlaybackState::PLAYBACK_STATE_INITIAL, "initial"},
    {AVPlaybackState::PLAYBACK_STATE_PREPARE, "prepare"},
    {AVPlaybackState::PLAYBACK_STATE_PLAY, "play"},
    {AVPlaybackState::PLAYBACK_STATE_PAUSE, "pause"},
    {AVPlaybackState::PLAYBACK_STATE_FAST_FORWARD, "fast_forward"},
    {AVPlaybackState::PLAYBACK_STATE_REWIND, "rewind"},
    {AVPlaybackState::PLAYBACK_STATE_STOP, "stop"},
    {AVPlaybackState::PLAYBACK_STATE_COMPLETED, "completed"},
    {AVPlaybackState::PLAYBACK_STATE_RELEASED, "released"},
    {AVPlaybackState::PLAYBACK_STATE_ERROR, "error"},
    {AVPlaybackState::PLAYBACK_STATE_IDLE, "idle"},
    {AVPlaybackState::PLAYBACK_STATE_BUFFERING, "buffering"},
};

static const std::unordered_map<int32_t, std::string> loopModeMap = {
    {AVPlaybackState::LOOP_MODE_UNDEFINED, "undefined"},
    {AVPlaybackState::LOOP_MODE_SEQUENCE, "sequence"},
    {AVPlaybackState::LOOP_MODE_SINGLE, "single"},
    {AVPlaybackState::LOOP_MODE_LIST, "list"},
    {AVPlaybackState::LOOP_MODE_SHUFFLE, "shuffle"},
    {AVPlaybackState::LOOP_MODE_CUSTOM, "custom"},
};

static const std::unordered_map<int32_t, std::string> controlCommandMap = {
    {AVControlCommand::SESSION_CMD_INVALID, "invalid"},
    {AVControlCommand::SESSION_CMD_PLAY, "play"},
    {AVControlCommand::SESSION_CMD_PAUSE, "pause"},
    {AVControlCommand::SESSION_CMD_STOP, "stop"},
    {AVControlCommand::SESSION_CMD_PLAY_NEXT, "play_next"},
    {AVControlCommand::SESSION_CMD_PLAY_PREVIOUS, "play_previous"},
    {AVControlCommand::SESSION_CMD_FAST_FORWARD, "fast_forward"},
    {AVControlCommand::SESSION_CMD_REWIND, "rewind"},
    {AVControlCommand::SESSION_CMD_SEEK, "seek"},
    {AVControlCommand::SESSION_CMD_SET_SPEED, "set_speed"},
    {AVControlCommand::SESSION_CMD_SET_LOOP_MODE, "set_loop_mode"},
    {AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE, "toggle_favorite"},
    {AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID, "play_from_assetid"},
    {AVControlCommand::SESSION_CMD_AVCALL_ANSWER, "avcall_answer"},
    {AVControlCommand::SESSION_CMD_AVCALL_HANG_UP, "avcall_hang_up"},
    {AVControlCommand::SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE, "avcall_toggle_call_mute"},
    {AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT, "media_key_support"},
    {AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE, "set_target_loop_mode"},
    {AVControlCommand::SESSION_CMD_PLAY_WITH_ASSETID, "play_with_assetid"},
};

void CLI_LOG(const std::string& message)
{
    std::cout << "[LOG] " << message << std::endl;
}

void CLI_ERROR(const std::string& message)
{
    std::cerr << "[ERROR] " << message << std::endl;
}

void OutputSuccess(const nlohmann::json& data)
{
    nlohmann::json output;
    output["type"] = "result";
    output["status"] = "success";
    output["data"] = data;
    std::cout << output.dump() << std::endl;
}

void OutputError(int32_t errCode, const std::string& errMsg, const std::string& suggestion)
{
    nlohmann::json output;
    output["type"] = "result";
    output["status"] = "error";
    output["errCode"] = errCode;
    output["errMsg"] = errMsg;
    output["suggestion"] = suggestion;
    std::cout << output.dump() << std::endl;
}

std::string GetErrorString(int32_t errCode)
{
    auto it = errorMap.find(errCode);
    if (it != errorMap.end()) {
        return it->second;
    }
    return "Unknown error: " + std::to_string(errCode);
}

std::string GetPlaybackStateString(int32_t state)
{
    auto it = playbackStateMap.find(state);
    if (it != playbackStateMap.end()) {
        return it->second;
    }
    return "unknown";
}

std::string GetLoopModeString(int32_t loopMode)
{
    auto it = loopModeMap.find(loopMode);
    if (it != loopModeMap.end()) {
        return it->second;
    }
    return "unknown";
}

std::string GetControlCommandString(int32_t cmd)
{
    auto it = controlCommandMap.find(cmd);
    if (it != controlCommandMap.end()) {
        return it->second;
    }
    return "unknown";
}

nlohmann::json AVSessionDescriptorToJson(const AVSessionDescriptor& descriptor)
{
    nlohmann::json json;
    json["sessionId"] = descriptor.sessionId_;
    json["sessionType"] = descriptor.sessionType_;
    json["sessionTag"] = descriptor.sessionTag_;
    json["elementName"] = {
        {"bundleName", descriptor.elementName_.GetBundleName()},
        {"moduleName", descriptor.elementName_.GetModuleName()},
        {"abilityName", descriptor.elementName_.GetAbilityName()}
    };
    json["pid"] = descriptor.pid_;
    json["uid"] = descriptor.uid_;
    json["isActive"] = descriptor.isActive_;
    json["isTopSession"] = descriptor.isTopSession_;
    json["isThirdPartyApp"] = descriptor.isThirdPartyApp_;
    json["outputDeviceInfo"] = OutputDeviceInfoToJson(descriptor.outputDeviceInfo_);
    json["userId"] = descriptor.userId_;
    return json;
}

nlohmann::json AVQueueInfoToJson(const AVQueueInfo& info)
{
    nlohmann::json json;
    json["bundleName"] = info.GetBundleName();
    json["avQueueName"] = info.GetAVQueueName();
    json["avQueueId"] = info.GetAVQueueId();
    json["avQueueImageUri"] = info.GetAVQueueImageUri();
    json["avQueueLength"] = info.GetAVQueueLength();
    return json;
}

nlohmann::json AVPlaybackStateToJson(const AVPlaybackState& state)
{
    nlohmann::json json;
    json["state"] = GetPlaybackStateString(state.GetState());
    json["speed"] = state.GetSpeed();
    auto position = state.GetPosition();
    json["position"] = {
        {"elapsedTime", position.elapsedTime_},
        {"updateTime", position.updateTime_}
    };
    json["bufferedTime"] = state.GetBufferedTime();
    json["loopMode"] = GetLoopModeString(state.GetLoopMode());
    json["isFavorite"] = state.GetFavorite();
    json["activeItemId"] = state.GetActiveItemId();
    json["volume"] = state.GetVolume();
    json["maxVolume"] = state.GetMaxVolume();
    json["muted"] = state.GetMuted();
    json["duration"] = state.GetDuration();
    json["videoWidth"] = state.GetVideoWidth();
    json["videoHeight"] = state.GetVideoHeight();
    return json;
}

nlohmann::json AVMetaDataToJson(const AVMetaData& meta)
{
    nlohmann::json json;
    json["assetId"] = meta.GetAssetId();
    json["title"] = meta.GetTitle();
    json["artist"] = meta.GetArtist();
    json["author"] = meta.GetAuthor();
    json["avQueueName"] = meta.GetAVQueueName();
    json["avQueueId"] = meta.GetAVQueueId();
    json["avQueueImageUri"] = meta.GetAVQueueImageUri();
    json["album"] = meta.GetAlbum();
    json["writer"] = meta.GetWriter();
    json["composer"] = meta.GetComposer();
    json["duration"] = meta.GetDuration();
    json["mediaImageUri"] = meta.GetMediaImageUri();
    json["publishDate"] = meta.GetPublishDate();
    json["subTitle"] = meta.GetSubTitle();
    json["description"] = meta.GetDescription();
    json["lyric"] = meta.GetLyric();
    json["singleLyricText"] = meta.GetSingleLyricText();
    json["previousAssetId"] = meta.GetPreviousAssetId();
    json["nextAssetId"] = meta.GetNextAssetId();
    json["skipIntervals"] = meta.GetSkipIntervals();
    json["fastForwardSkipIntervals"] = meta.GetFastForwardSkipIntervals();
    json["rewindSkipIntervals"] = meta.GetRewindSkipIntervals();
    json["filter"] = meta.GetFilter();
    json["displayTags"] = meta.GetDisplayTags();
    return json;
}

nlohmann::json AVQueueItemToJson(const AVQueueItem& item)
{
    nlohmann::json json;
    json["itemId"] = item.GetItemId();
    auto desc = item.GetDescription();
    if (desc != nullptr) {
        json["description"] = {
            {"mediaId", desc->GetMediaId()},
            {"title", desc->GetTitle()},
            {"subTitle", desc->GetSubtitle()},
            {"description", desc->GetDescription()},
            {"mediaUri", desc->GetMediaUri()}
        };
    }
    return json;
}

nlohmann::json OutputDeviceInfoToJson(const OutputDeviceInfo& info)
{
    nlohmann::json json = nlohmann::json::array();
    for (const auto& device : info.deviceInfos_) {
        nlohmann::json deviceJson;
        deviceJson["castCategory"] = device.castCategory_;
        deviceJson["deviceId"] = device.deviceId_;
        deviceJson["deviceName"] = device.deviceName_;
        deviceJson["networkId"] = device.networkId_;
        deviceJson["ipAddress"] = device.ipAddress_;
        deviceJson["manufacturer"] = device.manufacturer_;
        deviceJson["modelName"] = device.modelName_;
        deviceJson["deviceType"] = device.deviceType_;
        deviceJson["providerId"] = device.providerId_;
        deviceJson["supportedProtocols"] = device.supportedProtocols_;
        deviceJson["authenticationStatus"] = device.authenticationStatus_;
        json.push_back(deviceJson);
    }
    return json;
}

}