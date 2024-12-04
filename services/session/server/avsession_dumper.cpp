/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <iostream>
#include <ctime>

#include "avsession_errors.h"
#include "avsession_dumper.h"

namespace OHOS::AVSession {
const int32_t TIME_MAX = 64;
const char* ARGS_HELP = "-h";
const char* ILLEGAL_INFORMATION = "AVSession service, enter '-h' for usage.\n";
const char* ARGS_SHOW_METADATA = "-show_metadata";
const char* ARGS_SHOW_SESSION_INFO = "-show_session_info";
const char* ARGS_SHOW_CONTROLLER_INFO = "-show_controller_info";
const char* ARGS_SHOW_ERROR_INFO = "-show_error_info";
const char* ARGS_TRUSTED_DEVICES_INFO = "-show_trusted_devices_Info";

std::map<std::string, AVSessionDumper::DumpActionType> AVSessionDumper::funcMap_ = {
    { ARGS_SHOW_METADATA, AVSessionDumper::ShowMetaData },
    { ARGS_SHOW_SESSION_INFO, AVSessionDumper::ShowSessionInfo },
    { ARGS_SHOW_CONTROLLER_INFO, AVSessionDumper::ShowControllerInfo },
    { ARGS_SHOW_ERROR_INFO, AVSessionDumper::ShowErrorInfo },
    { ARGS_TRUSTED_DEVICES_INFO, AVSessionDumper::ShowTrustedDevicesInfo },
};

std::map<int32_t, std::string> AVSessionDumper::playBackStates_ = {
    { AVPlaybackState::PLAYBACK_STATE_INITIAL, "initial" },
    { AVPlaybackState::PLAYBACK_STATE_PREPARE, "preparing" },
    { AVPlaybackState::PLAYBACK_STATE_PLAY, "playing" },
    { AVPlaybackState::PLAYBACK_STATE_PAUSE, "paused" },
    { AVPlaybackState::PLAYBACK_STATE_FAST_FORWARD, "fast_forward" },
    { AVPlaybackState::PLAYBACK_STATE_REWIND, "rewind" },
    { AVPlaybackState::PLAYBACK_STATE_STOP, "stop" },
    { AVPlaybackState::PLAYBACK_STATE_COMPLETED, "complete" },
    { AVPlaybackState::PLAYBACK_STATE_RELEASED, "released" },
    { AVPlaybackState::PLAYBACK_STATE_ERROR, "error" },
    { AVPlaybackState::PLAYBACK_STATE_IDLE, "idle" },
    { AVPlaybackState::PLAYBACK_STATE_BUFFERING, "buffering" },
};

std::map<int32_t, std::string> AVSessionDumper::deviceTypeId_ = {
    {DistributedHardware::DEVICE_TYPE_UNKNOWN, "unknown" },
    {DistributedHardware::DEVICE_TYPE_WIFI_CAMERA, "camera" },
    {DistributedHardware::DEVICE_TYPE_AUDIO, "audio" },
    {DistributedHardware::DEVICE_TYPE_PC, "pc" },
    {DistributedHardware::DEVICE_TYPE_PHONE, "phone" },
    {DistributedHardware::DEVICE_TYPE_PAD, "pad" },
    {DistributedHardware::DEVICE_TYPE_WATCH, "watch" },
    {DistributedHardware::DEVICE_TYPE_CAR, "car" },
    {DistributedHardware::DEVICE_TYPE_TV, "tv" },
};

std::map<int32_t, std::string> AVSessionDumper::loopMode_ = {
    { AVPlaybackState::LOOP_MODE_SEQUENCE, "sequence" },
    { AVPlaybackState::LOOP_MODE_SINGLE, "single" },
    { AVPlaybackState::LOOP_MODE_LIST, "list" },
    { AVPlaybackState::LOOP_MODE_SHUFFLE, "shuffle" },
    { AVPlaybackState::LOOP_MODE_CUSTOM, "custom" },
};

std::vector<std::string> AVSessionDumper::errMessage_ = {};

void AVSessionDumper::ShowHelp(std::string& result) const
{
    result.append("Usage:dump <command> [options]\n")
        .append("Description:\n")
        .append("-show_metadata               :show all avsession metadata in the system\n")
        .append("-show_session_info           :show information of all sessions\n")
        .append("-show_controller_info        :show information of all controllers \n")
        .append("-show_error_info             :show error information about avsession\n")
        .append("-show_trusted_devices_Info   :show trusted devices Info\n");
}

void AVSessionDumper::ShowMetaData(std::string& result, const AVSessionService& sessionService)
{
    int32_t controllerIndex = 0;
    int32_t itemIndex = 0;
    for (const auto& it : sessionService.controllers_) {
        result.append("ControllerIndex: " + std::to_string(++controllerIndex) + "\n");
        for (const auto& item : it.second) {
            result.append("ItemIndex: " + std::to_string(++itemIndex)+ "\n");
            AVMetaData metaData;
            item->GetAVMetaData(metaData);

            result.append("Metadata:\n");
            result.append("        assetid              : " + metaData.GetAssetId() + "\n");
            result.append("        title                : " + metaData.GetTitle() + "\n");
            result.append("        artist               : " + metaData.GetArtist() + "\n");
            result.append("        author               : " + metaData.GetAuthor() + "\n");
            result.append("        avqueue name         : " + metaData.GetAVQueueName() + "\n");
            result.append("        avqueue id           : " + metaData.GetAVQueueId() + "\n");
            result.append("        avqueue url          : " + metaData.GetAVQueueImageUri() + "\n");
            result.append("        album                : " + metaData.GetAlbum() + "\n");
            result.append("        writer               : " + metaData.GetWriter() + "\n");
            result.append("        composer             : " + metaData.GetComposer() + "\n");
            result.append("        duration             : " + std::to_string(metaData.GetDuration()) + "\n");
            result.append("        media image url      : " + metaData.GetMediaImageUri() + "\n");
            result.append("        publish date         : " + std::to_string(metaData.GetPublishDate()) + "\n");
            result.append("        subtitle             : " + metaData.GetSubTitle() + "\n");
            result.append("        description          : " + metaData.GetDescription() + "\n");
            result.append("        lyric                : " + metaData.GetLyric() + "\n");
            result.append("        previous assetid     : " + metaData.GetPreviousAssetId() + "\n");
            result.append("        next assetid         : " + metaData.GetNextAssetId() + "\n");
            result.append("        skip intervals       : " + std::to_string(metaData.GetSkipIntervals()) + "\n");
            result.append("        filter               : " + std::to_string(metaData.GetFilter()) + "\n");
        }
    }
}

void AVSessionDumper::ShowTrustedDevicesInfo(std::string& result, const AVSessionService& sessionService)
{
    std::vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
    DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList("av_session", "", deviceList);

    std::string buff;
    result.append("Trusted Devices Info:\n\n")
        .append("Count                          : " + std::to_string(deviceList.size()) + "\n");
    for (const auto& device : deviceList) {
        buff=device.deviceId;
        result.append("         device id             : ");
        result.append(buff + "  ");

        buff=device.deviceName;
        result.append("\n        device name            : ");
        result.append(buff + "  ");

        result.append("\n        device type id         : " + deviceTypeId_.find(device.deviceTypeId)->second);

        buff=device.networkId;
        result.append("\n        network  id            : ");
        result.append(buff + "  ");

        result.append("\n        range                  : " + std::to_string(device.range));
        result.append("\n");
    }
}

void AVSessionDumper::ShowSessionInfo(std::string& result, const AVSessionService& sessionService)
{
    std::vector<sptr<AVSessionItem>> sessions = sessionService.GetContainer().GetAllSessions();
    result.append("Session Information:\n\n")
        .append("Count                        : " + std::to_string(sessions.size()));

    AVSessionDescriptor descriptor;
    for (const auto& session : sessions) {
        descriptor = session->GetDescriptor();
        std::string isActive = descriptor.isActive_ ? "true" : "false";
        std::string isTopSession = descriptor.isTopSession_ ? "true" : "false";
        result.append("\n\ncurrent session id           : " + descriptor.sessionId_ + "\n")
            .append("State:\n")
            .append("is active                    : " + isActive + "\n")
            .append("is the topsession            : " + isTopSession)
            .append("\n\nConfiguration:\n")
            .append("pid                          : " + std::to_string(session->GetPid()) + "\n")
            .append("uid                          : " + std::to_string(session->GetUid()) + "\n");
        if (descriptor.sessionType_ == AVSession::SESSION_TYPE_AUDIO) {
            result.append("session type                 : audio\n");
        } else if (descriptor.sessionType_ == AVSession::SESSION_TYPE_VIDEO) {
            result.append("session type                 : video\n");
        } else if (descriptor.sessionType_ == AVSession::SESSION_TYPE_VOICE_CALL) {
            result.append("session type                 : voice_call\n");
        } else if (descriptor.sessionType_ == AVSession::SESSION_TYPE_VIDEO_CALL) {
            result.append("session type                 : video_call\n");
        } else {
            result.append("session type is invalid.\n");
        }

        result.append("session tag                  : " + descriptor.sessionTag_ + "\n")
            .append("bundle name                  : " + descriptor.elementName_.GetBundleName() + "\n")
            .append("ability name                 : " + descriptor.elementName_.GetAbilityName() + "\n");

        result.append("outputdevice\n")
            .append("        the count of devices         : " +
            std::to_string(descriptor.outputDeviceInfo_.deviceInfos_.size()) +
            "\n        device id                    : ");
        for (const auto& deviceInfo : descriptor.outputDeviceInfo_.deviceInfos_) {
            result.append(deviceInfo.deviceId_ + "  ");
        }
        result.append("\n        device name                  : ");
        for (const auto& deviceInfo : descriptor.outputDeviceInfo_.deviceInfos_) {
            result.append(deviceInfo.deviceName_ + "  ");
        }
        result.append("\n\nRelated Controllers:\n")
            .append("the count of controllers     : " + std::to_string(session->controllers_.size()) + "\n")
            .append("pid of controllers           : ");
        for (const auto& it : session->controllers_) {
            result.append(std::to_string(it.first) + "  ");
        }
    }
}

void AVSessionDumper::ShowControllerInfo(std::string& result, const AVSessionService& sessionService)
{
    AVPlaybackState playbackState;
    std::string temp;
    int32_t controllerCount = 0;
    for (const auto& it : sessionService.controllers_) {
        for (const auto& controller : it.second) {
            controllerCount++;
            controller->GetAVPlaybackState(playbackState);

            int32_t state = playbackState.GetState();
            double speed = playbackState.GetSpeed();
            AVPlaybackState::Position position = playbackState.GetPosition();
            int64_t bufferedTime = playbackState.GetBufferedTime();
            int32_t loopMode = playbackState.GetLoopMode();
            std::string isFavorite = playbackState.GetFavorite() ? "true" : "false";

            temp.append("\n\ncurretn controller pid       : " + std::to_string(controller->GetPid()) + "\n")
                .append("State:\n")
                .append("state                        : " + playBackStates_.find(state)->second + "\n")
                .append("speed                        : " + std::to_string(speed) + "\n")
                .append("position\n")
                .append("        elapsed time                 : " + std::to_string(position.elapsedTime_) + "\n")
                .append("        update time                  : " + std::to_string(position.updateTime_) + "\n")
                .append("buffered time                : " + std::to_string(bufferedTime) + "\n")
                .append("loopmode                     : " + loopMode_.find(loopMode)->second + "\n")
                .append("is favorite                  : " + isFavorite + "\n")
                .append("\nRelated Sessionid            : " + controller->GetSessionId());
        }
    }
    result.append("Controller Information:\n\n")
        .append("Count                        : " + std::to_string(controllerCount))
        .append(temp);
}

void AVSessionDumper::SetErrorInfo(const std::string& inErrMsg)
{
    time_t now = time(nullptr);
    if (now == -1) {
        SLOGE("get time failed");
        return;
    }
    struct tm *locTime = localtime(&now);
    if (locTime == nullptr) {
        SLOGE("get localtime failed");
        return;
    }
    char tempTime [TIME_MAX];
    auto ret = strftime(tempTime, sizeof(tempTime), "%Y-%m-%d %H:%M:%S", locTime);
    if (ret == 0) {
        SLOGE("strftime failed");
        return;
    }
    auto time  = tempTime;
    std::string msgInfo;
    msgInfo.append(time + inErrMsg);
    errMessage_.push_back(msgInfo);
}

void AVSessionDumper::ShowErrorInfo(std::string& result, const AVSessionService& sessionService)
{
    if (errMessage_.empty()) {
        result.append("No Error Information!\n");
        return;
    }

    int32_t errMsgCount = 0;
    result.append("Error Information:\n\n");
    for (auto iter = errMessage_.begin(); iter != errMessage_.end(); iter++) {
        result.append(errMessage_.at(errMsgCount++) + "\n");
    }
}

void AVSessionDumper::ProcessParameter(const std::string& arg, std::string& result,
                                       const AVSessionService& sessionService) const
{
    if (arg == ARGS_HELP) {
        ShowHelp(result);
    } else {
        auto it = funcMap_.find(arg);
        if (it != funcMap_.end()) {
            it->second(result, sessionService);
        } else {
            ShowIllegalInfo(result);
        }
    }
}

void AVSessionDumper::ShowIllegalInfo(std::string& result) const
{
    result.append(ILLEGAL_INFORMATION);
}

void AVSessionDumper::Dump(const std::vector<std::string>& args, std::string& result,
    const AVSessionService& sessionService) const
{
    result.clear();
    auto argsSize = args.size();
    if (argsSize == 1) {
        ProcessParameter(args[0], result, sessionService);
    } else {
        ShowIllegalInfo(result);
    }
}
} // namespace OHOS::AVSession