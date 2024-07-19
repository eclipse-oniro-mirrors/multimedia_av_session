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

#include "avcontrol_command.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVControlCommand::AVControlCommand()
    : cmd_(SESSION_CMD_INVALID)
{
}

AVControlCommand::~AVControlCommand()
{
}

AVControlCommand *AVControlCommand::Unmarshalling(Parcel& data)
{
    auto result = new (std::nothrow) AVControlCommand();
    if (result != nullptr) {
        int32_t cmd = data.ReadInt32();
        result->SetCommand(cmd);
        switch (cmd) {
            case SESSION_CMD_FAST_FORWARD:
                result->SetForwardTime(data.ReadInt64());
                break;
            case SESSION_CMD_REWIND:
                result->SetRewindTime(data.ReadInt64());
                break;
            case SESSION_CMD_SEEK:
                result->SetSeekTime(data.ReadInt64());
                break;
            case SESSION_CMD_SET_SPEED:
                result->SetSpeed(data.ReadDouble());
                break;
            case SESSION_CMD_SET_LOOP_MODE:
                result->SetLoopMode(data.ReadInt32());
                break;
            case SESSION_CMD_TOGGLE_FAVORITE:
                result->SetAssetId(data.ReadString());
                break;
            case SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE:
                result->SetAVCallMuted(data.ReadBool());
                break;
            case SESSION_CMD_PLAY_FROM_ASSETID:
                result->SetPlayFromAssetId(data.ReadInt64());
                break;
            default:
                break;
        }
    }
    return result;
}

bool AVControlCommand::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt32(cmd_)) {
        return false;
    }
    switch (cmd_) {
        case SESSION_CMD_FAST_FORWARD:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int64_t>(param_)
                && parcel.WriteInt64(std::get<int64_t>(param_)), false, "write fast forward time failed");
            break;
        case SESSION_CMD_REWIND:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int64_t>(param_)
                && parcel.WriteInt64(std::get<int64_t>(param_)), false, "write rewind time failed");
            break;
        case SESSION_CMD_SEEK:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int64_t>(param_)
                && parcel.WriteInt64(std::get<int64_t>(param_)), false, "write seek time failed");
            break;
        case SESSION_CMD_SET_SPEED:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<double>(param_)
                && parcel.WriteDouble(std::get<double>(param_)), false, "write speed failed");
            break;
        case SESSION_CMD_SET_LOOP_MODE:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int32_t>(param_)
                && parcel.WriteInt32(std::get<int32_t>(param_)), false, "write loop mode failed");
            break;
        case SESSION_CMD_TOGGLE_FAVORITE:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<std::string>(param_)
                && parcel.WriteString(std::get<std::string>(param_)), false, "write toggle favorite failed");
            break;
        case SESSION_CMD_PLAY_FROM_ASSETID:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int64_t>(param_)
                && parcel.WriteInt64(std::get<int64_t>(param_)), false, "write play from assetId failed");
            break;
        default:
            break;
    }
    return true;
}

bool AVControlCommand::IsValid() const
{
    return cmd_ > SESSION_CMD_INVALID && cmd_ < SESSION_CMD_MAX;
}

int32_t AVControlCommand::SetCommand(int32_t cmd)
{
    if (cmd <= SESSION_CMD_INVALID || cmd >= SESSION_CMD_MAX) {
        return ERR_INVALID_PARAM;
    }
    cmd_ = cmd;
    return AVSESSION_SUCCESS;
}

int32_t AVControlCommand::GetCommand() const
{
    return cmd_;
}

int32_t AVControlCommand::SetSpeed(double speed)
{
    if (speed <= 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = speed;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControlCommand::GetSpeed(double& speed) const
{
    if (!std::holds_alternative<double>(param_)) {
        return AVSESSION_ERROR;
    }
    speed = std::get<double>(param_);
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControlCommand::SetForwardTime(int64_t forwardTime)
{
    SLOGD("SetForwardTime with time %{public}jd", static_cast<int64_t>(forwardTime));
    if (forwardTime < 0) {
        SLOGE("SetForwardTime error");
        return ERR_INVALID_PARAM;
    }
    param_ = forwardTime;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControlCommand::GetForwardTime(int64_t& forwardTime) const
{
    if (!std::holds_alternative<int64_t>(param_)) {
        SLOGE("GetForwardTime error");
        return AVSESSION_ERROR;
    }
    forwardTime = std::get<int64_t>(param_);
    SLOGE("GetForwardTime with time %{public}jd", static_cast<int64_t>(forwardTime));
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControlCommand::SetRewindTime(int64_t rewindTime)
{
    SLOGD("SetRewindTime with time %{public}jd", static_cast<int64_t>(rewindTime));
    if (rewindTime < 0) {
        SLOGE("SetRewindTime error");
        return ERR_INVALID_PARAM;
    }
    param_ = rewindTime;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControlCommand::GetRewindTime(int64_t& rewindTime) const
{
    if (!std::holds_alternative<int64_t>(param_)) {
        SLOGE("GetRewindTime error");
        return AVSESSION_ERROR;
    }
    rewindTime = std::get<int64_t>(param_);
    SLOGE("GetRewindTime with time %{public}jd", static_cast<int64_t>(rewindTime));
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControlCommand::SetSeekTime(int64_t time)
{
    if (time < 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = time;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControlCommand::GetSeekTime(int64_t& time) const
{
    if (!std::holds_alternative<int64_t>(param_)) {
        return AVSESSION_ERROR;
    }
    time = std::get<int64_t>(param_);
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControlCommand::SetLoopMode(int32_t mode)
{
    if (mode < AVPlaybackState::LOOP_MODE_UNDEFINED || mode > AVPlaybackState::LOOP_MODE_CUSTOM) {
        return ERR_INVALID_PARAM;
    }
    param_ = mode;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControlCommand::GetLoopMode(int32_t& mode) const
{
    if (!std::holds_alternative<int32_t>(param_)) {
        return AVSESSION_ERROR;
    }
    mode = std::get<int32_t>(param_);
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControlCommand::SetAssetId(const std::string& assetId)
{
    if (assetId.empty()) {
        return ERR_INVALID_PARAM;
    }
    param_ = assetId;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControlCommand::GetAssetId(std::string& assetId) const
{
    if (!std::holds_alternative<std::string>(param_)) {
        return AVSESSION_ERROR;
    }
    assetId = std::get<std::string>(param_);
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControlCommand::SetAVCallMuted(const bool isAVCallMuted)
{
    param_ = isAVCallMuted;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControlCommand::IsAVCallMuted(bool& isAVCallMuted) const
{
    if (!std::holds_alternative<bool>(param_)) {
        return AVSESSION_ERROR;
    }
    isAVCallMuted = std::get<bool>(param_);
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControlCommand::SetPlayFromAssetId(int64_t playFromAssetId)
{
    param_ = playFromAssetId;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControlCommand::GetPlayFromAssetId(int64_t& playFromAssetId) const
{
    if (!std::holds_alternative<int64_t>(param_)) {
        return AVSESSION_ERROR;
    }
    playFromAssetId = std::get<int64_t>(param_);
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
