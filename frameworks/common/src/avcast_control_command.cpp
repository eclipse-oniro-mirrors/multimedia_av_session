/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "avcast_control_command.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVCastControlCommand::AVCastControlCommand()
    : cmd_(CAST_CONTROL_CMD_INVALID)
{
}

AVCastControlCommand::~AVCastControlCommand()
{
}

AVCastControlCommand *AVCastControlCommand::Unmarshalling(Parcel& data)
{
    auto result = new (std::nothrow) AVCastControlCommand();
    if (result != nullptr) {
        int32_t cmd = data.ReadInt32();
        result->SetCommand(cmd);
        switch (cmd) {
            case CAST_CONTROL_CMD_FAST_FORWARD:
                result->SetForwardTime(data.ReadInt32());
                break;
            case CAST_CONTROL_CMD_REWIND:
                result->SetRewindTime(data.ReadInt32());
                break;
            case CAST_CONTROL_CMD_SEEK:
                result->SetSeekTime(data.ReadInt32());
                break;
            case CAST_CONTROL_CMD_SET_VOLUME:
                result->SetVolume(data.ReadInt32());
                break;
            case CAST_CONTROL_CMD_SET_SPEED:
                result->SetSpeed(data.ReadInt32());
                break;
            case CAST_CONTROL_CMD_SET_LOOP_MODE:
                result->SetLoopMode(data.ReadInt32());
                break;
            default:
                break;
        }
    }
    return result;
}

bool AVCastControlCommand::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt32(cmd_)) {
        return false;
    }
    switch (cmd_) {
        case CAST_CONTROL_CMD_SEEK:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int32_t>(param_)
                && parcel.WriteInt64(std::get<int32_t>(param_)), false, "write seek time failed");
            break;
        case CAST_CONTROL_CMD_SET_VOLUME:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int32_t>(param_)
                && parcel.WriteInt32(std::get<int32_t>(param_)), false, "write volume failed");
            break;
        case CAST_CONTROL_CMD_SET_SPEED:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int32_t>(param_)
                && parcel.WriteInt32(std::get<int32_t>(param_)), false, "write speed failed");
            break;
        default:
            break;
    }
    return true;
}

bool AVCastControlCommand::IsValid() const
{
    return cmd_ > CAST_CONTROL_CMD_INVALID && cmd_ < CAST_CONTROL_CMD_MAX;
}

int32_t AVCastControlCommand::SetCommand(int32_t cmd)
{
    if (cmd <= CAST_CONTROL_CMD_INVALID || cmd >= CAST_CONTROL_CMD_MAX) {
        return ERR_INVALID_PARAM;
    }
    cmd_ = cmd;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::GetCommand() const
{
    return cmd_;
}

int32_t AVCastControlCommand::SetForwardTime(int32_t forwardTime)
{
    if (forwardTime <= 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = forwardTime;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::GetForwardTime(int32_t& forwardTime) const
{
    if (!std::holds_alternative<int32_t>(param_)) {
        return AVSESSION_ERROR;
    }
    forwardTime = std::get<int32_t>(param_);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::SetRewindTime(int32_t rewindTime)
{
    if (rewindTime < 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = rewindTime;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::GetRewindTime(int32_t& rewindTime) const
{
    if (!std::holds_alternative<int32_t>(param_)) {
        return AVSESSION_ERROR;
    }
    rewindTime = std::get<int32_t>(param_);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::SetSeekTime(int32_t seekTime)
{
    if (seekTime < 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = seekTime;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::GetSeekTime(int32_t& seekTime) const
{
    if (!std::holds_alternative<int32_t>(param_)) {
        return AVSESSION_ERROR;
    }
    seekTime = std::get<int32_t>(param_);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::SetVolume(int32_t volume)
{
    param_ = volume;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::GetVolume(int32_t& volume) const
{
    if (!std::holds_alternative<int32_t>(param_)) {
        return AVSESSION_ERROR;
    }
    volume = std::get<int32_t>(param_);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::SetSpeed(int32_t speed)
{
    if (speed < 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = speed;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::GetSpeed(int32_t& speed) const
{
    if (!std::holds_alternative<int32_t>(param_)) {
        return AVSESSION_ERROR;
    }
    speed = std::get<int32_t>(param_);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::SetLoopMode(int32_t loopMode)
{
    if (loopMode < 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = loopMode;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControlCommand::GetLoopMode(int32_t& loopMode) const
{
    if (!std::holds_alternative<int32_t>(param_)) {
        return AVSESSION_ERROR;
    }
    loopMode = std::get<int32_t>(param_);
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
