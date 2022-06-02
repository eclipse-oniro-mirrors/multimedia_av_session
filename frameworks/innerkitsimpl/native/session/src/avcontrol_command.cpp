/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVControlCommand::AVControlCommand()
{
    cmd_ = SESSION_CMD_INVALID;
}

AVControlCommand::~AVControlCommand()
{
}

AVControlCommand *AVControlCommand::Unmarshalling(Parcel &data)
{
    auto result = new (std::nothrow) AVControlCommand();
    if (result != nullptr) {
        int32_t cmd = data.ReadInt32();
        result->SetCommand(cmd);
        switch (cmd) {
            case SESSION_CMD_SEEK:
                result->SetSeekTime(data.ReadInt64());
                break;
            case SESSION_CMD_SET_SPEED:
                result->SetSpeed(data.ReadFloat());
                break;
            case SESSION_CMD_SET_LOOP_MODE:
                result->SetLoopMode(data.ReadInt32());
                break;
            case SESSION_CMD_TOGGLE_FAVORITE:
                result->SetMediaId(data.ReadString());
                break;
            default:
                break;
        }
    }
    return result;
}

bool AVControlCommand::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(cmd_)) {
        return false;
    }
    switch (cmd_) {
        case SESSION_CMD_SEEK:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int64_t>(param_)
                && parcel.WriteInt64(std::get<int64_t>(param_)), false, "write seek time failed");
            break;
        case SESSION_CMD_SET_SPEED:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<float>(param_)
                && parcel.WriteFloat(std::get<float>(param_)), false, "write speed failed");
            break;
        case SESSION_CMD_SET_LOOP_MODE:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<int32_t>(param_)
                && parcel.WriteInt32(std::get<int32_t>(param_)), false, "write loop mode failed");
            break;
        case SESSION_CMD_TOGGLE_FAVORITE:
            CHECK_AND_RETURN_RET_LOG(std::holds_alternative<std::string>(param_)
                && parcel.WriteString(std::get<std::string>(param_)), false, "write toggle favorite failed");
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

int32_t AVControlCommand::SetSpeed(float speed)
{
    if (speed < 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = speed;
    return AVSESSION_SUCCESS;
}

int32_t AVControlCommand::GetSpeed(float &speed) const
{
    if (!std::holds_alternative<float>(param_)) {
        return AVSESSION_ERROR;
    }
    speed = std::get<float>(param_);
    return AVSESSION_SUCCESS;
}

int32_t AVControlCommand::SetSeekTime(int64_t time)
{
    if (time < 0) {
        return ERR_INVALID_PARAM;
    }
    param_ = time;
    return AVSESSION_SUCCESS;
}

int32_t AVControlCommand::GetSeekTime(int64_t &time) const
{
    if (!std::holds_alternative<int64_t>(param_)) {
        return AVSESSION_ERROR;
    }
    time = std::get<int64_t>(param_);
    return AVSESSION_SUCCESS;
}

int32_t AVControlCommand::SetLoopMode(int32_t mode)
{
    if (mode < LOOP_MODE_SEQUENCE || mode > LOOP_MODE_SHUFFLE) {
        return ERR_INVALID_PARAM;
    }
    param_ = mode;
    return AVSESSION_SUCCESS;
}

int32_t AVControlCommand::GetLoopMode(int32_t &mode) const
{
    if (!std::holds_alternative<int32_t>(param_)) {
        return AVSESSION_ERROR;
    }
    mode = std::get<int32_t>(param_);
    return AVSESSION_SUCCESS;
}

int32_t AVControlCommand::SetMediaId(const std::string &mediaId)
{
    if (mediaId.empty()) {
        return ERR_INVALID_PARAM;
    }
    param_ = mediaId;
    return AVSESSION_SUCCESS;
}

int32_t AVControlCommand::GetMediaId(std::string &mediaId) const
{
    if (!std::holds_alternative<std::string>(param_)) {
        return AVSESSION_ERROR;
    }
    mediaId = std::get<std::string>(param_);
    return AVSESSION_SUCCESS;
}
} // OHOS::AVSession