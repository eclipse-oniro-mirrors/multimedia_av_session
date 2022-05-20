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
AVControlCommand::AVControlCommand() : Parcelable(true)
{
}

AVControlCommand::~AVControlCommand()
{
}

AVControlCommand *AVControlCommand::Unmarshalling(MessageParcel &data)
{
    auto objptr = new (std::nothrow) AVControlCommand();
    if (objptr != nullptr) {
        int32_t cmd = data.ReadInt32();
        objptr->SetCommand(cmd);
        switch (cmd) {
            case SESSION_CMD_SEEK:
                objptr->SetSeekTime(data.ReadInt64());
                break;
            case SESSION_CMD_SET_SPEED:
                objptr->SetSpeed(data.ReadFloat());
                break;
            case SESSION_CMD_SET_LOOP_MODE:
                objptr->SetLoopMode(data.ReadInt32());
                break;
            case SESSION_CMD_TOGGLE_FAVORITE:
                objptr->SetMediaId(data.ReadString());
                break;
            default:
                break;
        }
    }
    return objptr;
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

int32_t AVControlCommand::SetCommand(int32_t cmd)
{
    if (cmd < SESSION_CMD_PLAY || cmd >= SESSION_CMD_MAX) {
        return ERR_INVALID_PARAM;
    }
    cmd_ = cmd;
    return AVSESSION_SUCCESS;
}

void AVControlCommand::SetSpeed(float speed)
{
    param_ = speed;
}

void AVControlCommand::SetSeekTime(int64_t time)
{
    param_ = time;
}

void AVControlCommand::SetLoopMode(int32_t mode)
{
    param_ = mode;
}

void AVControlCommand::SetMediaId(const std::string &mediaId)
{
    param_ = mediaId;
}
} // OHOS::AVSession