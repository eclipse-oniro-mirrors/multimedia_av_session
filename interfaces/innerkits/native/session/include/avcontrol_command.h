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

#ifndef OHOS_AVCONTROL_COMMAND_H
#define OHOS_AVCONTROL_COMMAND_H

#include <cinttypes>
#include <functional>
#include <string>
#include <variant>

#include "parcel.h"

namespace OHOS::AVSession {
class AVControlCommand : public Parcelable {
public:
    enum {
        SESSION_CMD_INVALID = -1,
        SESSION_CMD_PLAY,
        SESSION_CMD_PAUSE,
        SESSION_CMD_STOP,
        SESSION_CMD_PLAY_NEXT,
        SESSION_CMD_PLAY_PREVIOUS,
        SESSION_CMD_FAST_FORWARD,
        SESSION_CMD_REWIND,
        SESSION_CMD_SEEK,
        SESSION_CMD_SET_SPEED,
        SESSION_CMD_SET_LOOP_MODE,
        SESSION_CMD_TOGGLE_FAVORITE,
        SESSION_CMD_MAX,
    };

    enum {
        LOOP_MODE_SEQUENCE,
        LOOP_MODE_SINGLE,
        LOOP_MODE_LIST,
        LOOP_MODE_SHUFFLE,
    };

    AVControlCommand();
    ~AVControlCommand() override;

    static AVControlCommand *Unmarshalling(Parcel &data);
    bool Marshalling(Parcel &parcel) const override;

    bool IsValid() const;

    int32_t SetCommand(int32_t cmd);
    int32_t GetCommand() const;

    int32_t SetSpeed(float speed);
    int32_t GetSpeed(float &speed) const;

    int32_t SetSeekTime(int64_t time);
    int32_t GetSeekTime(int64_t &time) const;

    int32_t SetLoopMode(int32_t mode);
    int32_t GetLoopMode(int32_t &mode) const;

    int32_t SetMediaId(const std::string &mediaId);
    int32_t GetMediaId(std::string &mediaId) const;

private:
    int32_t cmd_;
    std::variant<int32_t, float, int64_t, std::string> param_;
};
}
#endif // OHOS_AVCONTROL_COMMAND_H