/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVCAST_CONTROL_COMMAND_H
#define OHOS_AVCAST_CONTROL_COMMAND_H

#include <cinttypes>
#include <functional>
#include <string>
#include <variant>

#include "parcel.h"

namespace OHOS::AVSession {
class AVCastControlCommand : public Parcelable {
public:
    enum {
        CAST_CONTROL_CMD_INVALID = -1,
        CAST_CONTROL_CMD_PLAY = 0,
        CAST_CONTROL_CMD_PAUSE = 1,
        CAST_CONTROL_CMD_STOP = 2,
        CAST_CONTROL_CMD_PLAY_NEXT = 3,
        CAST_CONTROL_CMD_PLAY_PREVIOUS = 4,
        CAST_CONTROL_CMD_FAST_FORWARD = 5,
        CAST_CONTROL_CMD_REWIND = 6,
        CAST_CONTROL_CMD_SEEK = 7,
        CAST_CONTROL_CMD_SET_VOLUME = 8,
        CAST_CONTROL_CMD_SET_SPEED = 9,
        CAST_CONTROL_CMD_SET_LOOP_MODE = 10,
        CAST_CONTROL_CMD_TOGGLE_FAVORITE = 11,
        CAST_CONTROL_CMD_TOGGLE_MUTE = 12,
        CAST_CONTROL_CMD_MAX = 13,
    };

    AVCastControlCommand();
    ~AVCastControlCommand() override;

    static AVCastControlCommand* Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    bool IsValid() const;

    int32_t SetCommand(int32_t cmd);
    int32_t GetCommand() const;

    int32_t SetForwardTime(int32_t forwardTime);
    int32_t GetForwardTime(int32_t& forwardTime) const;

    int32_t SetRewindTime(int32_t rewindTime);
    int32_t GetRewindTime(int32_t& rewindTime) const;

    int32_t SetSeekTime(int32_t seekTime);
    int32_t GetSeekTime(int32_t& seekTime) const;

    int32_t SetVolume(int32_t volume);
    int32_t GetVolume(int32_t& volume) const;

    int32_t SetSpeed(int32_t speed);
    int32_t GetSpeed(int32_t& speed) const;

    int32_t SetLoopMode(int32_t loopMode);
    int32_t GetLoopMode(int32_t& loopMode) const;

    const static inline std::vector<int32_t> localCapability {
        CAST_CONTROL_CMD_PLAY,
        CAST_CONTROL_CMD_PAUSE,
        CAST_CONTROL_CMD_STOP,
        CAST_CONTROL_CMD_PLAY_NEXT,
        CAST_CONTROL_CMD_PLAY_PREVIOUS,
        CAST_CONTROL_CMD_FAST_FORWARD,
        CAST_CONTROL_CMD_REWIND,
        CAST_CONTROL_CMD_SEEK,
        CAST_CONTROL_CMD_SET_VOLUME,
        CAST_CONTROL_CMD_SET_SPEED,
        CAST_CONTROL_CMD_SET_LOOP_MODE,
        CAST_CONTROL_CMD_TOGGLE_FAVORITE,
        CAST_CONTROL_CMD_TOGGLE_MUTE,
    };

private:
    int32_t cmd_ = CAST_CONTROL_CMD_INVALID;
    std::variant<int32_t, double, int64_t, bool> param_;
};
}
#endif // OHOS_AVCAST_CONTROL_COMMAND_H
