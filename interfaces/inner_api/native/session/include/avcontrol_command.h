/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
        SESSION_CMD_PLAY = 0,
        SESSION_CMD_PAUSE = 1,
        SESSION_CMD_STOP = 2,
        SESSION_CMD_PLAY_NEXT = 3,
        SESSION_CMD_PLAY_PREVIOUS = 4,
        SESSION_CMD_FAST_FORWARD = 5,
        SESSION_CMD_REWIND = 6,
        SESSION_CMD_SEEK = 7,
        SESSION_CMD_SET_SPEED = 8,
        SESSION_CMD_SET_LOOP_MODE = 9,
        SESSION_CMD_TOGGLE_FAVORITE = 10,
        SESSION_CMD_PLAY_FROM_ASSETID = 11,
        SESSION_CMD_AVCALL_ANSWER = 12,
        SESSION_CMD_AVCALL_HANG_UP = 13,
        SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE = 14,
        SESSION_CMD_MEDIA_KEY_SUPPORT = 15,
        SESSION_CMD_SET_TARGET_LOOP_MODE = 16,
        SESSION_CMD_PLAY_WITH_ASSETID = 17,
        SESSION_CMD_MAX
    };

    AVControlCommand();
    ~AVControlCommand() override;

    static AVControlCommand* Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    bool IsValid() const;

    int32_t SetCommand(int32_t cmd);
    int32_t GetCommand() const;

    int32_t SetSpeed(double speed);
    int32_t GetSpeed(double& speed) const;

    int32_t SetForwardTime(int64_t forwardTime);
    int32_t GetForwardTime(int64_t& forwardTime) const;

    int32_t SetRewindTime(int64_t rewindTime);
    int32_t GetRewindTime(int64_t& rewindTime) const;

    int32_t SetSeekTime(int64_t time);
    int32_t GetSeekTime(int64_t& time) const;

    int32_t SetLoopMode(int32_t mode);
    int32_t GetLoopMode(int32_t& mode) const;

    int32_t SetTargetLoopMode(int32_t targetMode);
    int32_t GetTargetLoopMode(int32_t& targetMode) const;

    int32_t SetAssetId(const std::string& assetId);
    int32_t GetAssetId(std::string& assetId) const;

    int32_t SetPlayFromAssetId(int64_t playFromAssetId);
    int32_t GetPlayFromAssetId(int64_t& playFromAssetId) const;

    int32_t SetPlayWithAssetId(const std::string& playWithAssetId);
    int32_t GetPlayWithAssetId(std::string& playWithAssetId) const;

    int32_t SetPlayParam(const std::string& playParam);
    int32_t GetPlayParam(std::string& playParam) const;

    const static inline std::vector<int32_t> localCapability {
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
        SESSION_CMD_PLAY_FROM_ASSETID,
        SESSION_CMD_PLAY_WITH_ASSETID,
        SESSION_CMD_AVCALL_ANSWER,
        SESSION_CMD_AVCALL_HANG_UP,
        SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE,
        SESSION_CMD_MEDIA_KEY_SUPPORT,
        SESSION_CMD_SET_TARGET_LOOP_MODE,
    };

private:
    int32_t cmd_ = SESSION_CMD_INVALID;
    std::variant<int32_t, double, int64_t, bool, std::string> param_;
};
}
#endif // OHOS_AVCONTROL_COMMAND_H