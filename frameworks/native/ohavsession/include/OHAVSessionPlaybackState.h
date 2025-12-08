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

#ifndef OHOS_OHAVSESSIONPLAYBACKSTATE_H
#define OHOS_OHAVSESSIONPLAYBACKSTATE_H

#include "native_avcastcontroller.h"
#include "native_avsession_base.h"
#include "avplayback_state.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
class OHAVSessionPlaybackState {
public:
    enum {
        PLAYBACK_STATE_INITIAL = 0,
        PLAYBACK_STATE_PREPARE = 1,
        PLAYBACK_STATE_PLAY = 2,
        PLAYBACK_STATE_PAUSE = 3,
        PLAYBACK_STATE_FAST_FORWARD = 4,
        PLAYBACK_STATE_REWIND = 5,
        PLAYBACK_STATE_STOP = 6,
        PLAYBACK_STATE_COMPLETED = 7,
        PLAYBACK_STATE_RELEASED = 8,
        PLAYBACK_STATE_ERROR = 9,
        PLAYBACK_STATE_IDLE = 10,
        PLAYBACK_STATE_BUFFERING = 11,
        PLAYBACK_STATE_MAX = 12,
    };
    
    struct Position {
        int64_t elapsedTime_ {};
        int64_t updateTime_ {};
    };

    OHAVSessionPlaybackState();
    ~OHAVSessionPlaybackState();

    void SetState(int32_t state);
    int32_t GetState() const;

    void SetPosition(const OHAVSessionPlaybackState::Position& position);
    OHAVSessionPlaybackState::Position GetPosition() const;

    void SetSpeed(double speed);
    double GetSpeed() const;

    void SetVolume(int32_t volume);
    int32_t GetVolume() const;
private:
    int32_t state_ = PLAYBACK_STATE_INITIAL;
    OHAVSessionPlaybackState::Position position_;
    double speed_ = 1.0;
    int32_t volume_ = 0;
};
}

#endif // OHOS_OHAVSESSIONPLAYBACKSTATE_H