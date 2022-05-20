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

#ifndef OHOS_AVPLAYBACK_STATE_H
#define OHOS_AVPLAYBACK_STATE_H

#include <parcel.h>

namespace OHOS::AVSession {
class AVPlaybackState : public Parcelable {
public:
    enum {
        PLAYBACK_STATE_INVALID = -1,
        PLAYBACK_STATE_PREPARING,
        PLAYBACK_STATE_PLAYING,
        PLAYBACK_STATE_PAUSED,
        PLAYBACK_STATE_STOPPED,
        PLAYBACK_STATE_MAX
    };
    AVPlaybackState() : Parcelable(true) {}
    AVPlaybackState(int32_t state, float speed, int64_t etime, int64_t btime, int32_t loopMode, bool
                    isFavorite);

    static AVPlaybackState* Unmarshalling(Parcel& parcel);
    bool Marshalling(Parcel& parcel);

    void SetState(int32_t state);
    int32_t GetState();

    void SetSpeed(float speed);
    float GetSpeed();

    void SetElapsedTime(int64_t time);
    int64_t GetElapsedTime();

    void SetBufferredTime(int64_t time);
    int64_t GetBufferredTime();

    void SetLoopMode(int32_t mode);
    int32_t GetLoopMode();

    void SetFavorite(bool isFavorite);
    bool GetFavorite();

private:
    int32_t state_;
    float speed_;
    int64_t elapsedTime_;
    int64_t bufferredTime_;
    int32_t loopMode_;
    bool isFavorite_;
};
} // namespace OHOS::AVSession
#endif //OHOS_AVPLAYBACK_STATE_H
