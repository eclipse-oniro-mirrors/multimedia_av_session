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
        PLAYBACK_STATE_INITIAL,
        PLAYBACK_STATE_PREPARING,
        PLAYBACK_STATE_PLAYING,
        PLAYBACK_STATE_PAUSED,
        PLAYBACK_STATE_FAST_FORWARD,
        PLAYBACK_STATE_REWIND,
        PLAYBACK_STATE_STOP,
        PLAYBACK_STATE_MAX
    };

    AVPlaybackState();

    static AVPlaybackState* Unmarshalling(Parcel& parcel);
    bool Marshalling(Parcel& parcel) const override;

    void SetState(int32_t state);
    int32_t GetState() const;

    void SetSpeed(float speed);
    float GetSpeed() const;

    void SetElapsedTime(int64_t time);
    int64_t GetElapsedTime() const;

    void SetUpdateTime(int64_t time);
    int64_t GetUpdateTime() const;

    void SetBufferedTime(int64_t time);
    int64_t GetBufferedTime() const;

    void SetLoopMode(int32_t mode);
    int32_t GetLoopMode() const;

    void SetFavorite(bool isFavorite);
    bool GetFavorite() const;

private:
    int32_t state_ = PLAYBACK_STATE_INITIAL;
    float speed_ {};
    int64_t elapsedTime_ {};
    int64_t updateTime_ {};
    int64_t bufferedTime_ {};
    int32_t loopMode_ {};
    bool isFavorite_ {};
};
} // namespace OHOS::AVSession
#endif // OHOS_AVPLAYBACK_STATE_H