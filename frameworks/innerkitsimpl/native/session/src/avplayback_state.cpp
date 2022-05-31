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

#include "avplayback_state.h"

namespace OHOS::AVSession {
AVPlaybackState::AVPlaybackState()
{
}

AVPlaybackState::AVPlaybackState(int32_t state, float speed, int64_t etime, int64_t btime, int32_t loopMode,
                                 bool isFavorite)
    : state_(state), speed_(speed), elapsedTime_(etime), bufferedTime_(btime), loopMode_(loopMode),
      isFavorite_(isFavorite)
{
}

bool AVPlaybackState::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(state_) &&
    parcel.WriteFloat(speed_) &&
    parcel.WriteInt64(elapsedTime_) &&
    parcel.WriteInt64(bufferedTime_) &&
    parcel.WriteInt32(loopMode_) &&
    parcel.WriteBool(isFavorite_);
}

AVPlaybackState *AVPlaybackState::Unmarshalling(Parcel &parcel)
{
    AVPlaybackState *avplaybackState = new (std::nothrow) AVPlaybackState();
    if (avplaybackState == nullptr) {
        return nullptr;
    }
    avplaybackState->state_ = parcel.ReadInt32();
    avplaybackState->speed_ = parcel.ReadFloat();
    avplaybackState->elapsedTime_ = parcel.ReadInt64();
    avplaybackState->bufferedTime_ = parcel.ReadInt64();
    avplaybackState->loopMode_ = parcel.ReadInt32();
    avplaybackState->isFavorite_ = parcel.ReadBool();
    return avplaybackState;
}

void AVPlaybackState::SetState(int32_t state)
{
    state_ = state;
}

void AVPlaybackState::SetSpeed(float speed)
{
    speed_ = speed;
}

void AVPlaybackState::SetElapsedTime(int64_t time)
{
    elapsedTime_ = time;
}

void AVPlaybackState::SetBufferedTime(int64_t time)
{
    bufferedTime_ = time;
}

void AVPlaybackState::SetLoopMode(int32_t mode)
{
    loopMode_ = mode;
}

void AVPlaybackState::SetFavorite(bool isFavorite)
{
    isFavorite_ = isFavorite;
}

int32_t AVPlaybackState::GetState() const
{
    return state_;
}

float AVPlaybackState::GetSpeed() const
{
    return speed_;
}

int64_t AVPlaybackState::GetElapsedTime() const
{
    return elapsedTime_;
}

int64_t AVPlaybackState::GetBufferedTime() const
{
    return bufferedTime_;
}

int32_t AVPlaybackState::GetLoopMode() const
{
    return loopMode_;
}

bool AVPlaybackState::GetFavorite() const
{
    return isFavorite_;
}
} // OHOS::AVSession