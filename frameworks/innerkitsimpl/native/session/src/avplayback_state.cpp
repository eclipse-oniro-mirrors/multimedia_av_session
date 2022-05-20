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
AVPlaybackState::AVPlaybackState() : Parcelable(true)
{}
AVPlaybackState::AVPlaybackState(int32_t state, float speed, int64_t etime, int64_t btime, int32_t loopMode, bool
                                 isFavorite)
               : state_(state),
                 speed_(speed),
                 etime_(etime),
                 btime_(btime),
                 loopMode_(loopMode),
                 isFavorite_(isFavorite)
{}

bool AVPlaybackState::Marshalling(Parcel &parcel)
{
    return false;
}

AVPlaybackState *AVPlaybackState::Unmarshalling(Parcel &parcel)
{
    return nullptr;
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

void AVPlaybackState::SetBufferredTime(int64_t time)
{
    bufferredTime_ = time;
}

void AVPlaybackState::SetLoopMode(int32_t mode)
{
    loopMode_ = mode;
}

void AVPlaybackState::SetFavorite(bool isFavorite)
{
    isFavorite_ = isFavorite;
}

int32_t AVPlaybackState::GetState()
{
    return state_;
}

float AVPlaybackState::GetSpeed()
{
    return speed_;
}

int64_t AVPlaybackState::GetElapsedTime()
{
    return elapsedTime_;
}

int64_t AVPlaybackState::GetBufferredTime()
{
    return bufferredTime_;
}

int32_t AVPlaybackState::GetLoopMode()
{
    return loopMode_;
}

bool AVPlaybackState::GetFavorite()
{
    return isFavorite_;
}
} // OHOS::AVSession
