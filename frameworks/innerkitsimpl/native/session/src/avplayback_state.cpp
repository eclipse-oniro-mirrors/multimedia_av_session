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

bool AVPlaybackState::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(state_) &&
        parcel.WriteDouble(speed_) &&
        parcel.WriteUint64(elapsedTime_) &&
        parcel.WriteUint64(updateTime_) &&
        parcel.WriteUint64(bufferedTime_) &&
        parcel.WriteInt32(loopMode_) &&
        parcel.WriteBool(isFavorite_);
}

AVPlaybackState *AVPlaybackState::Unmarshalling(Parcel &parcel)
{
    auto *result = new (std::nothrow) AVPlaybackState();
    if (result == nullptr) {
        return nullptr;
    }
    result->state_ = parcel.ReadInt32();
    result->speed_ = parcel.ReadDouble();
    result->elapsedTime_ = parcel.ReadUint64();
    result->updateTime_ = parcel.ReadUint64();
    result->bufferedTime_ = parcel.ReadUint64();
    result->loopMode_ = parcel.ReadInt32();
    result->isFavorite_ = parcel.ReadBool();
    return result;
}

void AVPlaybackState::SetState(int32_t state)
{
    state_ = state;
}

void AVPlaybackState::SetSpeed(double speed)
{
    speed_ = speed;
}

void AVPlaybackState::SetElapsedTime(uint64_t time)
{
    elapsedTime_ = time;
}

void AVPlaybackState::SetUpdateTime(uint64_t time)
{
    updateTime_ = time;
}

void AVPlaybackState::SetBufferedTime(uint64_t time)
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

double AVPlaybackState::GetSpeed() const
{
    return speed_;
}

uint64_t AVPlaybackState::GetElapsedTime() const
{
    return elapsedTime_;
}

uint64_t AVPlaybackState::GetUpdateTime() const
{
    return updateTime_;
}

uint64_t AVPlaybackState::GetBufferedTime() const
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