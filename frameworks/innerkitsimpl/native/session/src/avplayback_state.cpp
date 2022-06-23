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
        parcel.WriteUint64(position_.elapsedTime_) &&
        parcel.WriteUint64(position_.updateTime_) &&
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
    result->position_.elapsedTime_ = parcel.ReadUint64();
    result->position_.updateTime_ = parcel.ReadUint64();
    result->bufferedTime_ = parcel.ReadUint64();
    result->loopMode_ = parcel.ReadInt32();
    result->isFavorite_ = parcel.ReadBool();
    return result;
}

void AVPlaybackState::SetState(int32_t state)
{
    mask_.set(PLAYBACK_KEY_STATE);
    state_ = state;
}

void AVPlaybackState::SetSpeed(double speed)
{
    mask_.set(PLAYBACK_KEY_SPEED);
    speed_ = speed;
}

void AVPlaybackState::SetPosition(const Position &position)
{
    mask_.set(PLAYBACK_KEY_POSITION);
    position_ = position;
}

void AVPlaybackState::SetBufferedTime(uint64_t time)
{
    mask_.set(PLAYBACK_KEY_BUFFERD_TIME);
    bufferedTime_ = time;
}

void AVPlaybackState::SetLoopMode(int32_t mode)
{
    mask_.set(PLAYBACK_KEY_LOOP_MODE);
    loopMode_ = mode;
}

void AVPlaybackState::SetFavorite(bool isFavorite)
{
    mask_.set(PLAYBACK_KEY_IS_FAVORITE);
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

AVPlaybackState::Position AVPlaybackState::GetPosistion() const
{
    return position_;
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

AVPlaybackState::PlaybackStateMaskType AVPlaybackState::GetMask() const
{
    return mask_;
}

bool AVPlaybackState::CopyToByMask(PlaybackStateMaskType& mask, AVPlaybackState& out) const
{
    bool result = false;
    auto intersection = out.mask_ & mask;
    for (int i = 0; i < PLAYBACK_KEY_MAX; i++) {
        if (intersection.test(i)) {
            cloneActions[i](*this, out);
            result = true;
        }
    }

    return result;
}

bool AVPlaybackState::CopyFrom(const AVPlaybackState& in)
{
    bool result = false;
    for (int i = 0; i < PLAYBACK_KEY_MAX; i++) {
        if (in.mask_.test(i)) {
            cloneActions[i](in, *this);
            mask_.set(i);
            result = true;
        }
    }

    return result;
}

void AVPlaybackState::CloneState(const AVPlaybackState &from, AVPlaybackState &to)
{
    to.state_ = from.state_;
}

void AVPlaybackState::CloneSpeed(const AVPlaybackState &from, AVPlaybackState &to)
{
    to.speed_ = from.speed_;
}

void AVPlaybackState::ClonePosition(const AVPlaybackState &from, AVPlaybackState &to)
{
    to.position_ = from.position_;
}

void AVPlaybackState::CloneBufferedTime(const AVPlaybackState &from, AVPlaybackState &to)
{
    to.bufferedTime_ = from.bufferedTime_;
}

void AVPlaybackState::CloneLoopMode(const AVPlaybackState &from, AVPlaybackState &to)
{
    to.loopMode_ = from.loopMode_;
}

void AVPlaybackState::CloneIsFavorite(const AVPlaybackState &from, AVPlaybackState &to)
{
    to.isFavorite_ = from.isFavorite_;
}
} // OHOS::AVSession