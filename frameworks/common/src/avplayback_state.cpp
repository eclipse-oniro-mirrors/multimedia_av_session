/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "avsession_log.h"

namespace OHOS::AVSession {
AVPlaybackState::AVPlaybackState()
{
}

bool AVPlaybackState::Marshalling(Parcel& parcel) const
{
    return parcel.WriteString(mask_.to_string()) &&
        parcel.WriteInt32(state_) &&
        parcel.WriteDouble(speed_) &&
        parcel.WriteInt64(position_.elapsedTime_) &&
        parcel.WriteInt64(position_.updateTime_) &&
        parcel.WriteInt64(bufferedTime_) &&
        parcel.WriteInt32(loopMode_) &&
        parcel.WriteBool(isFavorite_) &&
        parcel.WriteInt32(activeItemId_) &&
        parcel.WriteInt32(volume_) &&
        parcel.WriteInt32(maxVolume_) &&
        parcel.WriteBool(muted_) &&
        parcel.WriteInt32(duration_) &&
        parcel.WriteInt32(videoWidth_) &&
        parcel.WriteInt32(videoHeight_) &&
        parcel.WriteParcelable(extras_.get());
}

AVPlaybackState *AVPlaybackState::Unmarshalling(Parcel& parcel)
{
    std::string mask;
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(mask) && mask.length() == PLAYBACK_KEY_MAX, nullptr, "mask not valid");
    CHECK_AND_RETURN_RET_LOG(mask.find_first_not_of("01") == std::string::npos, nullptr, "mask string not 0 or 1");

    auto *result = new (std::nothrow) AVPlaybackState();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVPlaybackState failed");
    result->mask_ = PlaybackStateMaskType(mask);
    if (!parcel.ReadInt32(result->state_) ||
        !parcel.ReadDouble(result->speed_) ||
        !parcel.ReadInt64(result->position_.elapsedTime_) ||
        !parcel.ReadInt64(result->position_.updateTime_) ||
        !parcel.ReadInt64(result->bufferedTime_) ||
        !parcel.ReadInt32(result->loopMode_) ||
        !parcel.ReadBool(result->isFavorite_) ||
        !parcel.ReadInt32(result->activeItemId_) ||
        !parcel.ReadInt32(result->volume_) ||
        !parcel.ReadInt32(result->maxVolume_) ||
        !parcel.ReadBool(result->muted_) ||
        !parcel.ReadInt32(result->duration_) ||
        !parcel.ReadInt32(result->videoWidth_) ||
        !parcel.ReadInt32(result->videoHeight_)) {
        SLOGE("Read AVPlaybackState failed");
        delete result;
        result = nullptr;
        return nullptr;
    }
    result->extras_ = std::shared_ptr<AAFwk::WantParams>(parcel.ReadParcelable<AAFwk::WantParams>());
    if (result->extras_ == nullptr) {
        SLOGD("Read AVPlaybackState with no extras");
    }
    return result;
}

bool AVPlaybackState::IsValid() const
{
    return state_ >= PLAYBACK_STATE_INITIAL &&
        state_ < PLAYBACK_STATE_MAX &&
        speed_ > 0 &&
        position_.elapsedTime_ >= 0 &&
        position_.updateTime_ >= 0 &&
        bufferedTime_ >= 0 &&
        loopMode_ >= LOOP_MODE_SEQUENCE &&
        loopMode_ <= LOOP_MODE_CUSTOM &&
        volume_ >= 0 &&
        maxVolume_ >= 0;
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

void AVPlaybackState::SetPosition(const Position& position)
{
    mask_.set(PLAYBACK_KEY_POSITION);
    position_ = position;
}

void AVPlaybackState::SetBufferedTime(int64_t time)
{
    mask_.set(PLAYBACK_KEY_BUFFERED_TIME);
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

void AVPlaybackState::SetActiveItemId(int32_t activeItemId)
{
    mask_.set(PLAYBACK_KEY_ACTIVE_ITEM_ID);
    activeItemId_ = activeItemId;
}

void AVPlaybackState::SetVolume(int32_t volume)
{
    mask_.set(PLAYBACK_KEY_VOLUME);
    volume_ = volume;
}

void AVPlaybackState::SetMaxVolume(int32_t maxVolume)
{
    mask_.set(PLAYBACK_KEY_MAX_VOLUME);
    maxVolume_ = maxVolume;
}

void AVPlaybackState::SetMuted(bool muted)
{
    mask_.set(PLAYBACK_KEY_MUTED);
    muted_ = muted;
}

void AVPlaybackState::SetDuration(int32_t duration)
{
    mask_.set(PLAYBACK_KEY_DURATION);
    duration_ = duration;
}

void AVPlaybackState::SetVideoWidth(int32_t videoWidth)
{
    mask_.set(PLAYBACK_KEY_VIDEO_WIDTH);
    videoWidth_ = videoWidth;
}

void AVPlaybackState::SetVideoHeight(int32_t videoHeight)
{
    mask_.set(PLAYBACK_KEY_VIDEO_HEIGHT);
    videoHeight_ = videoHeight;
}

void AVPlaybackState::SetExtras(const std::shared_ptr<AAFwk::WantParams>& extras)
{
    mask_.set(PLAYBACK_KEY_EXTRAS);
    extras_ = extras;
}

int32_t AVPlaybackState::GetState() const
{
    return state_;
}

double AVPlaybackState::GetSpeed() const
{
    return speed_;
}

AVPlaybackState::Position AVPlaybackState::GetPosition() const
{
    return position_;
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

int32_t AVPlaybackState::GetActiveItemId() const
{
    return activeItemId_;
}

int32_t AVPlaybackState::GetVolume() const
{
    return volume_;
}

int32_t AVPlaybackState::GetMaxVolume() const
{
    return maxVolume_;
}

bool AVPlaybackState::GetMuted() const
{
    return muted_;
}

int32_t AVPlaybackState::GetDuration() const
{
    return duration_;
}

int32_t AVPlaybackState::GetVideoWidth() const
{
    return videoWidth_;
}

int32_t AVPlaybackState::GetVideoHeight() const
{
    return videoHeight_;
}

std::shared_ptr<AAFwk::WantParams> AVPlaybackState::GetExtras() const
{
    return extras_;
}

AVPlaybackState::PlaybackStateMaskType AVPlaybackState::GetMask() const
{
    return mask_;
}

bool AVPlaybackState::CopyToByMask(PlaybackStateMaskType& mask, AVPlaybackState& out) const
{
    bool result = false;
    auto intersection = mask_ & mask;
    for (int i = 0; i < PLAYBACK_KEY_MAX; i++) {
        if (intersection.test(i)) {
            cloneActions[i](*this, out);
            out.mask_.set(i);
            result = true;
        }
    }

    return result;
}

AVPlaybackState::PlaybackStateMaskType AVPlaybackState::GetChangedStateMask(
    const AVPlaybackState::PlaybackStateMaskType& filter, const AVPlaybackState& newState) const
{
    PlaybackStateMaskType result;
    for (int i = 0; i < PLAYBACK_KEY_MAX; i++) {
        if (filter.test(i) && checkActions[i](newState, *this)) {
            result.set(i);
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

bool AVPlaybackState::CheckStateChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.state_ != oldState.state_;
}

bool AVPlaybackState::CheckSpeedChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.speed_ != oldState.speed_;
}

bool AVPlaybackState::CheckPositionChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.position_.elapsedTime_ != oldState.position_.elapsedTime_ ||
        newState.position_.updateTime_ != oldState.position_.updateTime_;
}

bool AVPlaybackState::CheckBufferedTimeChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.bufferedTime_ != oldState.bufferedTime_;
}

bool AVPlaybackState::CheckLoopModeChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.loopMode_ != oldState.loopMode_;
}

bool AVPlaybackState::CheckIsFavoriteChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.isFavorite_ != oldState.isFavorite_;
}

bool AVPlaybackState::CheckActiveItemIdChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.activeItemId_ != oldState.activeItemId_;
}

bool AVPlaybackState::CheckVolumeChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.volume_ != oldState.volume_;
}

bool AVPlaybackState::CheckMaxVolumeChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.maxVolume_ != oldState.maxVolume_;
}

bool AVPlaybackState::CheckMutedChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.muted_ != oldState.muted_;
}

bool AVPlaybackState::CheckDurationChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.duration_ != oldState.duration_;
}

bool AVPlaybackState::CheckVideoWidthChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.videoWidth_ != oldState.videoWidth_;
}

bool AVPlaybackState::CheckVideoHeightChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    return newState.videoHeight_ != oldState.videoHeight_;
}

bool AVPlaybackState::CheckExtrasChange(const AVPlaybackState& newState, const AVPlaybackState& oldState)
{
    if (!newState.extras_ && !oldState.extras_) {
        return false;
    }
    if (!newState.extras_ || !oldState.extras_) {
        return true;
    }
    return !(*newState.extras_ == *oldState.extras_);
}

void AVPlaybackState::CloneState(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.state_ = from.state_;
}

void AVPlaybackState::CloneSpeed(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.speed_ = from.speed_;
}

void AVPlaybackState::ClonePosition(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.position_ = from.position_;
}

void AVPlaybackState::CloneBufferedTime(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.bufferedTime_ = from.bufferedTime_;
}

void AVPlaybackState::CloneLoopMode(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.loopMode_ = from.loopMode_;
}

void AVPlaybackState::CloneIsFavorite(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.isFavorite_ = from.isFavorite_;
}

void AVPlaybackState::CloneActiveItemId(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.activeItemId_ = from.activeItemId_;
}

void AVPlaybackState::CloneVolume(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.volume_ = from.volume_;
}

void AVPlaybackState::CloneMaxVolume(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.maxVolume_ = from.maxVolume_;
}

void AVPlaybackState::CloneMuted(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.muted_ = from.muted_;
}

void AVPlaybackState::CloneDuration(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.duration_ = from.duration_;
}

void AVPlaybackState::CloneVideoWidth(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.videoWidth_ = from.videoWidth_;
}

void AVPlaybackState::CloneVideoHeight(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.videoHeight_ = from.videoHeight_;
}

void AVPlaybackState::CloneExtras(const AVPlaybackState& from, AVPlaybackState& to)
{
    to.extras_ = from.extras_;
}
} // OHOS::AVSession
