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

#include "OHAVSessionPlaybackState.h"

namespace OHOS::AVSession {
OHAVSessionPlaybackState::OHAVSessionPlaybackState()
{
}

OHAVSessionPlaybackState::~OHAVSessionPlaybackState()
{
}

void OHAVSessionPlaybackState::SetState(int32_t state)
{
    state_ = state;
}

int32_t OHAVSessionPlaybackState::GetState() const
{
    return state_;
}

void OHAVSessionPlaybackState::SetPosition(const OHAVSessionPlaybackState::Position& position)
{
    position_.elapsedTime_ = position.elapsedTime_;
    position_.updateTime_ = position.updateTime_;
}

OHAVSessionPlaybackState::Position OHAVSessionPlaybackState::GetPosition() const
{
    return position_;
}

void OHAVSessionPlaybackState::SetSpeed(double speed)
{
    speed_ = speed;
}

double OHAVSessionPlaybackState::GetSpeed() const
{
    return speed_;
}

void OHAVSessionPlaybackState::SetVolume(int32_t volume)
{
    volume_ = volume;
}

int32_t OHAVSessionPlaybackState::GetVolume() const
{
    return volume_;
}
}

AVSession_ErrCode OH_AVSession_GetPlaybackState(OH_AVSession_AVPlaybackState* playbState,
    AVSession_PlaybackState* state)
{
    CHECK_AND_RETURN_RET_LOG(playbState != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "playbState is null");
    CHECK_AND_RETURN_RET_LOG(state != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "state is null");
    OHOS::AVSession::OHAVSessionPlaybackState *oh_avsessionplaybackstate =
        (OHOS::AVSession::OHAVSessionPlaybackState *)playbState;
    *state = static_cast<AVSession_PlaybackState>(oh_avsessionplaybackstate->GetState());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_GetPlaybackPosition(OH_AVSession_AVPlaybackState* playbState,
    AVSession_PlaybackPosition* position)
{
    CHECK_AND_RETURN_RET_LOG(playbState != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "playbState is null");
    CHECK_AND_RETURN_RET_LOG(position != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "position is null");
    OHOS::AVSession::OHAVSessionPlaybackState *oh_avsessionplaybackstate =
        (OHOS::AVSession::OHAVSessionPlaybackState *)playbState;
    OHOS::AVSession::OHAVSessionPlaybackState::Position avPosition = oh_avsessionplaybackstate->GetPosition();
    position->elapsedTime = avPosition.elapsedTime_;
    position->updateTime = avPosition.updateTime_;
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_GetPlaybackSpeed(OH_AVSession_AVPlaybackState* playbState, int32_t* speed)
{
    CHECK_AND_RETURN_RET_LOG(playbState != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "playbState is null");
    CHECK_AND_RETURN_RET_LOG(speed != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "position is null");
    OHOS::AVSession::OHAVSessionPlaybackState *oh_avsessionplaybackstate =
        (OHOS::AVSession::OHAVSessionPlaybackState *)playbState;
    *speed = static_cast<int32_t>(oh_avsessionplaybackstate->GetSpeed());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_GetPlaybackVolume(OH_AVSession_AVPlaybackState* playbState, int32_t* volume)
{
    CHECK_AND_RETURN_RET_LOG(playbState != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "playbState is null");
    CHECK_AND_RETURN_RET_LOG(volume != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "volume is null");
    OHOS::AVSession::OHAVSessionPlaybackState *oh_avsessionplaybackstate =
        (OHOS::AVSession::OHAVSessionPlaybackState *)playbState;
    *volume = oh_avsessionplaybackstate->GetVolume();
    return AV_SESSION_ERR_SUCCESS;
}