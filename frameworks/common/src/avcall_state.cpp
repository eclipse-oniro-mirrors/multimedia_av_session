/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "avcall_state.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVCallState::AVCallState()
{
}

bool AVCallState::Marshalling(Parcel& parcel) const
{
    return parcel.WriteString(mask_.to_string()) &&
        parcel.WriteInt32(avCallState_);
}

AVCallState *AVCallState::Unmarshalling(Parcel& parcel)
{
    std::string mask;
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(mask) && mask.length() == AVCALL_KEY_MAX, nullptr, "mask not valid");
    CHECK_AND_RETURN_RET_LOG(mask.find_first_not_of("01") == std::string::npos, nullptr, "mask string not 0 or 1");

    auto *result = new (std::nothrow) AVCallState();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVCallState failed");
    result->mask_ = AVCallStateMaskType(mask);
    if (!parcel.ReadInt32(result->avCallState_)) {
        SLOGE("Read AVCallState failed");
        delete result;
        return nullptr;
    }
    return result;
}

bool AVCallState::IsValid() const
{
    return avCallState_ >= AVCALL_STATE_IDLE &&
        avCallState_ < AVCALL_STATE_MAX;
}

void AVCallState::SetAVCallState(int32_t avCallState)
{
    mask_.set(AVCALL_KEY_STATE);
    avCallState_ = avCallState;
}

int32_t AVCallState::GetAVCallState() const
{
    return avCallState_;
}

void AVCallState::SetAVCallMuted(bool isAVCallMuted)
{
    mask_.set(AVCALL_KEY_IS_MUTED);
    isAVCallMuted_ = isAVCallMuted;
}

bool AVCallState::IsAVCallMuted() const
{
    return isAVCallMuted_;
}

AVCallState::AVCallStateMaskType AVCallState::GetMask() const
{
    return mask_;
}

bool AVCallState::CopyToByMask(AVCallStateMaskType& mask, AVCallState& out) const
{
    bool result = false;
    auto intersection = mask_ & mask;
    for (int i = 0; i < AVCALL_STATE_MAX; i++) {
        if (intersection.test(i)) {
            cloneActions[i](*this, out);
            out.mask_.set(i);
            result = true;
        }
    }
    return result;
}

bool AVCallState::CopyFrom(const AVCallState& in)
{
    bool result = false;
    for (int i = 0; i < AVCALL_KEY_MAX; i++) {
        if (in.mask_.test(i)) {
            cloneActions[i](in, *this);
            mask_.set(i);
            result = true;
        }
    }
    return result;
}

void AVCallState::CloneAVCallState(const AVCallState& from, AVCallState& to)
{
    to.avCallState_ = from.avCallState_;
}

void AVCallState::CloneAVCallIsMuted(const AVCallState& from, AVCallState& to)
{
    to.isAVCallMuted_ = from.isAVCallMuted_;
}
} // namespace OHOS::AVSession
