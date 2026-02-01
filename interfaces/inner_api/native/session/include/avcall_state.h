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

#ifndef OHOS_AVCALL_STATE_H
#define OHOS_AVCALL_STATE_H

#include <bitset>
#include <parcel.h>

#ifndef CLIENT_LITE
#include "want_agent.h"
#endif

namespace OHOS::AVSession {
class AVCallState : public Parcelable {
public:
    enum {
        AVCALL_STATE_IDLE = 0,
        AVCALL_STATE_INCOMING = 1,
        AVCALL_STATE_ACTIVE = 2,
        AVCALL_STATE_DIALING = 3,
        AVCALL_STATE_WAITING = 4,
        AVCALL_STATE_HOLDING = 5,
        AVCALL_STATE_DISCONNECTING = 6,
        AVCALL_STATE_MAX = 7,
    };

    enum {
        AVCALL_STATE_KEY_STATE = 0,
        AVCALL_STATE_KEY_IS_MUTED = 1,
        AVCALL_STATE_KEY_MAX = 2,
    };

    using AVCallStateMaskType = std::bitset<AVCALL_STATE_KEY_MAX>;

    AVCallState();
    ~AVCallState() override = default;

    static AVCallState* Unmarshalling(Parcel& parcel);
    bool Marshalling(Parcel& parcel) const override;

    bool IsValid() const;

    void SetAVCallState(int32_t avCallState);
    int32_t GetAVCallState() const;

    void SetAVCallMuted(bool isAVCallMuted);
    bool IsAVCallMuted() const;

    AVCallStateMaskType GetMask() const;

    bool CopyToByMask(AVCallStateMaskType& mask, AVCallState& out) const;
    bool CopyFrom(const AVCallState& in);

    const static inline std::vector<int32_t> localCapability {
        AVCALL_STATE_KEY_STATE,
        AVCALL_STATE_KEY_IS_MUTED,
    };

private:
    AVCallStateMaskType mask_;

    int32_t avCallState_ = AVCALL_STATE_IDLE;
    bool isAVCallMuted_ = false;

    static void CloneAVCallState(const AVCallState& from, AVCallState& to);
    static void CloneAVCallIsMuted(const AVCallState& from, AVCallState& to);

    using CloneActionType = void(*)(const AVCallState& from, AVCallState& to);
    static inline CloneActionType cloneActions[AVCALL_STATE_KEY_MAX] = {
        &AVCallState::CloneAVCallState,
        &AVCallState::CloneAVCallIsMuted,
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCALL_STATE_H
