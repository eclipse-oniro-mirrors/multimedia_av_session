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

#ifndef TAIHE_AVSESSION_ENUM_H
#define TAIHE_AVSESSION_ENUM_H

#include "avplayback_state.h"
#include "avsession_info.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheAVSessionEnum {
public:
    enum TaiheAVSkipIntervals : int32_t {
        SECONDS_10 = 10,
        SECONDS_15 = 15,
        SECONDS_30 = 30,
    };

    static bool ToAniEnumHDRFormat(OHOS::AVSession::HDRFormat format, ani_enum_item &aniEnumItem);

    static LoopMode ToTaiheLoopMode(int32_t mode);
    static AVCastCategory ToTaiheAVCastCategory(int32_t category);
    static DeviceType ToTaiheDeviceType(int32_t type);
    static SkipIntervals ToTaiheSkipIntervals(int32_t intervals);
    static PlaybackState ToTaihePlaybackState(int32_t state);
    static CastDisplayState ToTaiheCastDisplayState(OHOS::AVSession::CastDisplayState state);
    static CallState ToTaiheCallState(int32_t state);
    static ConnectionState ToTaiheConnectionState(int32_t state);
    static DeviceLogEventCode ToTaiheDeviceLogEventCode(int32_t eventId);

    static OHOS::AVSession::DistributedSessionType ToDistributedSessionType(DistributedSessionType type);
};
} // namespace ANI::AVSession
#endif // TAIHE_AVSESSION_ENUM_H