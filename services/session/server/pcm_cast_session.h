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

#ifndef OHOS_PCM_CAST_SESSION_H
#define OHOS_PCM_CAST_SESSION_H

#include "avsession_info.h"

namespace OHOS::AVSession {
class PcmCastSession : public IAVRouterListener, public std::enable_shared_from_this<PcmCastSession> {
public:
    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove) override;

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg) override;

    int32_t StartCast(const OutputDeviceInfo& outputDeviceInfo,
        std::pair<std::string, std::string>& serviceNameStatePair);

    void StopCast();

private:
    int64_t castHandle_ = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_PCM_CAST_SESSION_H