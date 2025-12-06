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

#include "pcm_cast_session.h"

#include "avsession_log.h"
#include "avsession_utils.h"
#include "av_router.h"
#include "cast_engine_common.h"

namespace OHOS::AVSession {

void PcmCastSession::OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove)
{
    SLOGI("PcmCastSession OnCastStateChange state %{public}d id %{public}s", castState,
        AVSessionUtils::GetAnonymousDeviceId(deviceInfo.deviceId_).c_str());
    if (castState == static_cast<int32_t>(CastEngine::DeviceState::DISCONNECTED)) {
        AVRouter::GetInstance().UnRegisterCallback(castHandle_, shared_from_this(), "pcmCastSession");
        AVRouter::GetInstance().StopCastSession(castHandle_);
    }
}

void PcmCastSession::OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
{
    SLOGI("PcmCastSession OnCastEventRecv errorCode %{public}d errorMsg %{public}s", errorCode, errorMsg.c_str());
}

int32_t PcmCastSession::StartCast(const OutputDeviceInfo& outputDeviceInfo,
    std::pair<std::string, std::string>& serviceNameStatePair)
{
    castHandle_ = AVRouter::GetInstance().StartCast(outputDeviceInfo, serviceNameStatePair, "pcmCastSession");
    AVRouter::GetInstance().RegisterCallback(castHandle_, shared_from_this(),
        "pcmCastSession", outputDeviceInfo.deviceInfos_[0]);
    int32_t castId = static_cast<int32_t>(castHandle_);
    int32_t ret = AVRouter::GetInstance().AddDevice(castId, outputDeviceInfo, 0);
    SLOGI("PcmCastSession StartCast ret %{public}d", ret);
    return ret;
}

void PcmCastSession::StopCast()
{
    SLOGI("PcmCastSession StopCast");
    AVRouter::GetInstance().UnRegisterCallback(castHandle_, shared_from_this(), "pcmCastSession");
    AVRouter::GetInstance().StopCastSession(castHandle_);
}
} // namespace OHOS::AVSession