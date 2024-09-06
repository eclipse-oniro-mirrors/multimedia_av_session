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

#include "avcast_provider_manager.h"
#include "av_router.h"
#include "avsession_log.h"
namespace OHOS::AVSession {
AVCastProviderManager::AVCastProviderManager()
{
    SLOGD("AVCastProviderManager construct");
}

// LCOV_EXCL_START
void AVCastProviderManager::Init(int32_t providerId, std::shared_ptr<AVCastProvider> provider)
{
    providerId_ = providerId;
    provider_ = provider;
}

void AVCastProviderManager::OnDeviceAvailable(std::vector<DeviceInfo> deviceInfos)
{
    SLOGI("On device available");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    for (size_t i = 0; i < deviceInfos.size(); i++) {
        deviceInfos[i].providerId_ = providerId_;
    }
    OutputDeviceInfo outputDeviceInfo;
    outputDeviceInfo.deviceInfos_ = deviceInfos;
    AVRouter::GetInstance().OnDeviceAvailable(outputDeviceInfo);
#endif
}
// LCOV_EXCL_STOP

void AVCastProviderManager::OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param)
{
    SLOGI("On device log event");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVRouter::GetInstance().OnDeviceLogEvent(eventId, param);
#endif
}

void AVCastProviderManager::OnSessionNeedDestroy()
{
    SLOGI("On cast session need destroy");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVRouter::GetInstance().ReleaseCurrentCastSession();
#endif
}

void AVCastProviderManager::OnSessionCreated(const int32_t castId)
{
    SLOGI("On cast session created");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVRouter::GetInstance().OnCastSessionCreated(castId);
#endif
}

// LCOV_EXCL_START
void AVCastProviderManager::OnDeviceOffline(const std::string& deviceId)
{
    SLOGI("On device offline");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVRouter::GetInstance().OnDeviceOffline(deviceId);
#endif
}

void AVCastProviderManager::OnCastServerDied()
{
    SLOGI("On cast server died");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVRouter::GetInstance().OnCastServerDied(providerId_);
#endif
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
