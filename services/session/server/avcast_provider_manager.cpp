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

namespace OHOS::AVSession {
AVCastProviderManager::AVCastProviderManager()
{
    SLOGD("AVCastProviderManager construct");
}

// void AVCastProviderManager::Init(int32_t providerId, std::shared_ptr<AVCastProvider> provider)
// {
//     providerId_ = providerId;
//     provider_ = provider;
// }

void AVCastProviderManager::OnDeviceAvailable(std::vector<DeviceInfo> deviceInfos)
{
    SLOGI("On device available");
    for (int i = 0; i < deviceInfos.size(); i++) {
        deviceInfos[i].providerId_ = provider_.id;
    }
    OutputDeviceInfo outputDeviceInfo;
    outputDeviceInfo.deviceInfos_ = deviceInfos;
    AVRouter::GetInstance().OnDeviceAvailable(outputDeviceInfo);
}

void AVCastProviderManager::OnCastServerDied()
{
    SLOGI("On cast server died");
    // AVRouter::GetInstance().OnCastServerDied(provider_.id);
}

} // namespace OHOS::AVSession
