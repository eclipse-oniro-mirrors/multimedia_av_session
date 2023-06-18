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

#ifndef OHOS_AVROUTER_IMPL_H
#define OHOS_AVROUTER_IMPL_H

#include "av_router.h"
#include "avcast_provider_manager.h"

namespace OHOS::AVSession {
class AVRouterImpl : public AVRouter {
public:
    AVRouterImpl();

    void Init(IAVSessionServiceListener *servicePtr) override;

    int32_t StartCastDiscovery(int32_t castDeviceCapability) override;

    int32_t StopCastDiscovery() override;

    int32_t OnDeviceAvailable(OutputDeviceInfo& castOutputDeviceInfo) override;

    int32_t OnCastServerDied(int32_t providerId) override;

    std::shared_ptr<IAVCastControllerProxy> GetRemoteController(const int64_t castHandle) override;

    int64_t StartCast(const OutputDeviceInfo& outputDeviceInfo) override;

    int32_t AddDevice(const int32_t castId, const OutputDeviceInfo& outputDeviceInfo) override;

    int32_t StopCast(const int64_t castHandle) override;

    int32_t RegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVCastSessionStateListener> callback) override;

    int32_t UnRegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVCastSessionStateListener> callback) override;
protected:

private:
    std::recursive_mutex servicePtrLock_;
    IAVSessionServiceListener *servicePtr_;
    std::recursive_mutex providerManagerLock_;
    std::map<int32_t, std::shared_ptr<AVCastProviderManager>> providerManagerMap_;
    int32_t providerNumber_ = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVROUTER_IMPL_H
