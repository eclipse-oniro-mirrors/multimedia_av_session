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

#include "avrouter_impl.h"
#include "ipc_skeleton.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "permission_checker.h"

namespace OHOS::AVSession {
AVRouterImpl::AVRouterImpl()
{
    SLOGD("AVRouter construct");
}

void AVRouterImpl::Init(AVSessionService *servicePtr)
{
    servicePtr_ = servicePtr;
    // TODO: 这里new出来一个provider
}

int32_t AVRouterImpl::StartCastDiscovery(int32_t castDeviceCapability)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("StartCastDiscovery: CheckSystemPermission failed");
        return ERR_NO_PERMISSION;
    }
    std::lock_guard lockGuard(providerMapLock_);
    // for (const auto& [providerId, provider] : providerMap_) {
    //     provider->StartCastDiscovery(castDeviceCapability);
    // }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::OnDeviceFound(CastOutputDeviceInfo& castOutputDeviceInfo)
{
    std::lock_guard lockGuard(servicePtrLock_);
    if (servicePtr_ == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }
    servicePtr_->NotifyDeviceFound(castOutputDeviceInfo);
    return AVSESSION_SUCCESS;
}
} // OHOS::AVSession
