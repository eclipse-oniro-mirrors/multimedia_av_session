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
#include "avcast_provider_manager.h"

namespace OHOS::AVSession {
AVRouterImpl::AVRouterImpl()
{
    SLOGD("AVRouter construct");
}

void AVRouterImpl::Init(IAVSessionServiceListener *servicePtr)
{
    SLOGI("Start init AVRouter");
    servicePtr_ = servicePtr;
    // TODO: 这里new出来一个provider
    // HwCastProvider hwProvider = new HwCastProvider();
    // providerId++;
    // AVCastProvider *provider = static_cast<AVCastProvider>(hwProvider);
    // AVCastProviderManager *avCastProviderManager = new AVCastProviderManager();
    // avCastProviderManager.Init(providerId, provider);
    // providerManagerMap_.insert(providerId, avCastProviderManager);
    // provider.RegisterCastStateListener(avCastProviderManager);
}

int32_t AVRouterImpl::StartCastDiscovery(int32_t castDeviceCapability)
{
    SLOGI("AVRouterImpl StartCastDiscovery");

    // std::lock_guard lockGuard(providerManagerLock_);

    // for (const auto& [providerId, providerManager] : providerManagerMap_) {
    //     providerManager->provider->StartCastDiscovery(castDeviceCapability);
    // }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StopCastDiscovery()
{
    SLOGI("AVRouterImpl StopCastDiscovery");

    // std::lock_guard lockGuard(providerManagerLock_);

    // for (const auto& [providerId, providerManager] : providerManagerMap_) {
    //     providerManager->provider->StopCastDiscovery();
    // }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::OnDeviceAvailable(OutputDeviceInfo& castOutputDeviceInfo)
{
    SLOGI("AVRouterImpl received OnDeviceAvailable event");

    std::lock_guard lockGuard(servicePtrLock_);
    if (servicePtr_ == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }
    servicePtr_->NotifyDeviceAvailable(castOutputDeviceInfo);
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::OnCastServerDied(int32_t providerId)
{
    SLOGI("AVRouterImpl received OnCastServerDied event");

    // if (providerManagerMap_.find(providerId) != providerManagerMap_.end()){
    //     providerManagerMap_.erase(providerId);
    // } else {
    //     return AVSESSION_ERROR;
    // }
    return AVSESSION_SUCCESS;
}

std::shared_ptr<IAVCastControllerProxy> AVRouterImpl::GetRemoteController(const int32_t castHandler)
{
    SLOGI("AVRouterImpl start get remote controller process");

    // int32_t providerId = castHandle >> 32;
    // int32_t castId = (castHandle << 32) >> 32;
    // CHECK_AND_RETURN_RET_LOG(providerMap_.find(providerId) != providerMap_.end(),
    //     AVSESSION_ERROR, "Can not find corresponding provider");
    // return providerMap_[providerId].GetRemoteController(castId);
    return nullptr;
}

int64_t AVRouterImpl::StartCast(const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("AVRouterImpl start cast process");

    int64_t castHandle = -1;
    // CHECK_AND_RETURN_RET_LOG(providerMap_.find(outputDeviceInfo[0].providerId_) != providerMap_.end(),
    //     castHandle, "Can not find corresponding provider");
    // int32_t castId = providerMap_[outputDeviceInfo[0].providerId_].startCast(outputDeviceInfo[0]);

    // castHandle = (outputDeviceInfo[0].providerId_ << 32) | castId;
    return castHandle;
}

int32_t AVRouterImpl::StopCast(const int64_t castHandle)
{
    SLOGI("AVRouterImpl stop cast process");

    // int32_t providerId = castHandle >> 32;

    // int64_t castHandle = -1;
    // CHECK_AND_RETURN_RET_LOG(providerMap_.find(providerId) != providerMap_.end(),
    //     castHandle, "Can not find corresponding provider");
    // int32_t castId = providerMap_[providerId].StopCast();

    return AVSESSION_SUCCESS;
}


int32_t AVRouterImpl::RegisterCallback(int64_t castHandle, const std::shared_ptr<IAVCastSessionStateListener> callback)
{
    SLOGI("AVRouterImpl register IAVCastSessionStateListener callback to provider");
    // int32_t providerId = castHandle >> 32;
    // int32_t castId = (castHandle << 32) >> 32;
    // CHECK_AND_RETURN_RET_LOG(providerMap_.find(providerId) != providerMap_.end(),
    //     AVSESSION_ERROR, "Can not find corresponding provider");
    // providerMap_[providerId].RegisterCalback(callback, castId);
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::RegisterCastControllerProxyListener(const int64_t castHandle, const std::shared_ptr<IAVCastControllerProxyListener>& castControllerProxyListener)
{
    SLOGI("AVRouterImpl register IAVCastControllerProxyListener callback to provider");
    // int32_t providerId = castHandle >> 32;
    // int32_t castId = (castHandle << 32) >> 32;
    // CHECK_AND_RETURN_RET_LOG(providerMap_.find(providerId) != providerMap_.end(),
    //     AVSESSION_ERROR, "Can not find corresponding provider");
    // providerMap_[providerId].RegisterCalback(callback, castId);
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
