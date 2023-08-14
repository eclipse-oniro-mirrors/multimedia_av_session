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
#include "hw_cast_provider.h"

namespace OHOS::AVSession {
AVRouterImpl::AVRouterImpl()
{
    SLOGD("AVRouter construct");
}

void AVRouterImpl::Init(IAVSessionServiceListener *servicePtr)
{
    SLOGI("Start init AVRouter");
    {
        std::lock_guard lockGuard(servicePtrLock_);
        servicePtr_ = servicePtr;
    }
    std::shared_ptr<HwCastProvider> hwProvider = std::make_shared<HwCastProvider>();
    hwProvider->Init();
    providerNumber_++;
    std::shared_ptr<AVCastProviderManager> avCastProviderManager = std::make_shared<AVCastProviderManager>();
    avCastProviderManager->Init(providerNumber_, hwProvider);
    providerManagerMap_[providerNumber_] = avCastProviderManager;
    hwProvider->RegisterCastStateListener(avCastProviderManager);
}

int32_t AVRouterImpl::StartCastDiscovery(int32_t castDeviceCapability)
{
    SLOGI("AVRouterImpl StartCastDiscovery");

    std::lock_guard lockGuard(providerManagerLock_);

    for (const auto& [number, providerManager] : providerManagerMap_) {
        CHECK_AND_RETURN_RET_LOG(providerManager != nullptr && providerManager->provider_ != nullptr,
            AVSESSION_ERROR, "provider is nullptr");
        providerManager->provider_->StartDiscovery(castDeviceCapability);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StopCastDiscovery()
{
    SLOGI("AVRouterImpl StopCastDiscovery");

    std::lock_guard lockGuard(providerManagerLock_);

    for (const auto& [number, providerManager] : providerManagerMap_) {
        CHECK_AND_RETURN_RET_LOG(providerManager != nullptr && providerManager->provider_ != nullptr,
            AVSESSION_ERROR, "provider is nullptr");
        providerManager->provider_->StopDiscovery();
    }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::SetDiscoverable(const bool enable)
{
    SLOGI("AVRouterImpl SetDiscoverable");

    std::lock_guard lockGuard(providerManagerLock_);

    for (const auto& [number, providerManager] : providerManagerMap_) {
        CHECK_AND_RETURN_RET_LOG(providerManager != nullptr && providerManager->provider_ != nullptr,
            AVSESSION_ERROR, "provider is nullptr");
        providerManager->provider_->SetDiscoverable(enable);
    }
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

void AVRouterImpl::ReleaseCurrentCastSession()
{
    SLOGI("Start ReleaseCurrentCastSession");
    std::lock_guard lockGuard(servicePtrLock_);
    servicePtr_->ReleaseCastSession();
}

int32_t AVRouterImpl::OnCastSessionCreated(const int32_t castId)
{
    SLOGI("AVRouterImpl On cast session created, cast id is %{public}d", castId);

    int64_t castHandle = -1;
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(1) !=
        providerManagerMap_.end(), castHandle, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[1] != nullptr &&
        providerManagerMap_[1]->provider_ ! = nullptr, AVSESSION_ERROR, "provider is nullptr");
    int64_t tempId = 1;
    castHandle = (tempId << 32) | castId; // The first 32 bits are providerId, the last 32 bits are castId
    {
        std::lock_guard lockGuard(servicePtrLock_);
        servicePtr_->CreateSessionByCast(castHandle);
    }
    OutputDeviceInfo outputDeviceInfo;
    castHandleToOutputDeviceMap_[castId] = outputDeviceInfo;
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::OnDeviceOffline(const std::string& deviceId)
{
    SLOGI("AVRouterImpl received OnDeviceOffline event");

    std::lock_guard lockGuard(servicePtrLock_);
    if (servicePtr_ == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }
    servicePtr_->NotifyDeviceOffline(deviceId);
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::OnCastServerDied(int32_t providerNumber)
{
    SLOGI("AVRouterImpl received OnCastServerDied event");

    if (providerManagerMap_.find(providerNumber) != providerManagerMap_.end()) {
        providerManagerMap_.erase(providerNumber);
    } else {
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

std::shared_ptr<IAVCastControllerProxy> AVRouterImpl::GetRemoteController(const int64_t castHandle)
{
    SLOGI("AVRouterImpl start get remote controller process");

    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t providerNumber = castHandle >> 32;
    SLOGD("Get remote controller of provider %{public}d", providerNumber);
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((castHandle << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        nullptr, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr &&
        providerManagerMap_[providerNumber]->provider_ != nullptr, nullptr, "provider is nullptr");
    return providerManagerMap_[providerNumber]->provider_->GetRemoteController(castId);
}

int64_t AVRouterImpl::StartCast(const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("AVRouterImpl start cast process");

    int64_t castHandle = -1;
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(outputDeviceInfo.deviceInfos_[0].providerId_) !=
        providerManagerMap_.end(), castHandle, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_] != nullptr
        && providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_]->provider_ != nullptr,
        AVSESSION_ERROR, "provider is nullptr");
    int32_t castId = providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_]->provider_->StartCastSession();
    int64_t tempId = outputDeviceInfo.deviceInfos_[0].providerId_;
    castHandle = (tempId << 32) | castId; // The first 32 bits are providerId, the last 32 bits are castId
    return castHandle;
}

int32_t AVRouterImpl::AddDevice(const int32_t castId, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("AVRouterImpl AddDevice process");
    providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_]->provider_->AddCastDevice(castId,
        outputDeviceInfo.deviceInfos_[0]);
    castHandleToOutputDeviceMap_[castId] = outputDeviceInfo;
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StopCast(const int64_t castHandle)
{
    SLOGI("AVRouterImpl stop cast process");

    int32_t providerNumber = static_cast<int32_t>(castHandle >> 32);
    SLOGI("Stop cast, the provider number is %{public}d", providerNumber);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        castHandle, "Can not find corresponding provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((castHandle << 32) >> 32);
    SLOGI("Stop cast, the castId is %{public}d", castId);
    CHECK_AND_RETURN_RET_LOG(castHandleToOutputDeviceMap_.find(castId) != castHandleToOutputDeviceMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding castId");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->RemoveCastDevice(castId,
        castHandleToOutputDeviceMap_[castId].deviceInfos_[0]);

    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StopCastSession(const int64_t castHandle)
{
    SLOGI("AVRouterImpl stop cast process");

    int32_t providerNumber = static_cast<int32_t>(castHandle >> 32);

    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        castHandle, "Can not find corresponding provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((castHandle << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(castHandleToOutputDeviceMap_.find(castId) != castHandleToOutputDeviceMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding castId");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->StopCastSession(castId);

    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::RegisterCallback(int64_t castHandle, const std::shared_ptr<IAVCastSessionStateListener> callback)
{
    SLOGI("AVRouterImpl register IAVCastSessionStateListener callback to provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t providerNumber = castHandle >> 32;
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((castHandle << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->RegisterCastSessionStateListener(castId, callback);
    SLOGD("AVRouter impl register callback finished");
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::UnRegisterCallback(int64_t castHandle,
    const std::shared_ptr<IAVCastSessionStateListener> callback)
{
    SLOGI("AVRouterImpl UnRegisterCallback IAVCastSessionStateListener callback to provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t providerNumber = castHandle >> 32;
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((castHandle << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->UnRegisterCastSessionStateListener(castId, callback);
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
