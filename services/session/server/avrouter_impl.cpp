/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "avsession_sysevent.h"

static std::shared_ptr<OHOS::AVSession::HwCastProvider> hwProvider_;

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
    hwProvider_ = std::make_shared<HwCastProvider>();
    if (hwProvider_ != nullptr) {
        hwProvider_->Init();
    } else {
        SLOGE("init with null pvd to init");
        return;
    }
    providerNumber_ = providerNumberEnableDefault_;
    std::shared_ptr<AVCastProviderManager> avCastProviderManager = std::make_shared<AVCastProviderManager>();
    if (avCastProviderManager == nullptr) {
        SLOGE("init with null manager");
        return;
    }
    avCastProviderManager->Init(providerNumber_, hwProvider_);
    providerManagerMap_[providerNumber_] = avCastProviderManager;
    if (hwProvider_ != nullptr) {
        hwProvider_->RegisterCastStateListener(avCastProviderManager);
    } else {
        SLOGE("init with null pvd to registerlistener");
        return;
    }
    if (cacheStartDiscovery_) {
        SLOGI("cacheStartDiscovery check do discovery");
        StartCastDiscovery(cacheCastDeviceCapability_, cacheDrmSchemes_);
        cacheStartDiscovery_ = false;
    }
    SLOGI("init AVRouter done");
}

bool AVRouterImpl::Release()
{
    SLOGI("Start Release AVRouter");
    if (hasSessionAlive_) {
        SLOGE("has session alive, but continue");
    }
    if (hwProvider_ == nullptr || (castServiceNameMapState_["HuaweiCast"] == deviceStateConnection ||
        castServiceNameMapState_["HuaweiCast-Dual"] == deviceStateConnection)) {
        SLOGE("Start Release AVRouter err for no provider");
        return false;
    }
    std::lock_guard lockGuard(providerManagerLock_);

    if (hwProvider_ == nullptr) {
        SLOGE("repeat check for no pvd");
        return false;
    }
    SLOGI("repeat check for pvd alive");
    hwProvider_->Release();
    hwProvider_ = nullptr;
    providerNumber_ = providerNumberDisable_;
    providerManagerMap_.clear();
    SLOGD("Release AVRouter done");
    return false;
}

int32_t AVRouterImpl::StartDeviceLogging(int32_t fd, uint32_t maxSize)
{
    SLOGI("AVRouterImpl StartDeviceLogging");
    std::lock_guard lockGuard(providerManagerLock_);

    if (providerManagerMap_.empty()) {
        cacheStartDeviceLogging_ = true;
        return AVSESSION_SUCCESS;
    }
    for (const auto& [number, providerManager] : providerManagerMap_) {
        CHECK_AND_RETURN_RET_LOG(providerManager != nullptr && providerManager->provider_ != nullptr,
            AVSESSION_ERROR, "provider is nullptr");
        providerManager->provider_->StartDeviceLogging(fd, maxSize);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StopDeviceLogging()
{
    SLOGI("AVRouterImpl StopDeviceLogging");
    std::lock_guard lockGuard(providerManagerLock_);

    if (cacheStartDeviceLogging_) {
        SLOGI("clear cacheStartDeviceLogging_ when stop discovery");
        cacheStartDeviceLogging_ = false;
    }
    for (const auto& [number, providerManager] : providerManagerMap_) {
        CHECK_AND_RETURN_RET_LOG(providerManager != nullptr && providerManager->provider_ != nullptr,
            AVSESSION_ERROR, "provider is nullptr");
        providerManager->provider_->StopDeviceLogging();
    }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StartCastDiscovery(int32_t castDeviceCapability, std::vector<std::string> drmSchemes)
{
    SLOGI("AVRouterImpl StartCastDiscovery");
    std::lock_guard lockGuard(providerManagerLock_);

    if (providerManagerMap_.empty()) {
        SLOGI("set cacheStartDiscovery with no element with cap %{public}d", static_cast<int>(castDeviceCapability));
        cacheStartDiscovery_ = true;
        cacheCastDeviceCapability_ = castDeviceCapability;
        cacheDrmSchemes_ = drmSchemes;
        return AVSESSION_SUCCESS;
    }
    for (const auto& [number, providerManager] : providerManagerMap_) {
        CHECK_AND_RETURN_RET_LOG(providerManager != nullptr && providerManager->provider_ != nullptr,
            AVSESSION_ERROR, "provider is nullptr");
        providerManager->provider_->StartDiscovery(castDeviceCapability, drmSchemes);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StopCastDiscovery()
{
    SLOGI("AVRouterImpl StopCastDiscovery");
    std::lock_guard lockGuard(providerManagerLock_);

    if (cacheStartDiscovery_) {
        SLOGI("clear cacheStartDiscovery when stop discovery");
        cacheStartDiscovery_ = false;
    }
    for (const auto& [number, providerManager] : providerManagerMap_) {
        CHECK_AND_RETURN_RET_LOG(providerManager != nullptr && providerManager->provider_ != nullptr,
            AVSESSION_ERROR, "provider is nullptr");
        providerManager->provider_->StopDiscovery();
    }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::SetDiscoverable(const bool enable)
{
    SLOGI("AVRouterImpl SetDiscoverable %{public}d", enable);
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

int32_t AVRouterImpl::OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param)
{
    SLOGI("AVRouterImpl received OnDeviceLogEvent event");

    std::lock_guard lockGuard(servicePtrLock_);
    if (servicePtr_ == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }
    servicePtr_->NotifyDeviceLogEvent(eventId, param);
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
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumberEnableDefault_) !=
        providerManagerMap_.end(), castHandle, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[1] != nullptr
        && providerManagerMap_[1]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    int64_t tempId = 1;
    // The first 32 bits are providerId, the last 32 bits are castId
    castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) |
        static_cast<const uint32_t>(castId));
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
    hasSessionAlive_ = false;
    std::lock_guard lockGuard(providerManagerLock_);
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
    int32_t providerNumber = static_cast<int32_t>(static_cast<const uint64_t>(castHandle) >> 32);
    SLOGD("Get remote controller of provider %{public}d", providerNumber);
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<const uint64_t>(castHandle) << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        nullptr, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr &&
        providerManagerMap_[providerNumber]->provider_ != nullptr, nullptr, "provider is nullptr");
    return providerManagerMap_[providerNumber]->provider_->GetRemoteController(castId);
}

int64_t AVRouterImpl::StartCast(const OutputDeviceInfo& outputDeviceInfo,
    std::map<std::string, std::string>& serviceNameMapState)
{
    SLOGI("AVRouterImpl start cast process");
    castServiceNameMapState_ = serviceNameMapState;
    int64_t castHandle = -1;
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(outputDeviceInfo.deviceInfos_[0].providerId_) !=
        providerManagerMap_.end(), castHandle, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_] != nullptr
        && providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_]->provider_ != nullptr,
        AVSESSION_ERROR, "provider is nullptr");
    int32_t castId = providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_]->provider_->StartCastSession();
    int64_t tempId = outputDeviceInfo.deviceInfos_[0].providerId_;
    // The first 32 bits are providerId, the last 32 bits are castId
    castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) | static_cast<uint32_t>(castId));
    hasSessionAlive_ = true;

    return castHandle;
}

int32_t AVRouterImpl::AddDevice(const int32_t castId, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("AVRouterImpl AddDevice process");
    bool ret = providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_]->provider_->AddCastDevice(castId,
        outputDeviceInfo.deviceInfos_[0]);
    SLOGI("AVRouterImpl AddDevice process with ret %{public}d", static_cast<int32_t>(ret));
    castHandleToOutputDeviceMap_[castId] = outputDeviceInfo;
    return ret ? AVSESSION_SUCCESS : ERR_DEVICE_CONNECTION_FAILED;
}

int32_t AVRouterImpl::StopCast(const int64_t castHandle, int32_t removeTimes)
{
    SLOGI("AVRouterImpl stop cast process");

    int32_t providerNumber = static_cast<int32_t>(static_cast<uint64_t>(castHandle) >> 32);
    SLOGI("Stop cast, the provider number is %{public}d", providerNumber);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        castHandle, "Can not find corresponding provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<const uint64_t>(castHandle) << 32) >> 32);
    SLOGI("Stop cast, the castId is %{public}d, removeTimes is %{public}d", castId, removeTimes);
    CHECK_AND_RETURN_RET_LOG(castHandleToOutputDeviceMap_.find(castId) != castHandleToOutputDeviceMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding castId");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    CHECK_AND_RETURN_RET_LOG(castId != providerManagerMap_[providerNumber]->provider_->GetMirrorCastId() ||
        removeTimes == 0, AVSESSION_ERROR, "cannot remove");
    providerManagerMap_[providerNumber]->provider_->RemoveCastDevice(castId,
        castHandleToOutputDeviceMap_[castId].deviceInfos_[0]);
    hasSessionAlive_ = false;
    SLOGI("AVRouterImpl stop cast process remove device done");

    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StopCastSession(const int64_t castHandle)
{
    SLOGI("AVRouterImpl stop cast process");

    int32_t providerNumber = static_cast<int32_t>(static_cast<uint64_t>(castHandle) >> 32);

    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        castHandle, "Can not find corresponding provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
    castHandleToOutputDeviceMap_[castId] = castOutputDeviceInfo_;
    CHECK_AND_RETURN_RET_LOG(castHandleToOutputDeviceMap_.find(castId) != castHandleToOutputDeviceMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding castId");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->StopCastSession(castId);
    hasSessionAlive_ = false;

    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::SetServiceAllConnectState(int64_t castHandle, DeviceInfo deviceInfo)
{
    int32_t providerNumber = static_cast<int32_t>(static_cast<uint64_t>(castHandle) >> 32);
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
    castOutputDeviceInfo_.deviceInfos_.emplace_back(deviceInfo);
    castHandleToOutputDeviceMap_[castId] = castOutputDeviceInfo_;
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->SetStreamState(castId, deviceInfo);
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::GetRemoteNetWorkId(int64_t castHandle, std::string deviceId, std::string &networkId)
{
    int32_t providerNumber = static_cast<int32_t>(static_cast<uint64_t>(castHandle) >> 32);
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->GetRemoteNetWorkId(castId, deviceId, networkId);
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::RegisterCallback(int64_t castHandle, const std::shared_ptr<IAVCastSessionStateListener> callback)
{
    SLOGI("AVRouterImpl register IAVCastSessionStateListener callback to provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t providerNumber = static_cast<int32_t>(static_cast<uint64_t>(castHandle) >> 32);
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
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
    int32_t providerNumber = static_cast<uint64_t>(static_cast<uint64_t>(castHandle)) >> 32;
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->UnRegisterCastSessionStateListener(castId, callback);
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
