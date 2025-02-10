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
#include "hw_cast_provider.h"
#include "avsession_sysevent.h"

static std::shared_ptr<OHOS::AVSession::HwCastProvider> hwProvider_;

namespace OHOS::AVSession {
AVRouterImpl::AVRouterImpl()
{
    SLOGD("AVRouter construct");
}

int32_t AVRouterImpl::Init(IAVSessionServiceListener *servicePtr)
{
    SLOGI("Start init AVRouter");
    {
        std::lock_guard lockGuard(servicePtrLock_);
        servicePtr_ = servicePtr;
    }
    castSessionListener_ = std::make_shared<CastSessionListener>(this);
    hwProvider_ = std::make_shared<HwCastProvider>();
    if (hwProvider_ != nullptr && hwProvider_->Init() != AVSESSION_ERROR) {
        SLOGI("init pvd success");
    } else {
        hwProvider_ = nullptr;
        SLOGE("init with null pvd to init");
        return AVSESSION_ERROR;
    }
    providerNumber_ = providerNumberEnableDefault_;
    std::shared_ptr<AVCastProviderManager> avCastProviderManager = std::make_shared<AVCastProviderManager>();
    if (avCastProviderManager == nullptr) {
        SLOGE("init with null manager");
        return AVSESSION_ERROR;
    }
    avCastProviderManager->Init(providerNumber_, hwProvider_);
    providerManagerMap_[providerNumber_] = avCastProviderManager;
    if (hwProvider_ != nullptr) {
        hwProvider_->RegisterCastStateListener(avCastProviderManager);
    } else {
        SLOGE("init with null pvd to registerlistener");
        return AVSESSION_ERROR;
    }
    std::lock_guard lockGuard(providerManagerLock_);
    if (cacheStartDiscovery_) {
        SLOGI("cacheStartDiscovery check do discovery");
        StartCastDiscovery(cacheCastDeviceCapability_, cacheDrmSchemes_);
        cacheStartDiscovery_ = false;
    }
    SLOGI("init AVRouter done");
    return AVSESSION_SUCCESS;
}

bool AVRouterImpl::Release()
{
    SLOGI("Start Release AVRouter");
    if (hasSessionAlive_) {
        SLOGE("has session alive, but continue");
    }
    if (hwProvider_ == nullptr) {
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
    castHandleToInfoMap_.clear();
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

    castHandleToInfoMap_.clear();
    int64_t castHandle = -1;
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumberEnableDefault_) !=
        providerManagerMap_.end(), castHandle, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG((providerManagerMap_[providerNumberEnableDefault_] != nullptr) &&
        (providerManagerMap_[providerNumberEnableDefault_]->provider_ != nullptr),
        AVSESSION_ERROR, "provider is nullptr");
    int64_t tempId = 1;
    // The first 32 bits are providerId, the last 32 bits are castId
    castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) |
        static_cast<const uint32_t>(castId));
    CastHandleInfo castHandleInfo;
    OutputDeviceInfo outputDeviceInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleToInfoMap_[castHandle] = castHandleInfo;
    {
        std::lock_guard lockGuard(servicePtrLock_);
        servicePtr_->CreateSessionByCast(castHandle);
    }
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
    SLOGI("AVRouterImpl received OnCastServerDied event %{public}d", providerNumber);
    {
        std::lock_guard lockGuard(servicePtrLock_);
        if (servicePtr_ == nullptr) {
            return ERR_SERVICE_NOT_EXIST;
        }
        servicePtr_->setInCast(false);
    }
    std::lock_guard lockGuard(providerManagerLock_);
    hasSessionAlive_ = false;
    providerNumber_ = providerNumberDisable_;
    providerManagerMap_.clear();
    castHandleToInfoMap_.clear();
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
    for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
        if (number == castHandle && castHandleInfo.avCastControllerProxy_ != nullptr) {
            return castHandleInfo.avCastControllerProxy_;
        }
    }

    if (castHandleToInfoMap_.find(castHandle) != castHandleToInfoMap_.end()) {
        castHandleToInfoMap_[castHandle].avCastControllerProxy_ =
            providerManagerMap_[providerNumber]->provider_->GetRemoteController(castId);
    }
    return providerManagerMap_[providerNumber]->provider_->GetRemoteController(castId);
}

int64_t AVRouterImpl::StartCast(const OutputDeviceInfo& outputDeviceInfo,
    std::map<std::string, std::string>& serviceNameMapState, std::string sessionId)
{
    SLOGI("AVRouterImpl start cast process");
    castServiceNameMapState_ = serviceNameMapState;
    int64_t castHandle = -1;
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(outputDeviceInfo.deviceInfos_[0].providerId_) !=
        providerManagerMap_.end(), castHandle, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_] != nullptr
        && providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_]->provider_ != nullptr,
        AVSESSION_ERROR, "provider is nullptr");
    for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
        if (castHandleInfo.sessionId_ != sessionId && castHandleInfo.outputDeviceInfo_.deviceInfos_.size() > 0 &&
            castHandleInfo.outputDeviceInfo_.deviceInfos_[0].deviceId_ == outputDeviceInfo.deviceInfos_[0].deviceId_) {
            castHandleToInfoMap_[number].sessionId_ = sessionId;
            return number;
        }
    }
    int32_t castId = providerManagerMap_[outputDeviceInfo.deviceInfos_[0].
        providerId_]->provider_->StartCastSession();
    CHECK_AND_RETURN_RET_LOG(castId != AVSESSION_ERROR, AVSESSION_ERROR, "StartCast failed");
    int64_t tempId = outputDeviceInfo.deviceInfos_[0].providerId_;
    // The first 32 bits are providerId, the last 32 bits are castId
    castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) | static_cast<uint32_t>(castId));
    hasSessionAlive_ = true;

    CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = sessionId;
    OutputDeviceInfo localDevice;
    DeviceInfo localInfo;
    localInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
    localInfo.deviceId_ = "-1";
    localInfo.deviceName_ = "LocalDevice";
    localDevice.deviceInfos_.emplace_back(localInfo);
    castHandleInfo.outputDeviceInfo_ = localDevice;
    castHandleToInfoMap_[castHandle] = castHandleInfo;
    return castHandle;
}

int32_t AVRouterImpl::AddDevice(const int32_t castId, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("AVRouterImpl AddDevice process");
    
    int64_t tempId = outputDeviceInfo.deviceInfos_[0].providerId_;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) |
        static_cast<uint32_t>(castId));
    for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
        if (castHandle == number && castHandleInfo.outputDeviceInfo_.deviceInfos_.size() > 0 &&
            castHandleInfo.outputDeviceInfo_.deviceInfos_[0].deviceId_ == outputDeviceInfo.deviceInfos_[0].deviceId_) {
            return AVSESSION_SUCCESS;
        }
    }
    bool ret = providerManagerMap_[outputDeviceInfo.deviceInfos_[0].providerId_]->provider_->AddCastDevice(castId,
        outputDeviceInfo.deviceInfos_[0]);
    SLOGI("AVRouterImpl AddDevice process with ret %{public}d", static_cast<int32_t>(ret));
    if (ret && castHandleToInfoMap_.find(castHandle) != castHandleToInfoMap_.end()) {
        castHandleToInfoMap_[castHandle].outputDeviceInfo_ = outputDeviceInfo;
    }
    return ret ? AVSESSION_SUCCESS : ERR_DEVICE_CONNECTION_FAILED;
}

int32_t AVRouterImpl::StopCast(const int64_t castHandle)
{
    SLOGI("AVRouterImpl stop cast process");

    int32_t providerNumber = static_cast<int32_t>(static_cast<uint64_t>(castHandle) >> 32);
    SLOGI("Stop cast, the provider number is %{public}d", providerNumber);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        castHandle, "Can not find corresponding provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<const uint64_t>(castHandle) << 32) >> 32);
    SLOGI("Stop cast, the castId is %{public}d", castId);
    CHECK_AND_RETURN_RET_LOG(castHandleToInfoMap_.find(castHandle) != castHandleToInfoMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding castHandle");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    CHECK_AND_RETURN_RET_LOG(castHandleToInfoMap_[castHandle].outputDeviceInfo_.deviceInfos_.size() > 0,
        AVSESSION_ERROR, "deviceInfos is empty");
    providerManagerMap_[providerNumber]->provider_->RemoveCastDevice(castId,
        castHandleToInfoMap_[castHandle].outputDeviceInfo_.deviceInfos_[0]);
    hasSessionAlive_ = false;
    SLOGI("AVRouterImpl stop cast process remove device done");

    if (castHandleToInfoMap_.find(castHandle) != castHandleToInfoMap_.end()) {
        OutputDeviceInfo localDevice;
        DeviceInfo localInfo;
        localInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
        localInfo.deviceId_ = "-1";
        localInfo.deviceName_ = "LocalDevice";
        localDevice.deviceInfos_.emplace_back(localInfo);
        castHandleToInfoMap_[castHandle].outputDeviceInfo_ = localDevice;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::StopCastSession(const int64_t castHandle)
{
    SLOGI("AVRouterImpl stop cast session");

    int32_t providerNumber = static_cast<int32_t>(static_cast<uint64_t>(castHandle) >> 32);

    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        castHandle, "Can not find corresponding provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(castHandleToInfoMap_.find(castHandle) != castHandleToInfoMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding castHandle");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumber]->provider_->StopCastSession(castId);
    hasSessionAlive_ = false;

    for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
        if (number == castHandle) {
            castHandleToInfoMap_[number].avCastControllerProxy_ = nullptr;
        }
    }
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::SetServiceAllConnectState(int64_t castHandle, DeviceInfo deviceInfo)
{
    if (castHandleToInfoMap_.find(castHandle) != castHandleToInfoMap_.end()) {
        OutputDeviceInfo device;
        device.deviceInfos_.emplace_back(deviceInfo);
        castHandleToInfoMap_[castHandle].outputDeviceInfo_ = device;
    }
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumberEnableDefault_) != providerManagerMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumberEnableDefault_] != nullptr
        && providerManagerMap_[providerNumberEnableDefault_]->provider_ != nullptr,
        AVSESSION_ERROR, "provider is nullptr");
    providerManagerMap_[providerNumberEnableDefault_]->provider_->SetStreamState(castHandle, deviceInfo);
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

int32_t AVRouterImpl::RegisterCallback(int64_t castHandle, const std::shared_ptr<IAVRouterListener> callback,
    std::string sessionId, DeviceInfo deviceInfo)
{
    SLOGI("AVRouterImpl register IAVRouterListener callback to provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t providerNumber = static_cast<int32_t>(static_cast<uint64_t>(castHandle) >> 32);
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    if (GetMirrorCastHandle() == noMirrorCastHandle) {
        for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
            if (number == castHandle && castHandleInfo.outputDeviceInfo_.deviceInfos_.size() > 0 &&
                castHandleInfo.avRouterListener_ != nullptr) {
                SLOGI("trigger the OnCastStateChange for disconnected/connected avRouterListener");
                castHandleInfo.avRouterListener_->OnCastStateChange(castConnectStateForDisconnect_,
                    castHandleInfo.outputDeviceInfo_.deviceInfos_[0], false);
                castHandleToInfoMap_[castHandle].avRouterListener_ = callback;
                callback->OnCastStateChange(castConnectStateForConnected_,
                    castHandleInfo.outputDeviceInfo_.deviceInfos_[0], false);
                return AVSESSION_SUCCESS;
            }
        }
        providerManagerMap_[providerNumber]->provider_->RegisterCastSessionStateListener(castId, castSessionListener_);
        if (castHandleToInfoMap_.find(castHandle) != castHandleToInfoMap_.end()) {
            castHandleToInfoMap_[castHandle].avRouterListener_ = callback;
            castHandleToInfoMap_[castHandle].sessionId_ = sessionId;
        }
    } else {
        if (castHandleToInfoMap_.find(castHandle) != castHandleToInfoMap_.end() &&
            castHandleToInfoMap_[castHandle].avRouterListener_ == nullptr) {
            providerManagerMap_[providerNumber]->provider_->RegisterCastSessionStateListener(castId,
                castSessionListener_);
            OutputDeviceInfo outputDevice;
            outputDevice.deviceInfos_.emplace_back(deviceInfo);
            castHandleToInfoMap_[castHandle].outputDeviceInfo_ = outputDevice;
            castHandleToInfoMap_[castHandle].avRouterListener_ = callback;
            castHandleToInfoMap_[castHandle].sessionId_ = sessionId;
        } else {
            mirrorSessionMap_[sessionId] = callback;
        }
        callback->OnCastStateChange(castConnectStateForConnected_, deviceInfo, false);
    }
    SLOGD("AVRouter impl register callback finished");
    return AVSESSION_SUCCESS;
}

int32_t AVRouterImpl::UnRegisterCallback(int64_t castHandle,
    const std::shared_ptr<IAVRouterListener> callback, std::string sessionId)
{
    SLOGI("AVRouterImpl UnRegisterCallback IAVRouterListener callback to provider");
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t providerNumber = static_cast<uint64_t>(static_cast<uint64_t>(castHandle)) >> 32;
    // The first 32 bits are providerId, the last 32 bits are castId
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumber) != providerManagerMap_.end(),
        AVSESSION_ERROR, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumber] != nullptr
        && providerManagerMap_[providerNumber]->provider_ != nullptr, AVSESSION_ERROR, "provider is nullptr");
    for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
        if (castHandleInfo.sessionId_ == sessionId && number == castHandle) {
            providerManagerMap_[providerNumber]->provider_->UnRegisterCastSessionStateListener(castId,
                castSessionListener_);
            castHandleToInfoMap_[number].avRouterListener_ = nullptr;
        }
    }
    if (mirrorSessionMap_.find(sessionId) != mirrorSessionMap_.end()) {
        mirrorSessionMap_.erase(sessionId);
    }
    return AVSESSION_SUCCESS;
}

int64_t AVRouterImpl::GetMirrorCastHandle()
{
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_.find(providerNumberEnableDefault_) != providerManagerMap_.end(),
        providerNumberEnableDefault_, "Can not find corresponding provider");
    CHECK_AND_RETURN_RET_LOG(providerManagerMap_[providerNumberEnableDefault_] != nullptr &&
        providerManagerMap_[providerNumberEnableDefault_]->provider_ != nullptr,
        AVSESSION_ERROR, "provider is nullptr");
    return providerManagerMap_[providerNumberEnableDefault_]->provider_->GetMirrorCastHandle();
}

void AVRouterImpl::OnCastStateChange(int32_t castState, DeviceInfo deviceInfo)
{
    for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
        if (castHandleInfo.avRouterListener_ != nullptr) {
            SLOGI("trigger the OnCastStateChange for registered avRouterListener");
            std::shared_ptr<IAVRouterListener> listener = castHandleInfo.avRouterListener_;
            AVSessionEventHandler::GetInstance().AVSessionPostTask([listener, castState, deviceInfo]() {
                listener->OnCastStateChange(castState, deviceInfo, true);
                }, "OnCastStateChange", 0);
            if (castState == castConnectStateForDisconnect_) {
                OutputDeviceInfo localDevice;
                DeviceInfo localInfo;
                localInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
                localInfo.deviceId_ = "-1";
                localInfo.deviceName_ = "LocalDevice";
                localDevice.deviceInfos_.emplace_back(localInfo);
                castHandleToInfoMap_[number].outputDeviceInfo_ = localDevice;
            }
        }
    }
}

void AVRouterImpl::OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
{
    for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
        if (castHandleInfo.avRouterListener_ != nullptr) {
            SLOGI("trigger the OnCastEventRecv for registered avRouterListener");
            castHandleInfo.avRouterListener_->OnCastEventRecv(errorCode, errorMsg);
        }
    }
}

void AVRouterImpl::DisconnetOtherSession(std::string sessionId, DeviceInfo deviceInfo)
{
    for (const auto& [string, avRouterListener] : mirrorSessionMap_) {
        if (string != sessionId && avRouterListener != nullptr) {
            std::shared_ptr<IAVRouterListener> listener = avRouterListener;
            avRouterListener->OnCastStateChange(castConnectStateForDisconnect_, deviceInfo, false);
        }
    }
    for (const auto& [number, castHandleInfo] : castHandleToInfoMap_) {
        if (castHandleInfo.sessionId_ != sessionId) {
            if (castHandleInfo.avRouterListener_ != nullptr) {
                castHandleInfo.avRouterListener_->OnCastStateChange(castConnectStateForDisconnect_, deviceInfo, false);
            }
            castHandleToInfoMap_[number].sessionId_ = sessionId;
            castHandleToInfoMap_[number].avRouterListener_ = mirrorSessionMap_[sessionId];
        }
    }
    mirrorSessionMap_.clear();
}
} // namespace OHOS::AVSession
