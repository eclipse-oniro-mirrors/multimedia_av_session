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

#include "hw_cast_provider.h"
#include <thread>
#include "cast_session_manager.h"
#include "hw_cast_stream_player.h"
#include "avsession_log.h"
#include "avsession_errors.h"

using namespace OHOS::CastEngine::CastEngineClient;
using namespace OHOS::CastEngine;

namespace OHOS::AVSession {
const uint32_t UNTRUSTED_DEVICE = 0;
const uint32_t TRUSTED_DEVICE = 1;

HwCastProvider::~HwCastProvider()
{
    SLOGI("destruct the HwCastProvider");
    Release();
}

void HwCastProvider::Init()
{
    SLOGI("Init the HwCastProvider");
    CastSessionManager::GetInstance().RegisterListener(shared_from_this());
}

bool HwCastProvider::StartDiscovery(int castCapability)
{
    SLOGI("start discovery and the castCapability is %{public}d", castCapability);
    return CastSessionManager::GetInstance().StartDiscovery(castCapability);
}

void HwCastProvider::StopDiscovery()
{
    SLOGI("stop discovery");
    CastSessionManager::GetInstance().StopDiscovery();
}

int32_t HwCastProvider::SetDiscoverable(const bool enable)
{
    SLOGI("SetDiscoverable in %{public}d", static_cast<int32_t>(enable));
    return CastSessionManager::GetInstance().SetDiscoverable(enable);
}

void HwCastProvider::Release()
{
    SLOGI("Release the HwCastProvider");
    {
        std::lock_guard lockGuard(mutexLock_);
        hwCastProviderSessionMap_.clear();
        avCastControllerMap_.clear();
        castStateListenerList_.clear();
        castFlag_.clear();
    }
    if (!isRelease_) {
        SLOGI("release in with check pass");
        isRelease_ = true;
    } else {
        SLOGW("already in release, check return");
        return;
    }
    CastSessionManager::GetInstance().UnregisterListener();
    CastSessionManager::GetInstance().Release();
    SLOGD("Release done");
}

int HwCastProvider::StartCastSession()
{
    SLOGI("StartCastSession begin");
    CastSessionProperty property = {CastEngine::ProtocolType::CAST_PLUS_STREAM, CastEngine::EndType::CAST_SOURCE};
    std::shared_ptr<ICastSession> castSession = nullptr;
    CastSessionManager::GetInstance().CreateCastSession(property, castSession);
    int castId;
    {
        SLOGI("StartCastSession pre check lock");
        std::lock_guard lockGuard(mutexLock_);
        SLOGI("StartCastSession check lock");
        std::vector<bool>::iterator iter = find(castFlag_.begin(), castFlag_.end(), false);
        if (iter == castFlag_.end()) {
            SLOGE("StartCastSession faileded");
            return AVSESSION_ERROR;
        }
        *iter = true;
        castId = iter - castFlag_.begin();
        auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(castSession);
        if (hwCastProviderSession) {
            hwCastProviderSession->Init();
        }
        hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    }
    SLOGI("StartCastSession successed and return the castId is %{public}d", castId);

    return castId;
}
void HwCastProvider::StopCastSession(int castId)
{
    SLOGI("StopCastSession begin with %{public}d", castId);
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("StopCastSession check lock");

    auto hwCastStreamPlayer = avCastControllerMap_[castId];
    if (hwCastStreamPlayer) {
        hwCastStreamPlayer->Release();
    }

    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("no need to release castSession for castId %{public}d is not exit in hwCastProviderSessionMap_", castId);
        return;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession) {
        hwCastProviderSession->Release();
    }
    hwCastProviderSessionMap_.erase(castId);
    castFlag_[castId] = false;
    avCastControllerMap_.erase(castId);
}

bool HwCastProvider::AddCastDevice(int castId, DeviceInfo deviceInfo)
{
    SLOGI("AddCastDevice with config castSession and corresonding castId is %{public}d", castId);
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("add device check lock done");

    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("the castId corresonding to castSession is not exist");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (!hwCastProviderSession) {
        SLOGE("the castId corresonding to castSession is nullptr");
        return false;
    }

    lastCastId_ = castId;
    return hwCastProviderSession->AddDevice(deviceInfo.deviceId_);
}

bool HwCastProvider::RemoveCastDevice(int castId, DeviceInfo deviceInfo)
{
    SLOGI("RemoveCastDevice with config castSession and corresonding castId is %{public}d", castId);
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("remove device check lock");
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("the castId corresonding to castSession is not exist");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (!hwCastProviderSession) {
        SLOGE("the castId corresonding to castSession is nullptr");
        return false;
    }

    return hwCastProviderSession->RemoveDevice(deviceInfo.deviceId_);
}

bool HwCastProvider::RegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener)
{
    SLOGI("RegisterCastStateListener in");
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("RegisterCastStateListener in pass lock");
    if (listener == nullptr) {
        SLOGE("RegisterCastStateListener the listener is nullptr");
        return false;
    }
    if (find(castStateListenerList_.begin(), castStateListenerList_.end(), listener) != castStateListenerList_.end()) {
        SLOGE("RegisterCastStateListener the listener is already be registered");
        return false;
    }
    SLOGI("RegisterCastStateListener successed, and save it in the castStateListenerList_");
    castStateListenerList_.emplace_back(listener);

    return true;
}

bool HwCastProvider::UnRegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener)
{
    SLOGI("UnRegisterCastStateListener in");
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("UnRegisterCastStateListener in pass lock");
    if (listener == nullptr) {
        SLOGE("UnRegisterCastStateListener the listener is nullptr");
        return false;
    }
    for (auto iter = castStateListenerList_.begin(); iter != castStateListenerList_.end();) {
        if (*iter == listener) {
            castStateListenerList_.erase(iter);
            SLOGI("UnRegisterCastStateListener successed, and erase it from castStateListenerList_");
            return true;
        } else {
            ++iter;
        }
    }
    SLOGE("listener is not found in castStateListenerList_, so UnRegisterCastStateListener failed");

    return false;
}

std::shared_ptr<IAVCastControllerProxy> HwCastProvider::GetRemoteController(int castId)
{
    SLOGI("get remote controller with castId %{public}d", static_cast<int32_t>(castId));
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("get remote controller check lock with castId %{public}d", static_cast<int32_t>(castId));
    if (avCastControllerMap_.find(castId) != avCastControllerMap_.end()) {
        SLOGI("the castId corresonding to streamPlayer is already exist");
        return avCastControllerMap_[castId];
    }
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("No castSession corresonding to castId exists");
        return nullptr;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("castSession corresonding to castId is nullptr");
        return nullptr;
    }
    std::shared_ptr<IStreamPlayer> streamPlayer = hwCastProviderSession->CreateStreamPlayer();
    std::shared_ptr<HwCastStreamPlayer> hwCastStreamPlayer = std::make_shared<HwCastStreamPlayer>(streamPlayer);
    if (!hwCastStreamPlayer) {
        SLOGE("the created hwCastStreamPlayer is nullptr");
        return nullptr;
    }
    hwCastStreamPlayer->Init();
    avCastControllerMap_[castId] = hwCastStreamPlayer;
    SLOGI("Create streamPlayer finished");
    return hwCastStreamPlayer;
}

bool HwCastProvider::RegisterCastSessionStateListener(int castId,
    std::shared_ptr<IAVCastSessionStateListener> listener)
{
    SLOGD("RegisterCastSessionStateListener for castId %{public}d", castId);
    if (listener == nullptr) {
        SLOGE("RegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("register castsession state listener check lock with castId %{public}d", static_cast<int32_t>(castId));
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("RegisterCastSessionStateListener failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("RegisterCastSessionStateListener failed for the hwCastProviderSession is nullptr");
        return false;
    }

    return hwCastProviderSession->RegisterCastSessionStateListener(listener);
}

bool HwCastProvider::UnRegisterCastSessionStateListener(int castId,
    std::shared_ptr<IAVCastSessionStateListener> listener)
{
    if (listener == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("unregister castsession state listener check lock with castId %{public}d", static_cast<int32_t>(castId));
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("UnRegisterCastSessionStateListener failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the hwCastProviderSession is nullptr");
        return false;
    }

    return hwCastProviderSession->UnRegisterCastSessionStateListener(listener);
}


void HwCastProvider::OnDeviceFound(const std::vector<CastRemoteDevice> &deviceList)
{
    std::vector<DeviceInfo> deviceInfoList;
    if (deviceList.empty()) {
        SLOGW("recv empty deviceList, return");
        return;
    }
    SLOGI("get deviceList size %{public}zu", deviceList.size());
    for (CastRemoteDevice castRemoteDevice : deviceList) {
        SLOGI("get devices with deviceName %{public}s", castRemoteDevice.deviceName.c_str());
        DeviceInfo deviceInfo;
        deviceInfo.castCategory_ = AVCastCategory::CATEGORY_REMOTE;
        deviceInfo.deviceId_ = castRemoteDevice.deviceId;
        deviceInfo.deviceName_ = castRemoteDevice.deviceName;
        deviceInfo.deviceType_ = static_cast<int>(castRemoteDevice.deviceType);
        deviceInfo.ipAddress_ = castRemoteDevice.ipAddress;
        deviceInfo.supportedProtocols_ = ProtocolType::TYPE_CAST_PLUS_STREAM;
        deviceInfo.authenticationStatus_ = static_cast<int>(castRemoteDevice.subDeviceType) == 0 ?
            TRUSTED_DEVICE : UNTRUSTED_DEVICE;
        deviceInfoList.emplace_back(deviceInfo);
    }
    for (auto listener : castStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnDeviceAvailable for registered listeners");
            listener->OnDeviceAvailable(deviceInfoList);
        }
    }
}

void HwCastProvider::OnDeviceOffline(const std::string& deviceId)
{
    SLOGI("Received on device offline event");
    for (auto listener : castStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnDeviceOffline for registered listeners");
            listener->OnDeviceOffline(deviceId);
        }
    }
}

void HwCastProvider::WaitSessionRelease()
{
    SLOGI("waitSessionRelease get in");
    std::lock_guard lockGuard(mutexLock_);
    if (hwCastProviderSessionMap_.find(lastCastId_) == hwCastProviderSessionMap_.end()) {
        SLOGI("waitSessionRelease for the castId is not exit, check cache session");
        return;
    }
    auto hwCastProviderSession = lastCastSession;
    if (hwCastProviderSession == nullptr) {
        SLOGI("waitSessionRelease failed for the hwCastProviderSession is nullptr");
        return;
    }
    hwCastProviderSession->CheckProcessDone();
    SLOGI("waitSessionRelease get done");
}

void HwCastProvider::OnSessionCreated(const std::shared_ptr<CastEngine::ICastSession> &castSession)
{
    SLOGI("Cast provider received session create event");
    std::thread([this, castSession]() {
        SLOGI("Cast pvd received session create event and create task thread");
        WaitSessionRelease();
        SLOGI("Cast pvd received session create event and wait session release done");
        for (auto listener : castStateListenerList_) {
            listener->OnSessionNeedDestroy();
            SLOGI("Cast pvd received session create event and session destroy check done");
        }
        int32_t castId;
        {
            std::lock_guard lockGuard(mutexLock_);
            std::vector<bool>::iterator iter = find(castFlag_.begin(), castFlag_.end(), false);
            if (iter == castFlag_.end()) {
                SLOGE("Do not trigger callback due to the castFlag_ used up.");
                return;
            }
            *iter = true;
            castId = iter - castFlag_.begin();
            SLOGI("Cast task thread to find flag");
        }
        auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(castSession);
        if (hwCastProviderSession == nullptr) {
            SLOGE("get hwPvdSession in create with null");
            return;
        }
        hwCastProviderSession->Init();
        {
            std::lock_guard lockGuard(mutexLock_);
            hwCastProviderSessionMap_[castId] = hwCastProviderSession;
            lastCastSession = hwCastProviderSession;
            lastCastId_ = castId;
            SLOGI("Cast task thread to create player");
            std::shared_ptr<IStreamPlayer> streamPlayer = hwCastProviderSession->CreateStreamPlayer();
            std::shared_ptr<HwCastStreamPlayer> hwCastStreamPlayer = std::make_shared<HwCastStreamPlayer>(streamPlayer);
            if (hwCastStreamPlayer == nullptr) {
                SLOGE("the created hwCastStreamPlayer is nullptr");
                return;
            }
            hwCastStreamPlayer->Init();
            avCastControllerMap_[castId] = hwCastStreamPlayer;
        }
        SLOGI("Create streamPlayer finished %{public}d", castId);
        for (auto listener : castStateListenerList_) {
            listener->OnSessionCreated(castId);
        }
        SLOGI("do session create notify finished %{public}d", castId);
    }).detach();
}

void HwCastProvider::OnServiceDied()
{
    for (auto listener : castStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnServiceDied for registered listeners");
            listener->OnCastServerDied();
        }
    }
}
} // namespace OHOS::AVSession
