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
#include "cast_session_manager.h"
#include "hw_cast_stream_player.h"
#include "avsession_log.h"

using namespace OHOS::CastEngine::CastEngineClient;
using namespace OHOS::CastEngine;

namespace OHOS::AVSession {
HwCastProvider::~HwCastProvider()
{
    SLOGI("destruct the HwCastProvider");
    Release();
}

HwCastProvider::Init()
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

void HwCastProvider::Release()
{
    hwCastProviderSessionMap_.clear();
    avCastControllerMap_.clear();
    castStateListenerList_.clear();
    castFlag_.clear();
    CastSessionManager::GetInstance().UnregisterListener();
    CastSessionManager::GetInstance().Release();
}

int HwCastProvider::StartCastSession()
{
    SLOGI("StartCastSession begin");
    CastSessionProperty property = {ProtocolType::CAST_PLUS_STREAM, EndType::CAST_SOURCE};
    std::shared_ptr<ICastSession> castSession = CastSessionManager::GetInstance().CreateCastSession(property);
    int castId;
    {
        std::lock_guard<std::mutex> lock(mutex_);
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
    SLOGI("StopCastSession begin");
    std::lock_guard<std::mutex> lock(mutex_);
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

    // if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
    //     SLOGI("castId %{public}d is not exit and not need stopCastSession", castId);
    //     return;
    // }
    // if (avCastControllerMap_.find(castId) == avCastControllerMap_.end()) {
    //     SLOGE("no need to release streamPlayer for castId %{public}d is not exit in avCastControllerMap_", castId);
    //     return;
    // }
    auto hwCastStreamPlayer = avCastControllerMap_[castId];
    if (hwCastStreamPlayer) {
        hwCastStreamPlayer->Release();
    }
    avCastControllerMap_.erase(castId);
}

bool HwCastProvider::AddCastDevice(int castId, DeviceInfo deviceInfo)
{
    SLOGI("AddCastDevice with config castSession and corresonding castId is %{public}d", castId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("the castId corresonding to castSession is not exist");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (!hwCastProviderSession) {
        SLOGE("the castId corresonding to castSession is nullptr");
        return false;
    }

    return hwCastProviderSession->AddDevice(deviceInfo.deviceId_);
}

bool HwCastProvider::RemoveCastDevice(int castId, DeviceInfo deviceInfo)
{
    SLOGI("RemoveCastDevice with config castSession and corresonding castId is %{public}d", castId);
    std::lock_guard<std::mutex> lock(mutex_);
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
    std::lock_guard<std::mutex> lock(mutex_);
    if (listener == nullptr) {
        SLOGE("RegisterCastStateListener the listener is nullptr");
        return false;
    }
    if (find(castStateListenerList_begin(), castStateListenerList_.end(), listener) != castStateListenerList_.end()) {
        SLOGE("RegisterCastStateListener the listener is already be registered");
        return false;
    }
    SLOGI("RegisterCastStateListener successed, and save it in the castStateListenerList_");
    castStateListenerList_.emplace_back(listener);

    return true;
}

bool HwCastProvider::UnRegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (listener == nullptr) {
        SLOGE("UnRegisterCastStateListener the listener is nullptr");
        return false;
    }
    for (auto iter = castStateListenerList_.begin(); iter != castStateListenerList_.end();) {
        if (*iter == listener) {
            iter = castStateListenerList_.erase(iter);
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
    std::lock_guard<std::mutex> lock(mutex_);
    if (avCastControllerMap_.find(castId) != avCastControllerMap_.end()) {
        SLOGI("the castId corresonding to streamPlayer is already exist");
        return avCastControllerMap_[castId];
    }
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("No castSession corresonding to castId exists");
        return nullptr;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullPtr) {
        SLOGE("castSession corresonding to castId is nullptr");
        return nullPtr;
    }
    std::shared_ptr<IStreamPlayer> streamPlayer = hwCastProviderSession->CreateStreamPlayer();
    std::shared_ptr<HwCastStreamPlayer> hwCastStreamPlayer = std::make_shared<hwCastStreamPlayer>(streamPlayer);
    if (!hwCastStreamPlayer) {
        SLOGE("the created hwCastStreamPlayer is nullptr");
        return nullPtr;
    }
    hwCastStreamPlayer->Init();
    avCastControllerMap_[castId] = hwCastStreamPlayer;

    return hwCastStreamPlayer;
}

bool HwCastProvider::RegisterCastSessionStateListener(int castId, std::shared_ptr<IAVCastSessionStateListener> listener)
{ 
    if (listener == nullPtr) {
        SLOGE("RegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("RegisterCastSessionStateListener failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullPtr) {
        SLOGE("RegisterCastSessionStateListener failed for the hwCastProviderSession is nullptr");
        return false;
    }

    return hwCastProviderSession->RegisterCastSessionStateListener(listener);
}

bool HwCastProvider::UnRegisterCastSessionStateListener(int castId, std::shared_ptr<IAVCastSessionStateListener> listener)
{
    if (listener == nullPtr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("UnRegisterCastSessionStateListener failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullPtr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the hwCastProviderSession is nullptr");
        return false;
    }

    return hwCastProviderSession->UnRegisterCastSessionStateListener(listener);
}


void HwCastProvider::OnDeviceFound(const std::vector<CastRemoteDevice> &deviceList)
{
    std::vector<DeviceInfo> deviceInfoList;
    for (CastRemoteDevice castRemoteDevice : deviceList) {
        DeviceInfo deviceInfo;
        deviceInfo.deviceId_ = castRemoteDevice.deviceId;
        deviceInfo.deviceName_ = castRemoteDevice.deviceName;
        deviceInfo.deviceType_ = static_cast<int>(castRemoteDevice.deviceType);
        deviceInfo.ipAddress_ = castRemoteDevice.ipAddress;
        deviceInfoList.emplace_back(deviceInfo);
    }
    for (auto listener : castStateListenerList_) {
        if (listener != nullPtr) {
            SLOGI("trigger the onDeviceAvailable for registered listeners");
            listener->onDeviceAvailable(deviceInfoList);
        }
    }
}
void HwCastProvider::OnSessionCreated(const std::shared_ptr<CastEngine::ICastSession> &castSession)
{
    //Todo
}

void HwCastProvider::OnServiceDied()
{
    for (auto listener : castStateListenerList_) {
        if (listener != nullPtr) {
            SLOGI("trigger the OnServiceDied for registered listeners");
            listener->OnCastServerDied();
        }
    }
}
} // namespace OHOS::AVSession