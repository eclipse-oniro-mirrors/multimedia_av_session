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

#include "hw_cast_provider_session.h"
#include <thread>
#include "avsession_log.h"
#include "avsession_errors.h"

using namespace OHOS::CastEngine;

namespace OHOS::AVSession {
HwCastProviderSession::~HwCastProviderSession()
{
    SLOGI("destruct the HwCastProviderSession");
    Release();
}

int32_t HwCastProviderSession::Init()
{
    SLOGI("Init the HwCastProviderSession");
    if (castSession_) {
        return castSession_->RegisterListener(shared_from_this());
    }
    return AVSESSION_ERROR;
}

void HwCastProviderSession::Release()
{
    SLOGI("release the HwCastProviderSession");
    if (!castSession_) {
        SLOGE("castSession_ is not exist");
        return;
    }
    castSession_->Release();
    castSession_ = nullptr;
}

bool HwCastProviderSession::AddDevice(const std::string deviceId)
{
    SLOGI("AddDevice in HwCastProviderSession");
    if (!castSession_) {
        SLOGE("castSession_ is not exist");
        return false;
    }
    CastRemoteDevice castRemoteDevice = {};
    castRemoteDevice.deviceId = deviceId;

    int32_t ret = castSession_->AddDevice(castRemoteDevice);
    SLOGI("AddDevice in HwCastProviderSession with ret %{public}d", static_cast<int32_t>(ret));
    return (ret == 0) ? true : false;
}

bool HwCastProviderSession::RemoveDevice(std::string deviceId)
{
    SLOGI("RemoveDevice in HwCastProviderSession");
    if (!castSession_) {
        SLOGE("castSession_ is not exist");
        return false;
    }

    return castSession_->RemoveDevice(deviceId);
}

std::shared_ptr<CastEngine::IStreamPlayer> HwCastProviderSession::CreateStreamPlayer()
{
    SLOGI("CreateStreamPlayer in HwCastProviderSession");
    if (!castSession_) {
        SLOGE("castSession_ is not exist");
        return nullptr;
    }
    
    std::shared_ptr<CastEngine::IStreamPlayer> streamPlayerPtr = nullptr;
    castSession_->CreateStreamPlayer(streamPlayerPtr);
    return streamPlayerPtr;
}

bool HwCastProviderSession::GetRemoteNetWorkId(std::string deviceId, std::string &networkId)
{
    SLOGI("enter GetRemoteNetWorkId");
    if (!castSession_) {
        SLOGE("castSession_ is not exist");
        return false;
    }
    CastRemoteDevice castRemoteDevice = {};
    castSession_->GetRemoteDeviceInfo(deviceId, castRemoteDevice);
    networkId = castRemoteDevice.networkId;
    return true;
}

bool HwCastProviderSession::SetStreamState(DeviceInfo deviceInfo)
{
    std::lock_guard lockGuard(mutex_);
    for (auto listener : castSessionStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnCastStateChange for registered listeners");
            listener->OnCastStateChange(deviceStateConnection, deviceInfo);
        }
    }
    stashDeviceState_ = deviceStateConnection;
    stashDeviceId_ = deviceInfo.deviceId_;
    return true;
}

bool HwCastProviderSession::RegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener)
{
    SLOGI("RegisterCastSessionStateListener");
    if (listener == nullptr) {
        SLOGE("RegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    {
        std::lock_guard lockGuard(mutex_);
        if (find(castSessionStateListenerList_.begin(), castSessionStateListenerList_.end(), listener)
            != castSessionStateListenerList_.end()) {
            SLOGE("listener is already in castSessionStateListenerList_");
            return false;
        }
        castSessionStateListenerList_.emplace_back(listener);
        SLOGI("register listener finished with size %{public}d and check stash state %{public}d",
            static_cast<int>(castSessionStateListenerList_.size()), static_cast<int32_t>(stashDeviceState_));
    }
    if (stashDeviceState_ > 0) {
        DeviceInfo deviceInfo;
        deviceInfo.deviceId_ = stashDeviceId_;
        deviceInfo.deviceName_ = "RemoteCast";
        deviceInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
        if (listener != nullptr) {
            SLOGI("retry trigger the OnCastStateChange for registered listeners");
            listener->OnCastStateChange(static_cast<int>(stashDeviceState_), deviceInfo);
        }
    }
    return true;
}

bool HwCastProviderSession::UnRegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener)
{
    if (listener == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard lockGuard(mutex_);
    for (auto iter = castSessionStateListenerList_.begin(); iter != castSessionStateListenerList_.end();) {
        if (*iter == listener) {
            castSessionStateListenerList_.erase(iter);
            SLOGI("unRegister finished with size %{public}d", static_cast<int>(castSessionStateListenerList_.size()));
            return true;
        } else {
            ++iter;
        }
    }

    return false;
}

void HwCastProviderSession::OnDeviceState(const CastEngine::DeviceStateInfo &stateInfo)
{
    int32_t deviceState = static_cast<int32_t>(stateInfo.deviceState);
    std::vector<std::shared_ptr<IAVCastSessionStateListener>> tempListenerList;
    SLOGI("OnDeviceState from cast %{public}d", static_cast<int>(deviceState));
    if (stashDeviceState_ == deviceState) {
        SLOGI("duplicate devicestate");
        return;
    }
    {
        std::lock_guard lockGuard(mutex_);
        if (castSessionStateListenerList_.size() == 0) {
            SLOGI("current has not registered listener, stash state: %{public}d", deviceState);
            stashDeviceState_ = deviceState;
            stashDeviceId_ = stateInfo.deviceId;
            return;
        }
        stashDeviceState_ = -1;
        tempListenerList = castSessionStateListenerList_;
    }
    for (auto listener : tempListenerList) {
        DeviceInfo deviceInfo;
        deviceInfo.deviceId_ = stateInfo.deviceId;
        deviceInfo.deviceName_ = "RemoteCast";
        deviceInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
        if (listener != nullptr) {
            SLOGI("trigger the OnCastStateChange for ListSize %{public}d", static_cast<int>(tempListenerList.size()));
            listener->OnCastStateChange(static_cast<int>(deviceState), deviceInfo);
        }
    }
}

void HwCastProviderSession::OnEvent(const CastEngine::EventId &eventId, const std::string &jsonParam)
{
    SLOGI("OnEvent from cast with eventId %{public}d, %{public}s", eventId, jsonParam.c_str());
    std::string jsonStr = jsonParam;
    std::lock_guard lockGuard(mutex_);
    for (auto listener : castSessionStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnCastEventRecv for ListSize %{public}d",
                static_cast<int>(castSessionStateListenerList_.size()));
            listener->OnCastEventRecv(static_cast<int>(eventId), jsonStr);
        }
    }
}
}
