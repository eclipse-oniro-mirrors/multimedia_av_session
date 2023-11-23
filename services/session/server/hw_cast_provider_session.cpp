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

using namespace OHOS::CastEngine;

namespace OHOS::AVSession {
HwCastProviderSession::~HwCastProviderSession()
{
    SLOGI("destruct the HwCastProviderSession");
    Release();
}

void HwCastProviderSession::Init()
{
    SLOGI("Init the HwCastProviderSession");
    if (castSession_) {
        castSession_->RegisterListener(shared_from_this());
    }
}

void HwCastProviderSession::Release()
{
    SLOGI("release the HwCastProviderSession");
    if (!castSession_) {
        SLOGE("castSession_ is not exist");
        return;
    }
    self->castSession_->Release();
    self->castSession_ = nullptr;
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

    return castSession_->AddDevice(castRemoteDevice);
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

bool HwCastProviderSession::RegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener)
{
    SLOGI("RegisterCastSessionStateListener");
    if (listener == nullptr) {
        SLOGE("RegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (find(castSessionStateListenerList_.begin(), castSessionStateListenerList_.end(), listener)
        != castSessionStateListenerList_.end()) {
        SLOGE("listener is already in castSessionStateListenerList_");
        return false;
    }
    castSessionStateListenerList_.emplace_back(listener);
    SLOGD("Provider session register cast session state listener finished");
    return true;
}

bool HwCastProviderSession::UnRegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener)
{
    if (listener == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = castSessionStateListenerList_.begin(); iter != castSessionStateListenerList_.end();) {
        if (*iter == listener) {
            castSessionStateListenerList_.erase(iter);
            return true;
        } else {
            ++iter;
        }
    }

    return false;
}

void HwCastProviderSession::OnDeviceState(const CastEngine::DeviceStateInfo &stateInfo)
{
    SLOGI("OnDeviceState from cast %{public}d", static_cast<int>(stateInfo.deviceState));
    if (castSessionStateListenerList_.size() == 0) {
        SLOGI("current has not registered listener");
        return;
    }
    for (auto listener : castSessionStateListenerList_) {
        DeviceInfo deviceInfo;
        deviceInfo.deviceId_ = stateInfo.deviceId;
        deviceInfo.castCategory_ = AVCastCategory::CATEGORY_REMOTE;
        if (listener != nullptr) {
            SLOGI("trigger the OnCastStateChange for registered listeners here");
            listener->OnCastStateChange(static_cast<int>(stateInfo.deviceState), deviceInfo);
        }
    }
}

void HwCastProviderSession::OnEvent(const CastEngine::EventId &eventId, const std::string &jsonParam)
{
}
}
