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
    if (!caseSession_) {
        SLOGE("caseSession_ is not exist");
        return;
    }
    castSession_->UnregisterListener();
    castSession_->Release();
}

bool HwCastProviderSession::AddDevice(std::string deviceId)
{
    SLOGI("AddDevice in HwCastProviderSession");
    if (!caseSession_) {
        SLOGE("caseSession_ is not exist");
        return false;
    }
    CastRemoteDevice castRemoteDevice = {};
    castRemoteDevice.deviceId = deviceId;

    return castSession_->AddDevice(castRemoteDevice);
}

bool HwCastProviderSession::RemoveDevice(std::string deviceId)
{
    SLOGI("RemoveDevice in HwCastProviderSession");
    if (!caseSession_) {
        SLOGE("caseSession_ is not exist");
        return false;
    }

    return castSession_->RemoveDevice();
}

std::shared_ptr<CastEngine::IStreamPlayer> HwCastProviderSession::CreateStreamPlayer()
{
    SLOGI("CreateStreamPlayer in HwCastProviderSession");
    if (!caseSession_) {
        SLOGE("caseSession_ is not exist");
        return false;
    }

    return castSession_->CreateStreamPlayer();
}

bool HwCastProviderSession::RegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener)
{
    if (listener == nullPtr) {
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

    return true;
}

bool HwCastProviderSession::UnRegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener)
{
    if (listener == nullPtr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = castSessionStateListenerList_.begin(); iter != castSessionStateListenerList_.end();) {
        if (*iter == listener) {
            iter = castSessionStateListenerList_.erase(iter);
            return true;
        } else {
            ++iter;
        }
    }

    return false;   
}

void HwCastProviderSession::OnDeviceState(const CastEngine::DeviceStateInfo &stateInfo)
{
    if (castSessionStateListenerList_.size() == 0) {
        SLOGI("current has not registered listener");
        return;
    }
    for (auto listener : castSessionStateListenerList_) {
        DeviceInfo deviceInfo;
        deviceInfo.deviceId_ = stateInfo.deviceId;
        if (listener != nullPtr) {
            SLOGI("trigger the OnCastStateChange for registered listeners");
            listener->OnCastStateChange(static_cast<int>(stateInfo.deviceState), deviceInfo);
        }
    }
}

void HwCastProviderSession::OnEvent(const CastEngine::EventId &eventId, const std::string &jsonParam)
{
    //Todo
}

}