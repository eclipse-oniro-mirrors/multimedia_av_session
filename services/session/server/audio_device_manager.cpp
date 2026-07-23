/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "audio_device_manager.h"
#include "avsession_log.h"
#include "migrate_avsession_constant.h"

namespace OHOS::AVSession {
AudioDeviceManager &AudioDeviceManager::GetInstance()
{
    static AudioDeviceManager instance;
    return instance;
}

bool AudioDeviceManager::GetSessionInfoSyncState()
{
    std::lock_guard lockGuard(audioDeviceLock_);
    return AUDIO_OUTPUT_SOURCE == outputDevice_;
}

void AudioDeviceManager::InitAudioStateCallback(std::shared_ptr<MigrateAVSessionServer> migrateAVSession,
    std::string deviceId)
{
    SLOGI("enter InitAudioStateCallback");
    {
        std::lock_guard lockGuard(audioDeviceLock_);
        if (isRegistered_) {
            SLOGW("device change callback already registered");
            return;
        }
        if (preferredOutputDeviceChangeCallback_ == nullptr) {
            preferredOutputDeviceChangeCallback_ = std::make_shared<OutputDeviceChangeCallback>();
        }
        migrateSession_ = migrateAVSession;
        isRegistered_ = true;
        deviceId_ = deviceId;
    }

    AudioAdapter::GetInstance().AddPreferredOutputDeviceChangeCallback(preferredOutputDeviceChangeCallback_);
    RegisterAudioDeviceChangeCallback();
}

void AudioDeviceManager::UnInitAudioStateCallback()
{
    AudioAdapter::GetInstance().RemovePreferredOutputDeviceChangeCallback(preferredOutputDeviceChangeCallback_);
    UnRegisterAudioDeviceChangeCallback();
    {
        std::lock_guard lockGuard(audioDeviceLock_);
        preferredOutputDeviceChangeCallback_ = nullptr;
        audioDeviceChangeCallback_ = nullptr;
        isRegistered_ = false;
        outputDevice_ = AUDIO_OUTPUT_SOURCE;
    }
}

void AudioDeviceManager::RegisterAudioDeviceChangeCallback()
{
    SLOGI("enter RegisterAudioDeviceChangeCallback");
    if (audioDeviceChangeCallback_ == nullptr) {
        audioDeviceChangeCallback_ = std::make_shared<DeviceChangeCallback>();
    }
    AudioStandard::AudioSystemManager *audioSystemManager = AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    audioSystemManager->SetDeviceChangeCallback(
        AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG, audioDeviceChangeCallback_);
}

int32_t AudioDeviceManager::UnRegisterAudioDeviceChangeCallback()
{
    SLOGI("enter UnRegisterAudioDeviceChangeCallback");
    AudioStandard::AudioSystemManager *audioSystemManager = AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return AVSESSION_ERROR;
    }
    return audioSystemManager->UnsetDeviceChangeCallback(AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG);
}

void AudioDeviceManager::SendRemoteAvSessionInfo(const std::string &deviceId)
{
    if (migrateSession_ != nullptr) {
        migrateSession_->SendRemoteControllerList(deviceId);
        migrateSession_->SendRemoteHistorySessionList(deviceId);
    }
}

void AudioDeviceManager::ClearRemoteAvSessionInfo(const std::string &deviceId)
{
    if (migrateSession_ != nullptr) {
        migrateSession_->ClearRemoteControllerList(deviceId);
        migrateSession_->ClearRemoteHistorySessionList(deviceId);
    }
}

std::string AudioDeviceManager::GetDeviceId()
{
    std::lock_guard lockGuard(audioDeviceLock_);
    return deviceId_;
}

int32_t AudioDeviceManager::GetAudioState()
{
    std::lock_guard lockGuard(audioDeviceLock_);
    return outputDevice_;
}

void AudioDeviceManager::SetAudioState(int32_t state)
{
    SLOGI("current set audio is %{public}d", state);
    std::lock_guard lockGuard(audioDeviceLock_);
    outputDevice_ = state;
}

void OutputDeviceChangeCallback::OnPreferredOutputDeviceUpdated(
    const std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> &desc)
{
    SLOGI("receive OnPreferredOutputDeviceUpdated");
    if (desc.empty()) {
        SLOGE("device is empty");
        return;
    }

    auto deviceDesc = desc[0];
    if (deviceDesc == nullptr) {
        SLOGE("device is null");
        return;
    }
    std::lock_guard lockGuard(lock_);
    std::string deviceId = AudioDeviceManager::GetInstance().GetDeviceId();
    if (AudioStandard::LOCAL_NETWORK_ID == deviceDesc->networkId_) {
        if (AudioDeviceManager::GetInstance().GetAudioState() == AUDIO_OUTPUT_SOURCE) {
            return;
        }
        AudioDeviceManager::GetInstance().ClearRemoteAvSessionInfo(deviceId);
        AudioDeviceManager::GetInstance().SetAudioState(AUDIO_OUTPUT_SOURCE);
    } else {
        if (AudioDeviceManager::GetInstance().GetAudioState() == AUDIO_OUTPUT_SINK) {
            return;
        }
        SLOGI("receive OnPreferredOutputDeviceUpdated send remote session");
        AudioDeviceManager::GetInstance().SetAudioState(AUDIO_OUTPUT_SINK);
        AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(deviceId);
    }
}

void DeviceChangeCallback::OnDeviceChange(const AudioStandard::DeviceChangeAction &deviceChangeAction)
{
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> descs = deviceChangeAction.deviceDescriptors;
    if (descs.size() == 0) {
        SLOGE("callback device list is null");
        return;
    }
    std::shared_ptr<AudioStandard::AudioDeviceDescriptor> desc = deviceChangeAction.deviceDescriptors[0];
    if (desc == nullptr) {
        SLOGE("desc is null");
        return;
    }
    if (AudioStandard::ConnectState::VIRTUAL_CONNECTED == desc->connectState_) {
        SLOGI("receive OnDeviceChange VIRTUAL_CONNECTED");
        return;
    }
    bool isConnect = AudioStandard::DeviceChangeType::CONNECT == deviceChangeAction.type;
    if (!isConnect && AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP == desc->deviceType_ &&
        AudioStandard::DeviceCategory::BT_CAR == desc->deviceCategory_) {
        SLOGI("car a2dp offline send avdata");
        std::string deviceId = AudioDeviceManager::GetInstance().GetDeviceId();
        AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(deviceId);
    }
}
}