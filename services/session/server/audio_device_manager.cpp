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

namespace OHOS::AVSession {
AudioDeviceManager &AudioDeviceManager::GetInstance()
{
    static AudioDeviceManager instance;
    return instance;
}

bool AudioDeviceManager::GetVehicleA2dpConnectState()
{
    AudioStandard::AudioSystemManager *audioSystemManager =
        AudioStandard::AudioSystemManager::GetInstance();
    std::vector<sptr<AudioStandard::AudioDeviceDescriptor>> devices =
        audioSystemManager->GetActiveOutputDeviceDescriptors();
    bool isConnected = false;
    for (auto& device : devices) {
        if (device != nullptr &&
            AudioStandard::DeviceCategory::BT_CAR == device->deviceCategory_ &&
            AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP == device->deviceType_) {
            isConnected = true;
            break;
        }
    }
    return isConnected;
}

void AudioDeviceManager::RegisterAudioDeviceChangeCallback(std::shared_ptr<MigrateAVSessionServer> migrateAVSession,
    std::string deviceId)
{
    SLOGI("enter RegisterAudioDeviceChangeCallback");
    if (isRegistered_) {
        SLOGW("device change callback already registered");
        return;
    }
    if (audioDeviceChangeCallback_ == nullptr) {
        audioDeviceChangeCallback_ = std::make_shared<DeviceChangeCallback>();
    }
    AudioStandard::AudioSystemManager *audioSystemManager =
        AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    audioSystemManager->SetDeviceChangeCallback(AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG,
        audioDeviceChangeCallback_);
    migrateSession_ = migrateAVSession;
    isRegistered_ = true;
    deviceId_ = deviceId;
}

void AudioDeviceManager::UnRegisterAudioDeviceChangeCallback()
{
    SLOGI("enter UnRegisterAudioDeviceChangeCallback");
    AudioStandard::AudioSystemManager *audioSystemManager =
        AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    audioSystemManager->UnsetDeviceChangeCallback(AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG);
    isRegistered_ = false;
}

void AudioDeviceManager::SendRemoteAvSessionInfo(const std::string &deviceId)
{
    migrateSession_->OnConnectProxy(deviceId);
}

std::string AudioDeviceManager::GetDeviceId()
{
    return deviceId_;
}

void DeviceChangeCallback::OnDeviceChange(const AudioStandard::DeviceChangeAction &deviceChangeAction)
{
    SLOGI("receive OnDeviceChange");
    AudioStandard::AudioSystemManager *audioSystemManager =
        AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    if (AudioStandard::DeviceChangeType::DISCONNECT == deviceChangeAction.type) {
        std::vector<sptr<AudioStandard::AudioDeviceDescriptor>> deviceDescriptors =
            deviceChangeAction.deviceDescriptors;
        for (auto &device : deviceDescriptors) {
            if (device != nullptr &&
                AudioStandard::DeviceCategory::BT_CAR == device->deviceCategory_ &&
                AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP == device->deviceType_) {
                AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(
                    AudioDeviceManager::GetInstance().GetDeviceId());
                break;
            }
        }
    }
}
}