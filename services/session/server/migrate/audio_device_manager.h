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

#ifndef OHOS_AUDIO_DEVICE_MANAGER_H
#define OHOS_AUDIO_DEVICE_MANAGER_H

#include "audio_device_info.h"
#include "audio_routing_manager.h"
#include "bluetooth_a2dp_src.h"
#include "bluetooth_device.h"
#include "migrate_avsession_server.h"
#include "window_manager.h"
#include "window_manager_lite.h"

namespace OHOS::AVSession {
const std::map<std::pair<int, int>, AudioStandard::DeviceCategory> bluetoothDeviceCategoryMap_ = {
    {std::make_pair(Bluetooth::BluetoothDevice::MAJOR_AUDIO_VIDEO, Bluetooth::BluetoothDevice::AUDIO_VIDEO_HANDSFREE),
        AudioStandard::DeviceCategory::BT_CAR},
    {std::make_pair(Bluetooth::BluetoothDevice::MAJOR_AUDIO_VIDEO, Bluetooth::BluetoothDevice::AUDIO_VIDEO_CAR_AUDIO),
        AudioStandard::DeviceCategory::BT_CAR},
};

enum OutputDevice {
    AUDIO_OUTPUT_SINK = 0,
    AUDIO_OUTPUT_SOURCE
};

class AudioDeviceManager {
public:
    AudioDeviceManager() = default;
    ~AudioDeviceManager() = default;
    static AudioDeviceManager &GetInstance();
    bool GetSessionInfoSyncState();
    void InitAudioStateCallback(std::shared_ptr<MigrateAVSessionServer> migrateAVSession,
        std::string deviceId);
    void UnInitAudioStateCallback();
    void SendRemoteAvSessionInfo(const std::string &deviceId);
    void SendRemoteAudioMsg(const std::string &deviceId, std::string sessionId, std::string msg);
    void SetAudioState(int32_t state);
    int32_t GetAudioState();
    std::string GenerateEmptySession();
    std::string GetDeviceId();
    bool GetAppDisplayState(pid_t pid);
    bool GetAppDisplayState(std::string sessionId);
    void ProcessVirtualDisplay();
    int32_t DisconnectCarA2dp(std::string addr);
    bool GetA2dpDisconnectSub();
    void SetA2dpDisconnectSub(bool subject);
    void SetCarA2dpState(bool state);
    bool GetCarA2dpState();
    void GetAllSessionDescriptors(std::vector<AVSessionDescriptor> &descriptors);
    void SetVolumeState(bool state);
    bool GetVolumeState();
    void SendPlayCmd();

private:
    void RegisterAudioDeviceChangeCallback();
    void UnRegisterAudioDeviceChangeCallback();
    void RegisterPreferedOutputDeviceChangeCallback();
    void UnRegisterPreferedOutputDeviceChangeCallback();
    void RegisterAudioFocusChangeCallback();
    void UnRegisterAudioFocusChangeCallback();
    bool GetBtCarCategoryState(const Bluetooth::BluetoothRemoteDevice &device);
    int32_t GetAppDisplayId(uint64_t &displayId, pid_t currentPid,
        std::vector<sptr<Rosen::WindowVisibilityInfo>> infos);
    std::shared_ptr<AudioStandard::AudioManagerDeviceChangeCallback> audioDeviceChangeCallback_;
    std::shared_ptr<AudioStandard::AudioPreferredOutputDeviceChangeCallback> audioPreferedOutputDeviceChangeCallback_;
    std::shared_ptr<AudioStandard::AudioFocusInfoChangeCallback> audioFocusInfoCallback_;
    bool isRegistered_ = false;
    bool subjectDisconnect_ = false;
    bool carA2dpConnectState_ = false;
    bool setVolumeState_ = false;
    std::shared_ptr<MigrateAVSessionServer> migrateSession_;
    std::string deviceId_;
    int32_t outputDevice_ = AUDIO_OUTPUT_SINK;
};

class DeviceChangeCallback : public AudioStandard::AudioManagerDeviceChangeCallback {
public:
    void OnDeviceChange(const AudioStandard::DeviceChangeAction& deviceChangeAction) override;

private:
    void OnCarA2dpStateChange(AudioStandard::DeviceChangeType type);
};

class OutputDeviceChangeCallback : public AudioStandard::AudioPreferredOutputDeviceChangeCallback {
public:
    void OnPreferredOutputDeviceUpdated(
        const std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> &desc) override;
};

class FocusInfoChangeCallback : public AudioStandard::AudioFocusInfoChangeCallback {
public:
    void OnAudioFocusInfoChange(
        const std::list<std::pair<AudioStandard::AudioInterrupt, AudioStandard::AudioFocuState>>& infoList) override;
    void OnAudioFocusRequested(const AudioStandard::AudioInterrupt& requestedFocus) override;
    void OnAudioFocusAbandoned(const AudioStandard::AudioInterrupt& abandonFocus) override;
};
}
#endif