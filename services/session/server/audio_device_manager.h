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
#include "migrate_avsession_server.h"
 
namespace OHOS::AVSession {
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
    void ClearRemoteAvSessionInfo(const std::string &deviceId);
    void SetAudioState(int32_t state);
    int32_t GetAudioState();
    std::string GetDeviceId();
 
private:
    void RegisterPreferedOutputDeviceChangeCallback();
    void UnRegisterPreferedOutputDeviceChangeCallback();
    void RegisterAudioDeviceChangeCallback();
    int32_t UnRegisterAudioDeviceChangeCallback();
    std::shared_ptr<AudioStandard::AudioPreferredOutputDeviceChangeCallback> audioPreferedOutputDeviceChangeCallback_;
    std::shared_ptr<AudioStandard::AudioManagerDeviceChangeCallback> audioDeviceChangeCallback_;

    bool isRegistered_ = false;
    std::shared_ptr<MigrateAVSessionServer> migrateSession_;
    std::string deviceId_;
    int32_t outputDevice_ = AUDIO_OUTPUT_SOURCE;
};

class OutputDeviceChangeCallback : public AudioStandard::AudioPreferredOutputDeviceChangeCallback {
public:
    void OnPreferredOutputDeviceUpdated(
        const std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> &desc) override;
private:
    std::recursive_mutex lock_;
};
 
class DeviceChangeCallback : public AudioStandard::AudioManagerDeviceChangeCallback {
public:
    void OnDeviceChange(const AudioStandard::DeviceChangeAction &deviceChangeAction) override;
};
}
#endif