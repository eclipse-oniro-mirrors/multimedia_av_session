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

#include "audio_system_manager.h"
#include "audio_device_descriptor.h"
#include "audio_device_info.h"

namespace OHOS::AVSession {
class AudioDeviceManager {
public:
    AudioDeviceManager() = default;
    ~AudioDeviceManager() = default;
    static AudioDeviceManager &GetInstance();
    bool GetVehicleA2dpConnectState();
    void RegisterAudioDeviceChangeCallback(std::shared_ptr<MigrateAVSessionServer> migrateAVSession,
        std::string deviceId);
    void UnRegisterAudioDeviceChangeCallback();
    void SendRemoteAvSessionInfo(const std::string &deviceId);
    std::string GetDeviceId();

private:
    std::shared_ptr<AudioStandard::AudioManagerDeviceChangeCallback> audioDeviceChangeCallback_;
    bool isRegistered_ = false;
    std::shared_ptr<MigrateAVSessionServer> migrateSession_;
    std::string deviceId_;
};

class DeviceChangeCallback : public AudioStandard::AudioManagerDeviceChangeCallback {
public:
    void OnDeviceChange(const AudioStandard::DeviceChangeAction& deviceChangeAction) override;
};
}
#endif