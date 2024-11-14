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
}