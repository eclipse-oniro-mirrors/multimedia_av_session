/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "audiodevicemanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>

#include "audio_device_manager.h"
#include "securec.h"
#include "avsession_service.h"

namespace OHOS {
namespace AVSession {
using namespace std;
static const int32_t MAX_CODE_LEN  = 20;
static const int32_t MIN_SIZE_NUM = 10;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_totalSize = 0;
static size_t g_sizePos;
static std::shared_ptr<OutputDeviceChangeCallback> g_outputDeviceChangeCb = nullptr;
static std::shared_ptr<DeviceChangeCallback> g_deviceChangeCb = nullptr;

/*
* describe: get data from FUZZ untrusted data(RAW_DATA) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_totalSize - g_sizePos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_sizePos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_sizePos += objectSize;
    return object;
}

std::string GetString()
{
    size_t objectSize = (GetData<int8_t>() % MAX_CODE_LEN) + 1;
    if (RAW_DATA == nullptr || objectSize > g_totalSize - g_sizePos) {
        return "OVER_SIZE";
    }
    char object[objectSize + 1];
    errno_t ret = memcpy_s(object, sizeof(object), RAW_DATA + g_sizePos, objectSize);
    if (ret != EOK) {
        return "";
    }
    g_sizePos += objectSize;
    std::string output(object);
    return output;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        SLOGE("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

using TestFuncs = void (*)();

TestFuncs g_allFuncs[] = {
    TestAudioDeviceManager,
    TestAudioDeviceManagerExt,
    TestOutputDeviceChangeCallback,
    TestDeviceChangeCallback
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    // initialize data
    RAW_DATA = rawData;
    g_totalSize = size;
    g_sizePos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_allFuncs);
    if (len > 0) {
        uint32_t index = code % len;
        if (g_allFuncs[index]) {
            g_allFuncs[index]();
        }
    } else {
        SLOGE("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}

void TestAudioDeviceManager()
{
    std::string deviceId = GetString();
    AudioDeviceManager::GetInstance().ClearRemoteAvSessionInfo(deviceId);
    AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(deviceId);
    AudioDeviceManager::GetInstance().GetDeviceId();
    AudioDeviceManager::GetInstance().GetAudioState();
    AudioDeviceManager::GetInstance().SetAudioState(GetData<int32_t>());

    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> desc;
    AudioDeviceManager::GetInstance().RegisterPreferedOutputDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioPreferedOutputDeviceChangeCallback_->OnPreferredOutputDeviceUpdated(desc);
    
    AudioStandard::DeviceChangeAction deviceChangeAction;
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_->OnDeviceChange(deviceChangeAction);
}

void TestAudioDeviceManagerExt()
{
    std::string deviceId = GetString();
    sptr<AVSessionService> avservice = new (std::nothrow) AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    if (avservice == nullptr) {
        return;
    }
    auto migrateAVSession = std::make_shared<MigrateAVSessionServer>();
    if (migrateAVSession == nullptr) {
        return;
    }

    migrateAVSession->Init(avservice);
    AudioDeviceManager::GetInstance().InitAudioStateCallback(migrateAVSession, deviceId);
    AudioDeviceManager::GetInstance().ClearRemoteAvSessionInfo(deviceId);
    AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(deviceId);
    AudioDeviceManager::GetInstance().UnInitAudioStateCallback();
    AudioDeviceManager::GetInstance().migrateSession_ = nullptr;
}

void TestOutputDeviceChangeCallback()
{
    if (g_outputDeviceChangeCb == nullptr) {
        g_outputDeviceChangeCb = std::make_shared<OutputDeviceChangeCallback>();
    }
    if (g_outputDeviceChangeCb == nullptr) {
        return;
    }

    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> descs;
    descs.push_back(nullptr);
    g_outputDeviceChangeCb->OnPreferredOutputDeviceUpdated(descs);

    auto desc = std::make_shared<AudioStandard::AudioDeviceDescriptor>();
    if (desc == nullptr) {
        return;
    }

    descs.clear();
    desc->networkId_ = AudioStandard::LOCAL_NETWORK_ID;
    descs.push_back(desc);
    AudioDeviceManager::GetInstance().SetAudioState(AUDIO_OUTPUT_SOURCE);
    g_outputDeviceChangeCb->OnPreferredOutputDeviceUpdated(descs);
    AudioDeviceManager::GetInstance().SetAudioState(AUDIO_OUTPUT_SINK);
    g_outputDeviceChangeCb->OnPreferredOutputDeviceUpdated(descs);

    descs.clear();
    desc->networkId_ = AudioStandard::REMOTE_NETWORK_ID;
    descs.push_back(desc);
    AudioDeviceManager::GetInstance().SetAudioState(AUDIO_OUTPUT_SOURCE);
    g_outputDeviceChangeCb->OnPreferredOutputDeviceUpdated(descs);
    AudioDeviceManager::GetInstance().SetAudioState(AUDIO_OUTPUT_SINK);
    g_outputDeviceChangeCb->OnPreferredOutputDeviceUpdated(descs);
}

void TestDeviceChangeCallback()
{
    if (g_deviceChangeCb == nullptr) {
        g_deviceChangeCb = std::make_shared<DeviceChangeCallback>();
    }
    if (g_deviceChangeCb == nullptr) {
        return;
    }

    AudioStandard::DeviceChangeAction deviceChangeAction;
    g_deviceChangeCb->OnDeviceChange(deviceChangeAction);

    deviceChangeAction.deviceDescriptors.push_back(nullptr);
    g_deviceChangeCb->OnDeviceChange(deviceChangeAction);

    auto desc = std::make_shared<AudioStandard::AudioDeviceDescriptor>();
    if (desc == nullptr) {
        return;
    }

    deviceChangeAction.deviceDescriptors.clear();
    desc->connectState_ = AudioStandard::ConnectState::VIRTUAL_CONNECTED;
    deviceChangeAction.deviceDescriptors.push_back(desc);
    g_deviceChangeCb->OnDeviceChange(deviceChangeAction);

    deviceChangeAction.deviceDescriptors.clear();
    desc->connectState_ = AudioStandard::ConnectState::CONNECTED;
    deviceChangeAction.deviceDescriptors.push_back(desc);
    g_deviceChangeCb->OnDeviceChange(deviceChangeAction);

    deviceChangeAction.deviceDescriptors.clear();
    desc->connectState_ = AudioStandard::ConnectState::CONNECTED;
    deviceChangeAction.type = AudioStandard::DeviceChangeType::DISCONNECT;
    desc->deviceType_ = AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP;
    desc->deviceCategory_ = AudioStandard::DeviceCategory::BT_CAR;
    deviceChangeAction.deviceDescriptors.push_back(desc);
    g_deviceChangeCb->OnDeviceChange(deviceChangeAction);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }
    /* Run your code on data */
    FuzzTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
