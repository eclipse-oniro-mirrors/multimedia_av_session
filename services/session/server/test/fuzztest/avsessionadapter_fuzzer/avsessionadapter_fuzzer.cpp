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

#include "avsessionadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>

#include "audio_adapter.h"
#include "avsession_users_manager.h"
#include "collaboration_manager.h"
#include "securec.h"

namespace OHOS {
namespace AVSession {
using namespace std;
static const int32_t MAX_CODE_LEN  = 20;
static const int32_t MIN_SIZE_NUM = 10;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_totalSize = 0;
static size_t g_sizePos;

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

typedef void (*TestFuncs[4])();

TestFuncs g_allFuncs = {
    AVSessionUsersManagerTest,
    AVSessionAudioAdapterTest,
    CollaborationManagerTest,
    PluginLibTest,
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
        g_allFuncs[code % len]();
    } else {
        SLOGE("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}

void AVSessionUsersManagerTest()
{
    AVSessionUsersManager::GetInstance().Init();
}

void AVSessionAudioAdapterTest()
{
    AudioAdapter audioAdapter;
    audioAdapter.is2in1_ = GetData<bool>();

    audioAdapter.MuteAudioStream(GetData<int32_t>(), GetData<int32_t>());
    audioAdapter.UnMuteAudioStream(GetData<int32_t>());
    audioAdapter.UnMuteAudioStream(GetData<int32_t>(), static_cast<AudioStandard::StreamUsage>(GetData<int32_t>()));
    audioAdapter.MuteAudioStream(GetData<int32_t>(), static_cast<AudioStandard::StreamUsage>(GetData<int32_t>()));

    DeviceChangeAction deviceChangeAction;
    audioAdapter.OnDeviceChange(deviceChangeAction);
    audioAdapter.deviceChangeListeners_ =
        std::vector<OHOS::AVSession::AudioAdapter::PreferOutputDeviceChangeListener>();
    AudioDeviceDescriptors deviceDescriptors;
    audioAdapter.OnPreferredOutputDeviceUpdated(deviceDescriptors);

    audioAdapter.SetVolume(GetData<int32_t>());
    audioAdapter.GetVolume();
    audioAdapter.RegisterVolumeKeyEventCallback([](int32_t)->void {});
    audioAdapter.UnregisterVolumeKeyEventCallback();
    audioAdapter.GetAvailableDevices();
    audioAdapter.UnsetAvailableDeviceChangeCallback();
    audioAdapter.GetDevices();
    audioAdapter.GetPreferredOutputDeviceForRendererInfo();
    audioAdapter.UnsetPreferredOutputDeviceChangeCallback();
    AudioDeviceDescriptorWithSptr desc;
    audioAdapter.FindRenderDeviceForUsage(deviceDescriptors, desc);
}

void CollaborationManagerTest()
{
    CollaborationManager::GetInstance().SendCollaborationOnStop([]()->void {});
    CollaborationManager::GetInstance().SendCollaborationApplyResult([](int32_t)->void {});
}

void PluginLibTest()
{
    auto pluginLib = std::make_shared<PluginLib>(GetString());
    pluginLib->LogDlfcnErr(GetString());
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
