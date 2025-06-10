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

#include <cstddef>
#include <cstdint>

#include "ipc_skeleton.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_log.h"
#include "audio_info.h"
#include "avsessionserviceext_fuzzer.h"
#include "avsession_service.h"
#include "securec.h"

using namespace std;
namespace OHOS::AVSession {
static const int32_t MAX_CODE_LEN  = 512;
static const int32_t MIN_SIZE_NUM = 4;

static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos = 0;

class FuzzExtSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s created", descriptor.sessionId_.c_str());
    }

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s released", descriptor.sessionId_.c_str());
    }

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s be top session", descriptor.sessionId_.c_str());
    }

    void OnAudioSessionChecked(const int32_t uid) override
    {
        SLOGI("uid=%{public}d checked", uid);
    }
};

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

void AVSessionServiceExtFuzzer::AVSessionServiceExtFuzzTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    vector<string> states { "UNKNOWN", "IDLE", "CONNECTING" };
    vector<string> serviceNames { "Unknown", "SuperLauncher-Dual", "HuaweiCast" };
    vector<string> deviceIds { " ", "1234567", "7654321" };
    vector<string> extraInfos { "nothings", "reason", "others" };
    std::string state = states[GetData<uint8_t>() % states.size()];
    std::string serviceName = serviceNames[GetData<uint8_t>() % serviceNames.size()];
    std::string deviceId = deviceIds[GetData<uint8_t>() % deviceIds.size()];
    std::string extraInfo = extraInfos[GetData<uint8_t>() % extraInfos.size()];
    static sptr<AVSessionService> service = new AVSessionService(GetData<uint8_t>());
    service->SuperLauncher(deviceId, serviceName, extraInfo, state);
}

void AVSessionServiceExtRemoteRequest(uint8_t* data, size_t size)
{
    auto avSessionServiceExt = std::make_unique<AVSessionServiceExtFuzzer>();
    if (avSessionServiceExt == nullptr) {
        SLOGI("avSessionServiceExt is null");
        return;
    }
    avSessionServiceExt->AVSessionServiceExtFuzzTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    AVSessionServiceExtRemoteRequest(data, size);
    return 0;
}
}