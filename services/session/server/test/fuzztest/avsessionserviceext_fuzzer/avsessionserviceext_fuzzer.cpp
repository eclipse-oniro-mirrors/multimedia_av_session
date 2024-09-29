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

using namespace std;
namespace OHOS::AVSession {
static const int32_t MAX_CODE_LEN  = 512;
static const int32_t MIN_SIZE_NUM = 4;
static const int32_t MAX_CODE_TEST = 24;

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

void AVSessionServiceExtFuzzer::AVSessionServiceExtFuzzTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }

    vector<string> states {
        "UNKNOWN",
        "IDLE",
        "CONNECTING",
    };
    vector<string> serviceNames {
        "Unknown",
        "SuperLauncher",
        "HuaweiCast",
    };

    int32_t systemAbilityId = 1;
    static sptr<AVSessionService> service = new AVSessionService(systemAbilityId);
    
    std::string state = "CONNECTING";
    std::string serviceName = "SuperLauncher";
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string extraInfo(reinterpret_cast<const char*>(data), size);
    service->SuperLauncher(deviceId, serviceName, extraInfo, state);
    
    state = "IDLE";
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
    AVSessionServiceExtRemoteRequest(data, size);
    return 0;
}
}