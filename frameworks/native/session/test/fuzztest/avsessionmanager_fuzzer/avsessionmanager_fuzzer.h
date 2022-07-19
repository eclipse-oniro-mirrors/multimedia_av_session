/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSIONSERVICE_FUZZER_H
#define OHOS_AVSESSIONSERVICE_FUZZER_H

#include "avsession_log.h"
#include "avsession_manager.h"

namespace OHOS::AVSession {
bool AVSessionManagerInterfaceTest(uint8_t* data, size_t size);

static char TestBundleName[] = "test.ohos.avsession";
static char TestAbilityName[] = "test.ability";

class TestSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}s created", descriptor.sessionId_.c_str());
        descriptor_ = descriptor;
    }

    void OnSessionRelease(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}s released", descriptor.sessionId_.c_str());
        descriptor_ = descriptor;
    }

    void OnTopSessionChange(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}s be top session", descriptor.sessionId_.c_str());
    }

    std::string GetSessionId() const
    {
        return descriptor_.sessionId_;
    }

private:
    AVSessionDescriptor descriptor_;
};

class AVSessionManagerFuzzer {
public:
    AVSessionManagerFuzzer() = default;
    ~AVSessionManagerFuzzer() = default;
    bool AVSessionManagerFuzzTest(const uint8_t* data, size_t size);
};
}
#endif