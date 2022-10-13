/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_SESSIONLISTENERSTUB_FUZZER_H
#define OHOS_SESSIONLISTENERSTUB_FUZZER_H
#include "avsession_info.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
class TestSessionListener : public SessionListener{
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("Enter into TestSessionListener::OnSessionCreate.");
    }

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("Enter into TestSessionListener::OnSessionRelease.");
    }

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("Enter into TestSessionListener::OnTopSessionChange.");
    }
};
int32_t SessionListenerStubRemoteRequestTest(uint8_t* data, size_t size);

class SessionListenerStubFuzzer {
public:
    SessionListenerStubFuzzer() = default;
    ~SessionListenerStubFuzzer() = default;
    int32_t OnRemoteRequest(uint8_t* data, size_t size);
};
}
#endif
