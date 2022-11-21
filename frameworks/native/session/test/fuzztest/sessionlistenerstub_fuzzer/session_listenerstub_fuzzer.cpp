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

#include <iostream>

#include "avsession_log.h"
#include "avsession_errors.h"
#include "session_listener_client.h"
#include "session_listenerstub_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

constexpr int32_t MAX_CODE_LEN  = 512;
constexpr int32_t MAX_CODE_NUM = 3;
constexpr int32_t MIN_SIZE_NUM = 4;

int32_t SessionListenerStubFuzzer::OnRemoteRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_NUM) {
        return 0;
    }

    size -= sizeof(uint32_t);
    std::shared_ptr<TestSessionListener> testSessionListener = std::make_shared<TestSessionListener>();
    sptr<SessionListenerClient> sessionListenerStubClient = new SessionListenerClient(testSessionListener);
    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(sessionListenerStubClient->GetDescriptor())) {
        return AVSESSION_ERROR;
    }
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = sessionListenerStubClient->OnRemoteRequest(code, dataMessageParcel, reply, option);
    return ret;
}

int32_t OHOS::AVSession::SessionListenerStubRemoteRequestTest(uint8_t* data, size_t size)
{
    auto sessionListenerStub = std::make_unique<SessionListenerStubFuzzer>();
    if (sessionListenerStub == nullptr) {
        return false;
    }
    return sessionListenerStub->OnRemoteRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::SessionListenerStubRemoteRequestTest(data, size);
    return 0;
}
