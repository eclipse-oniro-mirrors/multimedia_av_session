/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software.
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <iostream>
#include <memory>
#include "avsession_log.h"
#include "avsession_errors.h"
#include "session_listener_proxy.h"
#include "session_listenerproxy_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_LEN = 512;
const int32_t MAX_CODE_NUM  = 3;
const int32_t MIN_SIZE_NUM = 4;

bool SessionListenerProxyFuzzer::FuzzSendRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return false;
    }
    uint32_t cmdCode = *(reinterpret_cast<const uint32_t*>(data));
    if (cmdCode >= MAX_CODE_NUM) {
        return false;
    }
    sptr<IRemoteObject> remoteObject = nullptr;
    std::shared_ptr<SessionListenerProxyFUzzerTest> sessionListenerProxy =
        std::make_shared<SessionListenerProxyFUzzerTest>(remoteObject);
    MessageParcel request;
    CHECK_AND_RETURN_RET_LOG(request.WriteInterfaceToken(sessionListenerProxy->GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = sessionListenerProxy->GetRemote();
    size -= sizeof(uint32_t);
    request.WriteBuffer(data + sizeof(uint32_t), size);
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG((result = remote->SendRequest(cmdCode, request, reply, option)) == 0, ERR_IPC_SEND_REQUEST,
        "send request failed");
    return result == AVSESSION_SUCCESS;
}

bool OHOS::AVSession::SessionListenerProxySendRequestTest(uint8_t* data, size_t size)
{
    auto sessionListenerProxy = std::make_unique<SessionListenerProxyFuzzer>();
    if (sessionListenerProxy == nullptr) {
        return false;
    }
    return sessionListenerProxy->FuzzSendRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::SessionListenerProxySendRequestTest(data, size);
    return 0;
}