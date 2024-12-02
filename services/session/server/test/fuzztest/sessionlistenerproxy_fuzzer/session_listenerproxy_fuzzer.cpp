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
#include "securec.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;

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

bool SessionListenerProxyFuzzer::FuzzSendRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
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
    request.RewindRead(GetData<uint8_t>());
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG((result = remote->SendRequest(GetData<uint8_t>(), request, reply, option)) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
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
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    OHOS::AVSession::SessionListenerProxySendRequestTest(data, size);
    return 0;
}