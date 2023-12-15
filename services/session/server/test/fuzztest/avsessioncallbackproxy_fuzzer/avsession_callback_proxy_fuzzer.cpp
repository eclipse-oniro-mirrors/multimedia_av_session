/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <iostream>
#include <memory>

#include "avsession_callback_proxy.h"
#include "iavcontroller_callback.h"
#include "iremote_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_callback_proxy_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static const int32_t MAX_CODE_LEN = 512;
static const int32_t MAX_CODE_TEST = 13;
static const int32_t MIN_SIZE_NUM = 4;

bool AvsessionCallbackProxyFuzzer::FuzzSendRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return false;
    }

    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return false;
    }

    sptr<IRemoteObject> remoteObject = nullptr;
    std::shared_ptr<AvsessionCallbackProxyFuzzerTest> avSessionCallbackProxy =
        std::make_shared<AvsessionCallbackProxyFuzzerTest>(remoteObject);
    if (!avSessionCallbackProxy) {
        SLOGI("avSessionCallbackProxy is null");
        return false;
    }
    MessageParcel request;
    CHECK_AND_PRINT_LOG(request.WriteInterfaceToken(avSessionCallbackProxy->GetDescriptor()),
        "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC};
    auto remote = avSessionCallbackProxy->GetRemote();
    if (!remote) {
        SLOGI("remote is null");
        return false;
    }
    size -= sizeof(uint32_t);
    request.WriteBuffer(data + sizeof(uint32_t), size);
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_PRINT_LOG((result = remote->SendRequest(code, request, reply, option)) == 0, "send request failed");
    return result == AVSESSION_SUCCESS;
}

bool OHOS::AVSession::AvsessionCallbackProxySendRequestTest(uint8_t* data, size_t size)
{
    auto avSessionCallbackProxy = std::make_unique<AvsessionCallbackProxyFuzzer>();
    if (avSessionCallbackProxy == nullptr) {
        return false;
    }
    return avSessionCallbackProxy->FuzzSendRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvsessionCallbackProxySendRequestTest(const_cast<uint8_t*>(data), size);
    return 0;
}