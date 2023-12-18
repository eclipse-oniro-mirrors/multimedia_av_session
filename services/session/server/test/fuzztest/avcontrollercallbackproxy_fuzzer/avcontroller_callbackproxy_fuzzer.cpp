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

#include <iostream>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "avcontroller_callback_proxy.h"
#include "iavcontroller_callback.h"
#include "iremote_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avcontroller_callbackproxy_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static const int32_t MAX_CODE_TEST = 5;
static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;

bool AvControllerCallbackProxyFuzzer::FuzzSendRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || size < MIN_SIZE_NUM) {
        return false;
    }

    uint32_t cmdCode = *(reinterpret_cast<const uint32_t*>(data));
    if (cmdCode >= MAX_CODE_TEST) {
        return false;
    }

    sptr<IRemoteObject> remoteObject = nullptr;
    std::shared_ptr<AVControllerCallbackProxyFuzzerTest> avControllerCallbackProxy =
        std::make_shared<AVControllerCallbackProxyFuzzerTest>(remoteObject);

    if (!avControllerCallbackProxy) {
        return false;
    }
    MessageParcel parcel;
    CHECK_AND_PRINT_LOG(parcel.WriteInterfaceToken(avControllerCallbackProxy->GetDescriptor()),
        "write interface token failed");

    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    auto remote = avControllerCallbackProxy->GetRemote();
    if (remote == nullptr) {
        SLOGD("remote is null");
        return false;
    }
    size -= sizeof(uint32_t);
    parcel.WriteBuffer(data + sizeof(uint32_t), size);
    parcel.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_PRINT_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_PRINT_LOG((result = remote->SendRequest(cmdCode, parcel, reply, option)) == 0,
                        "send request failed");
    return result == AVSESSION_SUCCESS;
}

bool OHOS::AVSession::AVControllerCallbackProxySendRequest(uint8_t* data, size_t size)
{
    auto avControllerCallbackProxy = std::make_unique<AvControllerCallbackProxyFuzzer>();
    if (avControllerCallbackProxy == nullptr) {
        return false;
    }
    return avControllerCallbackProxy->FuzzSendRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AVControllerCallbackProxySendRequest(const_cast<uint8_t*>(data), size);
    return 0;
}

