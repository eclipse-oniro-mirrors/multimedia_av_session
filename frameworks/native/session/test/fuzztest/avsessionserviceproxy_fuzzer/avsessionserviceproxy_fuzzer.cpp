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
#include <memory>
#include "avsessionserviceproxy_fuzzer.h"
#include "avsession_log.h"
#include "avsession_errors.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_TEST = 8;
const int32_t MIN_SIZE_NUM = 4;

bool AVSessionServiceProxyFuzzer::FuzzSendRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return false;
    }

    uint32_t cmdCode = *(reinterpret_cast<const uint32_t*>(data));
	if (cmdCode >= MAX_CODE_TEST) {
		return false;
	}

    sptr<IRemoteObject> remoteObject = nullptr;
    std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy =
        std::make_shared<AVSessionServiceProxyFuzzerTest>(remoteObject);

    MessageParcel request;
    CHECK_AND_RETURN_RET_LOG(request.WriteInterfaceToken(avServiceProxy->GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = avServiceProxy->GetRemote();
    size -= sizeof(uint32_t);
	request.WriteBuffer(data + sizeof(uint32_t), size);
	request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG((result = remote->SendRequest(cmdCode, request, reply, option)) == 0, ERR_IPC_SEND_REQUEST,
        "send request failed");
    return result == AVSESSION_SUCCESS;
}

bool OHOS::AVSession::AVServiceProxySendRequestTest(uint8_t* data, size_t size)
{
    auto avServiceProxy = std::make_unique<AVSessionServiceProxyFuzzer>();
    if (avServiceProxy == nullptr) {
        return false;
    }
    return avServiceProxy->FuzzSendRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AVServiceProxySendRequestTest(data, size);
    return 0;
}