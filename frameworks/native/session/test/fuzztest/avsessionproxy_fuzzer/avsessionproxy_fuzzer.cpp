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
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsessionproxy_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_LEN  = 512;
const int32_t MAX_CODE_NUM = 14;
const int32_t MIN_SIZE_NUM = 4;

bool AvsessionProxyFuzzer::FuzzSendRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return false;
    }
    uint32_t cmdCode = *(reinterpret_cast<const uint32_t*>(data));
    if (cmdCode >= MAX_CODE_NUM) {
        return false;
    }
    sptr<IRemoteObject> remoteObject = nullptr;
    std::shared_ptr<AVSessionProxyTestFuzzer> avSessionProxy = std::make_shared<AVSessionProxyTestFuzzer>(remoteObject);

    MessageParcel request;
    CHECK_AND_RETURN_RET_LOG(request.WriteInterfaceToken(avSessionProxy->GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = avSessionProxy->GetRemote();
    size -= sizeof(uint32_t);
    request.WriteBuffer(data + sizeof(uint32_t), size);
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG((result = remote->SendRequest(cmdCode, request, reply, option)) == 0, ERR_IPC_SEND_REQUEST,
        "send request failed");
    return result == AVSESSION_SUCCESS;
}

bool OHOS::AVSession::AvsessionProxySendRequestTest(uint8_t* data, size_t size)
{
    auto avsessionProxy = std::make_unique<AvsessionProxyFuzzer>();
    if (avsessionProxy == nullptr) {
        return false;
    }
    return avsessionProxy->FuzzSendRequest(data, size);
}

void OHOS::AVSession::AvsessionProxyTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    AVMetaData metaData;
    std::string strData(reinterpret_cast<const char*>(data), size);
    metaData.SetAssetId(strData);

    AVPlaybackState avState;
    int32_t state = *(reinterpret_cast<const int32_t*>(data));
    avState.SetState(state);

    int32_t cmd = *(reinterpret_cast<const int32_t*>(data));

    sptr<IRemoteObject> impl = nullptr;
    AVSessionProxy avSessionProxy(impl);
    avSessionProxy.GetAVMetaData(metaData);
    avSessionProxy.SetAVMetaData(metaData);
    avSessionProxy.GetAVPlaybackState(avState);
    avSessionProxy.SetAVPlaybackState(avState);
    avSessionProxy.AddSupportCommand(cmd);
    avSessionProxy.DeleteSupportCommand(cmd);
    avSessionProxy.GetSessionId();
    avSessionProxy.GetController();
    avSessionProxy.Activate();
    avSessionProxy.Deactivate();
    avSessionProxy.IsActive();
    avSessionProxy.Destroy();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvsessionProxySendRequestTest(data, size);
    OHOS::AVSession::AvsessionProxyTest(data, size);
    return 0;
}