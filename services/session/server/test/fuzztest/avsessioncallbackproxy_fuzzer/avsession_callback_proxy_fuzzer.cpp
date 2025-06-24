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

#include "securec.h"
#include "av_session_callback_proxy.h"
#include "iavcontroller_callback.h"
#include "iremote_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_callback_proxy_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static const int32_t MAX_CODE_TEST = 13;
static const int32_t MIN_SIZE_NUM = 10;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_totalSize = 0;
static size_t g_sizePos;

namespace {
    /*
    * describe: get data from FUZZ untrusted data(RAW_DATA) which size is according to sizeof(T)
    * tips: only support basic type
    */
    template<class T>
    T GetData()
    {
        T object {};
        size_t objectSize = sizeof(object);
        if (RAW_DATA == nullptr || objectSize > g_totalSize - g_sizePos) {
            return object;
        }
        errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_sizePos, objectSize);
        if (ret != EOK) {
            return {};
        }
        g_sizePos += objectSize;
        return object;
    }

    template<class T>
    uint32_t GetArrLength(T& arr)
    {
        if (arr == nullptr) {
            SLOGE("%{public}s: The array length is equal to 0", __func__);
            return 0;
        }
        return sizeof(arr) / sizeof(arr[0]);
    }

    typedef void (*TestFuncs[1])();

    TestFuncs g_allFuncs = {
        AvsessionCallbackProxySendRequestTest
    };

    bool FuzzTest(const uint8_t* rawData, size_t size)
    {
        if (rawData == nullptr) {
            return false;
        }

        // initialize data
        RAW_DATA = rawData;
        g_totalSize = size;
        g_sizePos = 0;

        uint32_t code = GetData<uint32_t>();
        uint32_t len = GetArrLength(g_allFuncs);
        if (len > 0) {
            g_allFuncs[code % len]();
        } else {
            SLOGE("%{public}s: The len length is equal to 0", __func__);
        }

        return true;
    }
}

bool AvsessionCallbackProxyFuzzer::FuzzSendRequest()
{
    uint32_t code = GetData<uint32_t>();
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
    request.WriteBuffer(RAW_DATA, g_sizePos);
    g_sizePos += sizeof(uint32_t);
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_PRINT_LOG((result = remote->SendRequest(code, request, reply, option)) == 0, "send request failed");
    return result == AVSESSION_SUCCESS;
}

void OHOS::AVSession::AvsessionCallbackProxySendRequestTest()
{
    auto avSessionCallbackProxy = std::make_unique<AvsessionCallbackProxyFuzzer>();
    if (avSessionCallbackProxy == nullptr) {
        return;
    }
    avSessionCallbackProxy->FuzzSendRequest();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }
    /* Run your code on data */
    FuzzTest(data, size);
    return 0;
}