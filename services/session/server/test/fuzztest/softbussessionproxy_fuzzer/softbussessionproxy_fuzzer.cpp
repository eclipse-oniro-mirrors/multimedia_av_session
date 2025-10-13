/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "avsession_log.h"
#include "softbussessionproxy_fuzzer.h"
#include "softbus_session_proxy.h"
#include "securec.h"

using namespace std;
namespace OHOS::AVSession {
static const int32_t MIN_SIZE_NUM = 4;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos || g_pos > g_dataSize - objectSize) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

void SoftbusSessionProxyFuzzer::ConnectServerFuzzTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    auto softbusSessionProxy = std::make_unique<SoftbusSessionProxy>();
    CHECK_AND_RETURN(softbusSessionProxy != nullptr);
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    softbusSessionProxy->ConnectServer(socket);
    softbusSessionProxy->DisconnectServer(socket);
}

typedef void (*TestFuncs[1])();

TestFuncs g_allFuncs = {
    SoftbusSessionProxyFuzzer::ConnectServerFuzzTest,
};

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    SLOGI("the maximum length of size should not be verified");
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    return 0;
}
}