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
#include "avcall_meta_data.h"
#include "avcall_state.h"
#include "avsessionproxy_fuzzer.h"
#include "securec.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MAX_CODE_NUM = 14;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t *RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

/*
* describe: get data from outside untrusted data(RAW_DATA) which size is according to sizeof(T)
* tips: only support basic type
*/
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

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        SLOGI("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

bool AvsessionProxyFuzzer::FuzzSendRequest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return false;
    }
    uint32_t cmdCode = GetData<uint32_t>();
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
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    request.WriteBuffer(RAW_DATA + sizeof(uint32_t), g_dataSize - sizeof(uint32_t));
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG((result = remote->SendRequest(cmdCode, request, reply, option)) == 0, ERR_IPC_SEND_REQUEST,
        "send request failed");
    return result == AVSESSION_SUCCESS;
}

void OHOS::AVSession::AvsessionProxySendRequestTest()
{
    auto avsessionProxy = std::make_unique<AvsessionProxyFuzzer>();
    if (avsessionProxy == nullptr) {
        return;
    }
    avsessionProxy->FuzzSendRequest();
}

void OHOS::AVSession::AvsessionProxyTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }

    AVMetaData metaData;
    uint8_t randomData = GetData<uint8_t>();
    std::vector<std::string> strDatas = { "assetId1", "assetId2", "assetId3" };
    metaData.SetAssetId(strDatas[randomData % strDatas.size()]);

    AVPlaybackState avState;
    int32_t state = GetData<int32_t>();
    avState.SetState(state);

    AVCallMetaData callMetaData;
    int32_t numberDate = GetData<int32_t>();
    std::string dataToS(std::to_string(numberDate));
    std::string strCallMetaData(dataToS);
    callMetaData.SetName(strCallMetaData);
    callMetaData.SetPhoneNumber(strCallMetaData);

    AVCallState avCallState;
    int32_t callState = std::stoi(dataToS);
    avCallState.SetAVCallState(callState);
    bool mute = std::stoi(dataToS);
    avCallState.SetAVCallMuted(mute);

    int32_t cmd = GetData<int32_t>();
    AAFwk::WantParams wantParams;

    sptr<IRemoteObject> impl = nullptr;
    AVSessionProxy avSessionProxy(impl);
    avSessionProxy.SetAVCallMetaData(callMetaData);
    avSessionProxy.SetAVCallState(avCallState);
    avSessionProxy.GetAVMetaData(metaData);
    avSessionProxy.SetAVMetaData(metaData);
    avSessionProxy.GetAVPlaybackState(avState);
    avSessionProxy.SetAVPlaybackState(avState);
    avSessionProxy.SetExtras(wantParams);
    avSessionProxy.AddSupportCommand(cmd);
    avSessionProxy.DeleteSupportCommand(cmd);
    avSessionProxy.GetSessionId();
    avSessionProxy.GetController();
    avSessionProxy.Activate();
    avSessionProxy.Deactivate();
    avSessionProxy.IsActive();
    avSessionProxy.Destroy();
}

typedef void (*TestFuncs[2])();

TestFuncs g_testFuncs = {
    AvsessionProxySendRequestTest,
    AvsessionProxyTest,
};

static bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        SLOGI("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < THRESHOLD) {
        return 0;
    }

    FuzzTest(data, size);
    return 0;
}