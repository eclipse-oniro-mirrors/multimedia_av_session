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

#include "avsession_controller_proxy_fuzzer.h"
#include <iostream>
#include <cstddef>
#include <cstdint>
#include "avsession_callback_proxy.h"
#include "avsession_controller_proxy.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_manager_impl.h"
#include "securec.h"

using namespace std;
namespace OHOS {
namespace AVSession {
static constexpr int32_t MAX_CODE_TEST  = 12;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";
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

bool AvsessionControllerProxyFuzzer::FuzzSendRequest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return false;
    }
    sptr<IRemoteObject> remoteObject = nullptr;
    std::shared_ptr<AvsessionControllerProxyFuzzerTest> avSessionProxy =
        std::make_shared<AvsessionControllerProxyFuzzerTest>(remoteObject);

    MessageParcel request;
    CHECK_AND_RETURN_RET_LOG(request.WriteInterfaceToken(avSessionProxy->GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = avSessionProxy->GetRemote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    request.WriteBuffer(RAW_DATA + sizeof(uint32_t), g_dataSize - sizeof(uint32_t));
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(
        (result = remote->SendRequest(GetData<uint32_t>() % MAX_CODE_TEST + 1, request, reply, option)) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    return result == AVSESSION_SUCCESS;
}

void AvsessionControllerProxySendRequest()
{
    auto avsessionProxy = std::make_unique<AvsessionControllerProxyFuzzer>();
    if (avsessionProxy == nullptr) {
        SLOGE("avsessionProxy is not null");
        return;
    }
    avsessionProxy->FuzzSendRequest();
}

void AvsessionControllerProxyTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    AVPlaybackState state;
    int32_t stateTemp = GetData<int32_t>();
    state.SetState(stateTemp);

    AVMetaData metaData;
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> dataTemps = { "test1", "test2", "test3" };
    std::string dataTemp(dataTemps[randomNum % dataTemps.size()]);
    metaData.SetAssetId(dataTemp);

    std::vector<int32_t> cmds;
    int32_t fuzzCmds = GetData<int32_t>();
    cmds.push_back(fuzzCmds);

    bool isActive = GetData<bool>();

    AVControlCommand controlCommand;
    int32_t cmd = GetData<int32_t>();
    controlCommand.SetCommand(cmd);

    randomNum = GetData<uint8_t>();
    std::vector<std::string> eventNames = { "event1", "event2", "event3" };
    std::string eventName(eventNames[randomNum % eventNames.size()]);
    AAFwk::WantParams wantParams;

    sptr<IRemoteObject> impl = nullptr;
    AVSessionControllerProxy avSessionControllerProxy(impl);
    avSessionControllerProxy.GetAVPlaybackState(state);
    avSessionControllerProxy.GetAVMetaData(metaData);
    avSessionControllerProxy.GetValidCommands(cmds);
    avSessionControllerProxy.IsSessionActive(isActive);
    avSessionControllerProxy.SendControlCommand(controlCommand);
    avSessionControllerProxy.SendCommonCommand(eventName, wantParams);
    avSessionControllerProxy.GetExtras(wantParams);
}

void AvsessionItemTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    std::string fuzzString(reinterpret_cast<const char*>(RAW_DATA), g_dataSize);

    int32_t type = GetData<int32_t>() % 2; // valid type 0-1
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    AAFwk::WantParams wantParams;

    // To test the server interface, the session must be legal
    std::shared_ptr <AVSession> avSession = AVSessionManager::GetInstance().CreateSession("FuzzTest", type,
        elementName);
    if (!avSession) {
        SLOGI("avSession is null");
        return;
    }
    std::shared_ptr <AVSessionController> avSessionController;
    int32_t ret = AVSessionManager::GetInstance().CreateController(avSession->GetSessionId(), avSessionController);
    if (ret != AVSESSION_SUCCESS) {
        SLOGI("CreateController fail");
        return;
    }
    if (!avSessionController) {
        SLOGI("avSessionController is null");
        return;
    }
    avSession->Activate();
    avSession->SetSessionEvent(fuzzString, wantParams);
    avSessionController->SendCommonCommand(fuzzString, wantParams);
}

typedef void (*TestFuncs[3])();

TestFuncs g_testFuncs = {
    AvsessionControllerProxySendRequest,
    AvsessionControllerProxyTest,
    AvsessionItemTest,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
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
    if (size < OHOS::AVSession::THRESHOLD) {
        return 0;
    }

    FuzzTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
