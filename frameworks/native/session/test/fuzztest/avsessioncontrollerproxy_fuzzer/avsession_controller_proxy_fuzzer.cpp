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

using namespace std;
namespace OHOS {
namespace AVSession {
static constexpr int32_t MAX_CODE_TEST  = 12;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";

bool AvsessionControllerProxyFuzzer::FuzzSendRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return false;
    }

    uint32_t cmdCode = *(reinterpret_cast<const uint32_t*>(data));
    if (cmdCode >= MAX_CODE_TEST) {
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
    size -= sizeof(uint32_t);
    request.WriteBuffer(data + sizeof(uint32_t), size);
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG((result = remote->SendRequest(cmdCode, request, reply, option)) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    return result == AVSESSION_SUCCESS;
}

bool AvsessionControllerProxySendRequest(uint8_t* data, size_t size)
{
    auto avsessionProxy = std::make_unique<AvsessionControllerProxyFuzzer>();
    CHECK_AND_RETURN_RET_LOG(avsessionProxy != nullptr, false, "avsessionProxy is null");
    return avsessionProxy->FuzzSendRequest(data, size);
}

void AvsessionControllerProxyTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    AVPlaybackState state;
    int32_t stateTemp = *(reinterpret_cast<const int32_t*>(data));
    state.SetState(stateTemp);

    AVMetaData metaData;
    std::string dataTemp(reinterpret_cast<const char*>(data), size);
    metaData.SetAssetId(dataTemp);

    std::vector<int32_t> cmds;
    int32_t fuzzCmds = *(reinterpret_cast<const int32_t*>(data));
    cmds.push_back(fuzzCmds);

    bool isActive = *(reinterpret_cast<const bool*>(data));

    AVControlCommand controlCommand;
    int32_t cmd = *(reinterpret_cast<const int32_t*>(data));
    controlCommand.SetCommand(cmd);

    std::string eventName(reinterpret_cast<const char*>(data), size);
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

void AvsessionItemTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    std::string fuzzString(reinterpret_cast<const char*>(data), size);

    int32_t type = (*reinterpret_cast<const int32_t *>(data)) % 2; // valid type 0-1
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

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    AvsessionControllerProxySendRequest(data, size);
    AvsessionControllerProxyTest(data, size);
    AvsessionItemTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
