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

#include "avcontrolleritem_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "avsession_item.h"
#include "ipc_skeleton.h"
#include "avcontroller_callback_proxy.h"
#include "avsession_controller_stub.h"
#include "session_stack.cpp"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_service.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_TEST = 15;
const int32_t MAX_CODE_LEN = 512;
void AvControllerItemFuzzer::FuzzOnRemoteRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }
    if (size > MAX_CODE_LEN) {
        return;
    }
    
    std::string tag(reinterpret_cast<const char*>(data), size);
    int32_t type = *reinterpret_cast<const int32_t*>(data);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        SLOGI("avSessionItem is null");
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code > MAX_CODE_TEST) {
        return;
    }
    auto avControllerItemObj = service->CreateControllerInner(avSessionItem->GetSessionId());
    sptr<AVControllerItem> avControllerItem = (sptr<AVControllerItem>&)avControllerItemObj;
    if (!avControllerItem) {
        SLOGI("avControllerItem is null");
        return;
    }
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    if (!dataMessageParcel.WriteInterfaceToken(avControllerItem->GetDescriptor())) {
        return;
    }
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    avControllerItem->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void OHOS::AVSession::AvControllerItemRemoteRequestTest(const uint8_t* data, size_t size)
{
    auto avControllerItemFuzzer = std::make_unique<AvControllerItemFuzzer>();
    if (avControllerItemFuzzer == nullptr) {
        cout << "avControllerItemFuzzer is null" << endl;
        return;
    }
    avControllerItemFuzzer->FuzzOnRemoteRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvControllerItemRemoteRequestTest(data, size);
    return 0;
}

