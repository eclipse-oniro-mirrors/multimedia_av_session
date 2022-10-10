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

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include "avsession_item.h"
#include "iav_session.h"
#include "iremote_stub.h"
#include "avsession_stub.h"
#include "avsession_callback_proxy.h"
#include "avsession_controller_stub.h"
#include "avsession_service.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsessionitem_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_TEST  = 14;
const int32_t MAX_CODE_LEN  = 512;
const int32_t MIN_SIZE_NUM = 4;

void AvSessionItemFuzzer::AvSessionItemFuzzerTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }
    std::string tag(reinterpret_cast<const char*>(data), size);
    int32_t type = *reinterpret_cast<const int32_t*>(data);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);

    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        SLOGI("avSessionItem is null");
        return;
    }
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    if (!dataMessageParcel.WriteInterfaceToken(IAVSession::GetDescriptor())) {
        return;
    }
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    avSessionItem->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void OHOS::AVSession::AvSessionItemOnRemoteRequest(uint8_t* data, size_t size)
{
    auto avSessionItem = std::make_unique<AvSessionItemFuzzer>();
    if (avSessionItem == nullptr) {
        SLOGI("avSessionItem is null");
        return;
    }
    avSessionItem->AvSessionItemFuzzerTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvSessionItemOnRemoteRequest(const_cast<uint8_t*>(data), size);
    return 0;
}