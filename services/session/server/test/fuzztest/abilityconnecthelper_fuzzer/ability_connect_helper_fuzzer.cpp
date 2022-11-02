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

#include "avsession_log.h"
#include "iremote_proxy.h"
#include "avcontroller_callback_proxy.h"
#include "iavcontroller_callback.h"
#include "iremote_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_service.h"
#include "ability_connect_helper_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_LEN  = 512;
const int32_t MIN_SIZE_NUM = 4;

void OHOS::AVSession::AbilityConnectHelperFuzzTest(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);

    AbilityConnectHelper::GetInstance().StartAbilityByCall(bundleName, abilityName);
}

void OHOS::AVSession::AbilityConnectionStubFuzzTest(uint8_t *data, size_t size)
{
    MessageParcel Parcel;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));

    AbilityConnectCallback abilityConnectCallback;
    abilityConnectCallback.OnRemoteRequest(code, Parcel, reply, option);
}

void OHOS::AVSession::AbilityConnectCallbackFuzzTest(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    OHOS::AppExecFwk::ElementName elementName;
    int resultCode = *(reinterpret_cast<const int*>(data));
    AbilityConnectCallback abilityConnectCallback;
    sptr<IRemoteObject> remoteObject = nullptr;

    abilityConnectCallback.OnAbilityConnectDone(elementName, remoteObject, resultCode);
    abilityConnectCallback.OnAbilityDisconnectDone(elementName, resultCode);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AbilityConnectHelperFuzzTest(data, size);
    OHOS::AVSession::AbilityConnectionStubFuzzTest(data, size);
    OHOS::AVSession::AbilityConnectCallbackFuzzTest(data, size);
    return 0;
}