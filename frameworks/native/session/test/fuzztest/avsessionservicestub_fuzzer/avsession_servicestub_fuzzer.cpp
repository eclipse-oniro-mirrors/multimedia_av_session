/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_service_stub.h"
#include "iavsession_controller.h"
#include "iremote_stub.h"
#include "avcontroller_item.h"
#include "avsession_item.h"
#include "avsession_service.h"
#include "want_params.h"
#include "avsession_servicestub_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_TEST = 5;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM  = 4;

void AvSessionServiceFuzzer::FuzzOnRemoteRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    
    if (!avSessionService) {
        SLOGI("avSessionService is null");
        return;
    }

    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    if (!dataMessageParcel.WriteInterfaceToken(avSessionService->GetDescriptor())) {
        return;
    }
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    int32_t ret = avSessionService->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
}

void AvSessionServiceFuzzer::FuzzTests(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!avSessionService) {
        SLOGI("avSessionService is null");
        return;
    }
}


void OHOS::AVSession::AvSessionServiceOnRemoteRequest(const uint8_t* data, size_t size)
{
    auto aVSessionService = std::make_unique<AvSessionServiceFuzzer>();
    if (aVSessionService == nullptr) {
        SLOGI("aVSessionService is null");
        return;
    }
    aVSessionService->FuzzOnRemoteRequest(data, size);
}

void OHOS::AVSession::AvSessionServiceTests(const uint8_t* data, size_t size)
{
    auto aVSessionService = std::make_unique<AvSessionServiceFuzzer>();
    if (aVSessionService == nullptr) {
        SLOGI("aVSessionService is null");
        return;
    }
    aVSessionService->FuzzTests(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvSessionServiceOnRemoteRequest(data, size);
    OHOS::AVSession::AvSessionServiceTests(data, size);
    return 0;
}