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
#include "avsession_controller_stub.h"
#include "iavsession_controller.h"
#include "iremote_stub.h"
#include "avcontroller_item.h"
#include "avsession_item.h"
#include "avsession_controller.h"
#include "want_params.h"
#include "avsession_controllerstub_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_TEST = 5;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM  = 4;

void AvSessionControllerFuzzer::FuzzOnRemoteRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }
    AVSessionDescriptor descriptor;
    sptr<AVSessionItem> testAVSessionItem = new(std::nothrow) AVSessionItem(descriptor);
    if (!testAVSessionItem) {
        SLOGI("testAVSessionController is null");
        return;
    }
    int32_t pid = *(reinterpret_cast<const int32_t *>(data));
    sptr<AVControllerItem> avControllerItem = new(std::nothrow) AVControllerItem(pid, testAVSessionItem);

    if (!avControllerItem) {
        SLOGI("aVSessionController is null");
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
    int32_t ret = avControllerItem->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
}

void AvSessionControllerFuzzer::FuzzTests(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    AVSessionDescriptor descriptor;
    sptr<AVSessionItem> testAVSessionItem = new(std::nothrow) AVSessionItem(descriptor);
    if (!testAVSessionItem) {
        SLOGI("testAVSessionItem is null");
        return;
    }
    int32_t pid = *(reinterpret_cast<const int32_t *>(data));
    sptr<AVControllerItem> avControllerItem = new(std::nothrow) AVControllerItem(pid, testAVSessionItem);
    
    AVCallState avCallState;
    int32_t numberDate = *(reinterpret_cast<const int32_t*>(data));
    std::string dataToS(std::to_string(numberDate));
    int32_t callState = std::stoi(dataToS);
    avCallState.SetAVCallState(callState);
    bool mute = std::stoi(dataToS);
    avCallState.SetAVCallMuted(mute);
    avControllerItem->GetAVCallState(avCallState);

    AVCallMetaData avCallMetaData;
    std::string strCallMetaData(dataToS);
    avCallMetaData.SetName(strCallMetaData);
    avCallMetaData.SetPhoneNumber(strCallMetaData);
    avControllerItem->GetAVCallMetaData(avCallMetaData);
}


void OHOS::AVSession::AvSessionControllerOnRemoteRequest(const uint8_t* data, size_t size)
{
    auto aVSessionController = std::make_unique<AvSessionControllerFuzzer>();
    if (aVSessionController == nullptr) {
        SLOGI("aVSessionController is null");
        return;
    }
    aVSessionController->FuzzOnRemoteRequest(data, size);
}

void OHOS::AVSession::AvSessionControllerTests(const uint8_t* data, size_t size)
{
    auto aVSessionController = std::make_unique<AvSessionControllerFuzzer>();
    if (aVSessionController == nullptr) {
        SLOGI("aVSessionController is null");
        return;
    }
    aVSessionController->FuzzTests(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvSessionControllerOnRemoteRequest(data, size);
    OHOS::AVSession::AvSessionControllerTests(data, size);
    return 0;
}