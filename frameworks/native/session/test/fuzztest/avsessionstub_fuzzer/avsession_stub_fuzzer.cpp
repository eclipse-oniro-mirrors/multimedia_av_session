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
#include "avsession_stub.h"
#include "iavsession_controller.h"
#include "iremote_stub.h"
#include "avcontroller_item.h"
#include "avsession_item.h"
#include "avsession_service.h"
#include "av_session.h"
#include "want_params.h"
#include "avsession_stub_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_TEST = 30;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM  = 4;

static char g_testSessionTag[] = "test";
static std::shared_ptr<AVSessionService> g_AVSessionService;

void AvSessionFuzzer::FuzzOnRemoteRequest(int32_t code, const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    if (code >= MAX_CODE_TEST) {
        return;
    }
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
    OHOS::AppExecFwk::ElementName elementName;
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    OHOS::sptr<AVSessionItem> avSessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    if (avSessionItem == nullptr) {
        return;
    }

    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    dataMessageParcel.WriteInterfaceToken(IAVSession::GetDescriptor());
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    int32_t ret = avSessionItem->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
    avSessionItem->Destroy();
}

void OHOS::AVSession::AvSessionOnRemoteRequest(int32_t code, const uint8_t* data, size_t size)
{
    auto aVSession = std::make_unique<AvSessionFuzzer>();
    aVSession->FuzzOnRemoteRequest(code, data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    for (uint32_t i = 0; i <= MAX_CODE_TEST; i++) {
        OHOS::AVSession::AvSessionOnRemoteRequest(i, data, size);
    }
    return 0;
}