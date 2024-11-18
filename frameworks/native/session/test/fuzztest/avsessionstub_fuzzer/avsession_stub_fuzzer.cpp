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
class AVSessionStubDemo;

static constexpr int32_t MAX_CODE_TEST = 30;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM  = 4;

shared_ptr<AVSessionStubDemo> g_AVSessionStubDemo(nullptr);
class AVSessionStubDemo : public AVSessionStub {
public:
    std::string GetSessionId() override { return ""; };
    std::string GetSessionType() override { return ""; };
    int32_t GetAVMetaData(AVMetaData &meta) override { return 0; };
    int32_t SetAVMetaData(const AVMetaData &meta) override { return 0; };
    int32_t SetAVCallMetaData(const AVCallMetaData &meta) override { return 0; };
    int32_t SetAVCallState(const AVCallState &avCallState) override { return 0; };
    int32_t GetAVPlaybackState(AVPlaybackState &state) override { return 0; };
    int32_t SetAVPlaybackState(const AVPlaybackState &state) override { return 0; };
    int32_t GetAVQueueItems(std::vector<AVQueueItem> &items) override { return 0; };
    int32_t SetAVQueueItems(const std::vector<AVQueueItem> &items) override { return 0; };
    int32_t GetAVQueueTitle(std::string &title) override { return 0; };
    int32_t SetAVQueueTitle(const std::string &title) override { return 0; };
    int32_t SetLaunchAbility(const OHOS::AbilityRuntime::WantAgent::WantAgent &ability) override { return 0; };
    int32_t GetExtras(OHOS::AAFwk::WantParams &extras) override { return 0; };
    int32_t SetExtras(const OHOS::AAFwk::WantParams &extras) override { return 0; };
    std::shared_ptr<AVSessionController> GetController() override { return nullptr; };
    int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback> &callback) override { return 0; };
    int32_t Activate() override { return 0; };
    int32_t Deactivate() override { return 0; };
    bool IsActive() override { return true; };
    int32_t Destroy() override { return 0; };
    int32_t AddSupportCommand(const int32_t cmd) override { return 0; };
    int32_t DeleteSupportCommand(const int32_t cmd) override { return 0; };
    int32_t SetSessionEvent(const std::string &event, const OHOS::AAFwk::WantParams &args) override { return 0; };

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> GetAVCastController() override { return nullptr; };
    int32_t ReleaseCast() override { return 0; };
    int32_t StartCastDisplayListener() override { return 0; };
    int32_t StopCastDisplayListener() override { return 0; };
    int32_t GetAllCastDisplays(std::vector<CastDisplayInfo> &castDisplays) override { return 0; };
#endif

protected:
    int32_t RegisterCallbackInner(const OHOS::sptr<IAVSessionCallback> &callback) override { return 0; };
    OHOS::sptr<IRemoteObject> GetControllerInner() override { return nullptr; };

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::sptr<IRemoteObject> GetAVCastControllerInner() override { return nullptr; };
#endif
};

void AvSessionFuzzer::FuzzOnRemoteRequest(int32_t code, const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    if (code >= MAX_CODE_TEST) {
        return;
    }
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    dataMessageParcel.WriteInterfaceToken(IAVSession::GetDescriptor());
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    int32_t ret = g_AVSessionStubDemo->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
    g_AVSessionStubDemo->Destroy();
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
    SLOGI("the maximum length of size should not be verified");
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    
    g_AVSessionStubDemo = make_shared<AVSessionStubDemo>();

    for (uint32_t i = 0; i <= MAX_CODE_TEST; i++) {
        OHOS::AVSession::AvSessionOnRemoteRequest(i, data, size);
    }
    return 0;
}