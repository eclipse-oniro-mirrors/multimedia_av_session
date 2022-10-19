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
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_service.h"
#include "avsessionservice_fuzzer.h"
using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_LEN  = 512;
constexpr const char* TEST_BUNDLE_NAME = "test.ohos.avsession";
constexpr const char* TEST_ABILITY_NAME = "test.ability";

int32_t AVSessionServiceFuzzer::OnRemoteRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return AVSESSION_ERROR;
    }
    if (size > MAX_CODE_LEN) {
        return AVSESSION_ERROR;
    }
    MessageParcel dataMessageParcel;
    auto localDescriptor = IAVSessionService::GetDescriptor();
    if (!dataMessageParcel.WriteInterfaceToken(localDescriptor)) {
        return AVSESSION_ERROR;
    }

    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));

    size -= sizeof(uint32_t);

    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    sptr<AVSessionService> mAVSessionService = new AVSessionService(AVSESSION_SERVICE_ID);

    MessageParcel reply;
    MessageOption option;
    mAVSessionService->OnStart();
    int32_t ret = mAVSessionService->OnRemoteRequest(code, dataMessageParcel, reply, option);
    mAVSessionService->OnStop();
    return ret;
}

int32_t AVSessionServiceFuzzer::GetAllSessionDescriptorsTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return AVSESSION_ERROR;
    }
    if (size > MAX_CODE_LEN) {
        return AVSESSION_ERROR;
    }

    sptr<AVSessionService> mAVSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = mAVSessionService->GetAllSessionDescriptors(descriptors);

    AVSessionDescriptor descriptor;
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    mAVSessionService->GetSessionDescriptorsBySessionId(sessionId, descriptor);

    return ret;
}

int32_t AVSessionServiceFuzzer::CreateSessionAndControllerTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return AVSESSION_ERROR;
    }
    if (size > MAX_CODE_LEN) {
        return AVSESSION_ERROR;
    }

    int32_t type = *reinterpret_cast<const int32_t*>(data);
    std::string tag(reinterpret_cast<const char*>(data), size);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(TEST_BUNDLE_NAME);
    elementName.SetAbilityName(TEST_ABILITY_NAME);

    sptr<AVSessionService> mAVSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    auto session = mAVSessionService->CreateSessionInner(tag, type, elementName);
    if (session == nullptr) {
        return AVSESSION_ERROR;
    }
    sptr<AVSessionItem> sessionItem = (sptr<AVSessionItem>&)session;

    sptr<IRemoteObject> object = nullptr;
    int32_t ret = mAVSessionService->CreateControllerInner(sessionItem->GetSessionId(), object);

    if (!sessionItem) {
        return AVSESSION_ERROR;
    }
    mAVSessionService->HandleSessionRelease(*sessionItem);
    return ret;
}

int32_t AVSessionServiceFuzzer::RegisterTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return AVSESSION_ERROR;
    }
    if (size > MAX_CODE_LEN) {
        return AVSESSION_ERROR;
    }

    sptr<AVSessionService> mAVSessionService = new AVSessionService(AVSESSION_SERVICE_ID);

    pid_t pid = *reinterpret_cast<const pid_t*>(data);
    mAVSessionService->OnClientDied(pid);

    return AVSESSION_SUCCESS;
}

void AVSessionServiceFuzzer::OnAddSystemAbilityTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }
    if (size > MAX_CODE_LEN) {
        return;
    }

    sptr<AVSessionService> mAVSessionService = new AVSessionService(AVSESSION_SERVICE_ID);

    int32_t systemAbilityId = *reinterpret_cast<const int32_t*>(data);
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    mAVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
}

int32_t AVSessionServiceFuzzer::SendCommandTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return AVSESSION_ERROR;
    }
    if (size > MAX_CODE_LEN) {
        return AVSESSION_ERROR;
    }

    sptr<AVSessionService> mAVSessionService = new AVSessionService(AVSESSION_SERVICE_ID);

    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    if (!keyEvent) {
        SLOGI("keyEvent is null");
        return false;
    }
    int32_t keyCode = *reinterpret_cast<const int32_t*>(data);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(*reinterpret_cast<const int32_t*>(data));
    keyEvent->SetActionTime(*reinterpret_cast<const int64_t*>(data));
    auto keyItem = OHOS::MMI::KeyEvent::KeyItem();
    keyItem.SetKeyCode(*reinterpret_cast<const int32_t*>(data));
    keyItem.SetDownTime(*reinterpret_cast<const int64_t*>(data));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);
    int32_t ret = mAVSessionService->SendSystemAVKeyEvent(*keyEvent);

    AVControlCommand command;
    command.SetCommand(*reinterpret_cast<const int32_t*>(data));
    ret = mAVSessionService->SendSystemControlCommand(command);

    return ret;
}

int32_t OHOS::AVSession::AVSessionServiceRemoteRequestTest(uint8_t* data, size_t size)
{
    auto avSessionService = std::make_unique<AVSessionServiceFuzzer>();
    if (avSessionService == nullptr) {
        SLOGI("avSessionServiceFuzzer is null");
        return AVSESSION_ERROR;
    }
    return avSessionService->OnRemoteRequest(data, size);
}

int32_t OHOS::AVSession::AVSessionServiceGetAllSessionDescriptorsTest(uint8_t* data, size_t size)
{
    auto avSessionService = std::make_unique<AVSessionServiceFuzzer>();
    if (avSessionService == nullptr) {
        SLOGI("avSessionServiceFuzzer is null");
        return AVSESSION_ERROR;
    }
    return avSessionService->GetAllSessionDescriptorsTest(data, size);
}

int32_t OHOS::AVSession::AVSessionServiceCreSessionAndControllerTest(uint8_t* data, size_t size)
{
    auto avSessionService = std::make_unique<AVSessionServiceFuzzer>();
    if (avSessionService == nullptr) {
        SLOGI("avSessionServiceFuzzer is null");
        return AVSESSION_ERROR;
    }
    return avSessionService->CreateSessionAndControllerTest(data, size);
}

int32_t OHOS::AVSession::AVSessionServiceRegisterTest(uint8_t* data, size_t size)
{
    auto avSessionService = std::make_unique<AVSessionServiceFuzzer>();
    if (avSessionService == nullptr) {
        SLOGI("avSessionServiceFuzzer is null");
        return AVSESSION_ERROR;
    }
    return avSessionService->RegisterTest(data, size);
}

void OHOS::AVSession::AVSessionOnAddSystemAbilityTest(uint8_t* data, size_t size)
{
    auto avSessionService = std::make_unique<AVSessionServiceFuzzer>();
    if (avSessionService == nullptr) {
        SLOGI("avSessionServiceFuzzer is null");
        return;
    }
    avSessionService->OnAddSystemAbilityTest(data, size);
}

int32_t OHOS::AVSession::AVSessionSendCommandTest(uint8_t* data, size_t size)
{
    auto avSessionService = std::make_unique<AVSessionServiceFuzzer>();
    if (avSessionService == nullptr) {
        SLOGI("avSessionServiceFuzzer is null");
        return AVSESSION_ERROR;
    }
    return avSessionService->SendCommandTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AVSessionServiceRemoteRequestTest(data, size);
    OHOS::AVSession::AVSessionServiceGetAllSessionDescriptorsTest(data, size);
    OHOS::AVSession::AVSessionServiceCreSessionAndControllerTest(data, size);
    OHOS::AVSession::AVSessionServiceRegisterTest(data, size);
    OHOS::AVSession::AVSessionOnAddSystemAbilityTest(data, size);
    OHOS::AVSession::AVSessionSendCommandTest(data, size);
    return 0;
}