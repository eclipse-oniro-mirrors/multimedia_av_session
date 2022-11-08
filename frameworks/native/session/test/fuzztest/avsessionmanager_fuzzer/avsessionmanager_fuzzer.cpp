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
#include <string>
#include <memory>

#include "avsession_errors.h"
#include "avsession_manager_impl.h"
#include "avsessionmanager_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

constexpr int32_t MAX_CODE_LEN  = 512;
constexpr int32_t TIME = 1000;
constexpr int32_t MIN_SIZE_NUM = 4;
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";

bool AVSessionManagerFuzzer::AVSessionManagerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return false;
    }

    int32_t type = *reinterpret_cast<const int32_t *>(data);
    std::string tag(reinterpret_cast<const char *>(data), size);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);

    std::shared_ptr <AVSession> avSession = AVSessionManager::GetInstance().CreateSession(tag, type, elementName);
    if (!avSession) {
        SLOGI("avSession is null");
        return false;
    }
    std::shared_ptr <AVSessionController> avSessionController;
    int32_t ret = AVSessionManager::GetInstance().CreateController(avSession->GetSessionId(), avSessionController);
    if (ret != AVSESSION_SUCCESS) {
        SLOGI("CreateController fail");
        return false;
    }
    if (!avSessionController) {
        SLOGI("avSessionController is null");
        return false;
    }

    if (avSession != nullptr) {
        avSession->Destroy();
    }
    if (avSessionController != nullptr) {
        avSessionController->Destroy();
    }

    bool result = SendSystemControlCommandFuzzTest(data);
    return result == AVSESSION_SUCCESS;
}

bool AVSessionManagerFuzzer::SendSystemControlCommandFuzzTest(const uint8_t *data)
{
    std::shared_ptr<TestSessionListener> listener = std::make_shared<TestSessionListener>();
    if (!listener) {
        SLOGI("listener is null");
        return false;
    }
    auto result = AVSessionManager::GetInstance().RegisterSessionListener(listener);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    if (!keyEvent) {
        SLOGI("keyEvent is null");
        return false;
    }
    int32_t keyCode = *reinterpret_cast<const int32_t*>(data);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(*reinterpret_cast<const int32_t*>(data));
    keyEvent->SetActionTime(TIME);
    auto keyItem = OHOS::MMI::KeyEvent::KeyItem();
    keyItem.SetKeyCode(*reinterpret_cast<const int32_t*>(data));
    keyItem.SetDownTime(TIME);
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);
    result = AVSessionManager::GetInstance().SendSystemAVKeyEvent(*keyEvent);
    AVControlCommand command;
    command.SetCommand(*reinterpret_cast<const int32_t*>(data));
    result = AVSessionManager::GetInstance().SendSystemControlCommand(command);

    return result;
}

bool OHOS::AVSession::AVSessionManagerInterfaceTest(uint8_t* data, size_t size)
{
    auto avSessionManager = std::make_unique<AVSessionManagerFuzzer>();
    if (avSessionManager == nullptr) {
        SLOGI("avSessionManagerFuzzer is null");
        return false;
    }
    return avSessionManager->AVSessionManagerFuzzTest(data, size);
}

void OHOS::AVSession::AVSessionManagerTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        SLOGI("Invalid data");
        return;
    }

    std::vector<AVSessionDescriptor> descriptors;
    std::string avSessionId(reinterpret_cast<const char*>(data), size);
    AVSessionDescriptor avSessionDescriptor;
    avSessionDescriptor.sessionId_ = avSessionId;
    descriptors.push_back(avSessionDescriptor);

    std::string sessionId(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<AVSessionController> controller;

    std::string bySessionId(reinterpret_cast<const char*>(data), size);
    AVSessionDescriptor descriptor;

    AVControlCommand command;
    int32_t cmd = *(reinterpret_cast<const int32_t*>(data));
    command.SetCommand(cmd);

    AVSessionManagerImpl avSessionManagerImpl;
    avSessionManagerImpl.GetAllSessionDescriptors(descriptors);
    avSessionManagerImpl.CreateController(sessionId, controller);
    avSessionManagerImpl.GetActivatedSessionDescriptors(descriptors);
    avSessionManagerImpl.GetSessionDescriptorsBySessionId(bySessionId, descriptor);
    avSessionManagerImpl.SendSystemControlCommand(command);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AVSessionManagerInterfaceTest(data, size);
    OHOS::AVSession::AVSessionManagerTest(data, size);
    return 0;
}