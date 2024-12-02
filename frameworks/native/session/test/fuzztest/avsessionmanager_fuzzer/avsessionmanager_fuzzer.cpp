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

#include "avsessionmanager_fuzzer.h"
#include <string>
#include <memory>
#include "avsession_errors.h"
#include "avsession_manager_impl.h"
#include "securec.h"

using namespace std;
namespace OHOS {
namespace AVSession {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t TIME = 1000;
static constexpr int32_t MIN_SIZE_NUM = 4;
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";
static const uint8_t *RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

/*
* describe: get data from outside untrusted data(RAW_DATA) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        SLOGI("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

bool AVSessionManagerFuzzer::AVSessionManagerFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return false;
    }

    int32_t type = GetData<int32_t>();
    int8_t random = GetData<int8_t>();
    std::vector<std::string> tags = { "tag1", "tag2", "tag3" };
    std::string tag(tags[random % tags.size()]);
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

    bool result = SendSystemControlCommandFuzzTest();
    return result == AVSESSION_SUCCESS;
}

bool AVSessionManagerFuzzer::SendSystemControlCommandFuzzTest()
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
    int32_t keyCode = GetData<int32_t>();
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(GetData<int32_t>());
    keyEvent->SetActionTime(TIME);
    auto keyItem = OHOS::MMI::KeyEvent::KeyItem();
    keyItem.SetKeyCode(GetData<int32_t>());
    keyItem.SetDownTime(TIME);
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);
    result = AVSessionManager::GetInstance().SendSystemAVKeyEvent(*keyEvent);
    AVControlCommand command;
    command.SetCommand(GetData<int32_t>());
    result = AVSessionManager::GetInstance().SendSystemControlCommand(command);

    return result;
}

void AVSessionManagerInterfaceTest()
{
    auto avSessionManager = std::make_unique<AVSessionManagerFuzzer>();
    if (avSessionManager == nullptr) {
        SLOGI("avSessionManagerFuzzer is null");
        return;
    }
    avSessionManager->AVSessionManagerFuzzTest();
}

void AVSessionManagerTestClient()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        SLOGI("Invalid data");
        return;
    }

    std::vector<AVSessionDescriptor> descriptors;
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> sessionIds = { "session1", "session2", "session3" };
    std::string avSessionId(sessionIds[randomNum % sessionIds.size()]);
    AVSessionDescriptor avSessionDescriptor;
    avSessionDescriptor.sessionId_ = avSessionId;
    descriptors.push_back(avSessionDescriptor);

    randomNum = GetData<uint8_t>();
    std::string sessionId(sessionIds[randomNum % sessionIds.size()]);
    std::shared_ptr<AVSessionController> controller;

    std::string bySessionId(sessionIds[randomNum % sessionIds.size()]);
    AVSessionDescriptor descriptor;
    int32_t maxSize = GetData<int32_t>() % 11; // valid size 0~10
    AVControlCommand command;
    int32_t cmd = GetData<int32_t>();
    command.SetCommand(cmd);
    SessionToken sessionToken;
    sessionToken.sessionId = sessionId;
    std::vector<AudioStandard::AudioDeviceDescriptor> deviceDescriptor;

    AVSessionManagerImpl avSessionManagerImpl;
    avSessionManagerImpl.GetAllSessionDescriptors(descriptors);
    avSessionManagerImpl.GetHistoricalSessionDescriptors(maxSize, descriptors);
    avSessionManagerImpl.CreateController(sessionId, controller);
    avSessionManagerImpl.GetActivatedSessionDescriptors(descriptors);
    avSessionManagerImpl.GetSessionDescriptorsBySessionId(bySessionId, descriptor);
    avSessionManagerImpl.SendSystemControlCommand(command);
    avSessionManagerImpl.CastAudio(sessionToken, deviceDescriptor);
}

void AVSessionManagerTestServer()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }

    int32_t type = GetData<uint8_t>() % 2; // valid type 0-1
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);

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

    SessionToken sessionToken;
    sessionToken.sessionId = avSession->GetSessionId();
    std::vector<AudioStandard::AudioDeviceDescriptor> deviceDescriptor;
    AudioStandard::AudioDeviceDescriptor audioDeviceDescriptor;
    deviceDescriptor.push_back(audioDeviceDescriptor);
    AVSessionManagerImpl avSessionManagerImpl;
    avSessionManagerImpl.CastAudio(sessionToken, deviceDescriptor);

    if (avSession != nullptr) {
        avSession->Destroy();
    }
    if (avSessionController != nullptr) {
        avSessionController->Destroy();
    }
}

typedef void (*TestFuncs[3])();

TestFuncs g_testFuncs = {
    AVSessionManagerInterfaceTest,
    AVSessionManagerTestClient,
    AVSessionManagerTestServer,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        SLOGI("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::AVSession::THRESHOLD) {
        return 0;
    }

    FuzzTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
