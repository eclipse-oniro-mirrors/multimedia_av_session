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

#include "avsessionserviceproxy_fuzzer.h"

#include <cstdint>
#include <iostream>
#include <memory>

#include "iservice_registry.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "securec.h"
#include "session_listener_client.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

namespace OHOS::AVSession {

static constexpr int32_t MAX_CODE_TEST = 8;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 25;
static size_t g_dataSize = 0;
static size_t g_pos;
using TestFunc = function<void(FuzzedDataProvider&)>;

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
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

std::string GetString()
{
    size_t objectSize = (GetData<int8_t>() % MAX_CODE_TEST) + 1;
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return "OVER_SIZE";
    }
    char object[objectSize + 1];
    errno_t ret = memcpy_s(object, sizeof(object), RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return "";
    }
    g_pos += objectSize;
    std::string output(object);
    return output;
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

class AncoMediaSessionListenerFuzz : public AncoMediaSessionListener {
public:
    int32_t OnStartAVPlayback(const std::string &bundleName) override
    {
        return 0;
    }
    ~AncoMediaSessionListenerFuzz() override = default;
};

void AVSessionServiceProxyFuzzer::FuzzDoProxyTaskOne(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy,
    sptr<IRemoteObject> object)
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(GetString());
    elementName.SetAbilityName(GetString());
    std::shared_ptr<AVSession> session = nullptr;
    std::shared_ptr<AVSessionController> controller = nullptr;
    std::vector<AVSessionDescriptor> descriptors;

    AVSessionDescriptor descriptor;
    avServiceProxy->CreateSession(GetString(), GetData<int32_t>(), elementName);
    avServiceProxy->CreateSession(GetString(), GetData<int32_t>(), elementName, session);
    avServiceProxy->CreateSessionInner(GetString(), GetData<int32_t>(), elementName);
    avServiceProxy->CreateSessionInner(GetString(), GetData<int32_t>(), elementName, object);
    avServiceProxy->GetAllSessionDescriptors(descriptors);
    avServiceProxy->GetSessionDescriptors(GetData<int32_t>(), descriptors);
    avServiceProxy->GetSessionDescriptorsBySessionId(GetString(), descriptor);
    avServiceProxy->GetHistoricalSessionDescriptors(GetData<int32_t>(), descriptors);

    avServiceProxy->StartAVPlayback(GetString(), GetString(), GetString());
    avServiceProxy->CreateController(GetString(), controller);
    avServiceProxy->CreateControllerInner(GetString(), object);
    avServiceProxy->Close();
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> castController = nullptr;
    avServiceProxy->GetAVCastController(GetString(), castController);
    avServiceProxy->GetAVCastControllerInner(GetString(), object);
#endif
}

void AVSessionServiceProxyFuzzer::FuzzDoProxyTaskTwo(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy)
{
    std::string input(GetData<char>(), g_dataSize);
    std::string output(GetData<char>(), g_dataSize);

    auto keyEventHandle = OHOS::MMI::KeyEvent::Create();
    keyEventHandle->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEventHandle->SetActionTime(1);
    keyEventHandle->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    item.SetDownTime(1);
    item.SetPressed(GetData<bool>());
    keyEventHandle->AddKeyItem(item);
    MMI::KeyEvent keyEvent = *(keyEventHandle.get());
    AAFwk::Want wantParam;

    AVControlCommand command;
    command.SetCommand(GetData<int32_t>());
    SessionToken sessionToken;
    sessionToken.sessionId = GetString();
    std::vector<AudioStandard::AudioDeviceDescriptor> deviceDescriptor;
    AudioStandard::AudioDeviceDescriptor audioDeviceDescriptor;
    deviceDescriptor.push_back(audioDeviceDescriptor);

    AVSessionServiceProxy::RemoteServiceCommand remoteCommand =
        static_cast<AVSessionServiceProxy::RemoteServiceCommand>(GetData<int32_t>());
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    avServiceProxy->SendSystemAVKeyEvent(keyEvent);
    avServiceProxy->SendSystemControlCommand(command);
    avServiceProxy->CastAudio(sessionToken, deviceDescriptor);
    avServiceProxy->CastAudioForAll(deviceDescriptor);
    avServiceProxy->ProcessCastAudioCommand(remoteCommand, input, output);
    avServiceProxy->SendSystemAVKeyEvent(keyEvent, wantParam);

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    bool enable = GetData<bool>();
    int32_t castDeviceCapability = GetData<int32_t>();
    std::vector<std::string> drmSchemes;
    drmSchemes.push_back("test");
    avServiceProxy->StartCastDiscovery(castDeviceCapability, drmSchemes);
    avServiceProxy->StopCastDiscovery();
    avServiceProxy->SetDiscoverable(enable);
    // do not test StartDeviceLogging at fuzz, as it may pass fd for alive testFile to avsession service
    // so test fwk can not check whether this test case is ending
    avServiceProxy->StopDeviceLogging();
    avServiceProxy->StartCast(sessionToken, outputDeviceInfo);
    avServiceProxy->StopCast(sessionToken);
    avServiceProxy->checkEnableCast(enable);
#endif
}

void AVSessionServiceProxyFuzzer::FuzzDoProxyTaskThird(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy)
{
    std::vector<AVQueueInfo> avQueueInfos;

    AVQueueInfo info;
    info.SetBundleName(GetString());
    info.SetAVQueueName(GetString());
    info.SetAVQueueId(GetString());
    info.SetAVQueueImageUri(GetString());
    info.SetAVQueueLength(GetData<uint32_t>());
    avQueueInfos.push_back(info);
    MessageParcel reply;
    reply.WriteUint32(0);

    avServiceProxy->GetHistoricalAVQueueInfos(GetData<int32_t>(), GetData<int32_t>(), avQueueInfos);
    OHOS::sptr<ISessionListener> listener = new TestISessionListener();
    avServiceProxy->RegisterSessionListener(listener);
    avServiceProxy->RegisterSessionListenerForAllUsers(listener);
    DistributedSessionType sessionType = static_cast<DistributedSessionType>(GetData<int32_t>());
    std::vector<std::shared_ptr<AVSessionController>> controllers;
    avServiceProxy->GetDistributedSessionControllers(sessionType, controllers);
    std::vector<sptr<IRemoteObject>> innerControllers;
    avServiceProxy->GetDistributedSessionControllersInner(sessionType, innerControllers);
}

void AVSessionServiceProxyFuzzer::FuzzDoProxyTask(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy,
    sptr<IRemoteObject> object)
{
    SLOGI("enter extra fuzz task");
    FuzzDoProxyTaskOne(avServiceProxy, object);
    FuzzDoProxyTaskTwo(avServiceProxy);
    FuzzDoProxyTaskThird(avServiceProxy);
}

bool AVSessionServiceProxyFuzzer::FuzzSendRequest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize < MIN_SIZE_NUM)) {
        return false;
    }

    uint32_t cmdCode = GetData<uint32_t>();
    if (cmdCode >= MAX_CODE_TEST) {
        return false;
    }

    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGE("failed to get sa mgr");
        return false;
    }
    auto object = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    if (object == nullptr) {
        SLOGE("failed to get service");
        return false;
    }
    std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy =
        std::make_shared<AVSessionServiceProxyFuzzerTest>(object);
    FuzzDoProxyTask(avServiceProxy, object);
    MessageParcel request;
    CHECK_AND_RETURN_RET_LOG(request.WriteInterfaceToken(avServiceProxy->GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = avServiceProxy->GetRemote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    request.WriteBuffer(RAW_DATA + sizeof(uint32_t), g_dataSize - sizeof(uint32_t));
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG((result = remote->SendRequest(cmdCode, request, reply, option)) == 0, ERR_IPC_SEND_REQUEST,
        "send request failed");
    return result == AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession

bool OHOS::AVSession::AVServiceProxySendRequestTest()
{
    auto avServiceProxy = std::make_unique<AVSessionServiceProxyFuzzer>();
    if (avServiceProxy == nullptr) {
        return false;
    }
    return avServiceProxy->FuzzSendRequest();
}

void GetSessionFuzzTest(FuzzedDataProvider& provider)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN(mgr != nullptr);
    auto object = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN(object != nullptr);
    std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy =
        std::make_shared<AVSessionServiceProxyFuzzerTest>(object);
    CHECK_AND_RETURN(avServiceProxy != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(GetString());
    elementName.SetAbilityName(GetString());
    std::string tag = GetString();
    int32_t type = GetData<int32_t>();
    std::shared_ptr<OHOS::AVSession::AVSession> session = nullptr;
    avServiceProxy->CreateSession(tag, type, elementName, session);
    avServiceProxy->GetSession(elementName, tag, session);
}

void GetSessionInnerFuzzTest(FuzzedDataProvider& provider)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN(mgr != nullptr);
    auto object = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN(object != nullptr);
    std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy =
        std::make_shared<AVSessionServiceProxyFuzzerTest>(object);
    CHECK_AND_RETURN(avServiceProxy != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(GetString());
    elementName.SetAbilityName(GetString());
    std::string tag = GetString();
    int32_t type = GetData<int32_t>();
    avServiceProxy->CreateSession(tag, type, elementName);
    sptr<IRemoteObject> session = nullptr;
    avServiceProxy->GetSessionInner(elementName, tag, session);
}

void RegisterAncoMediaSessionListenerFuzzTest(FuzzedDataProvider& provider)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN(mgr != nullptr);
    auto object = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN(object != nullptr);
    std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy =
        std::make_shared<AVSessionServiceProxyFuzzerTest>(object);
    CHECK_AND_RETURN(avServiceProxy != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(GetString());
    elementName.SetAbilityName(GetString());
    std::string tag = GetString();
    int32_t type = GetData<int32_t>();
    avServiceProxy->CreateSession(tag, type, elementName);
    std::shared_ptr<AncoMediaSessionListenerFuzz> listener = std::make_shared<AncoMediaSessionListenerFuzz>();
    CHECK_AND_RETURN(listener != nullptr);
    sptr<IAncoMediaSessionListener> listenerPtr = new(std::nothrow) AncoMediaSessionListenerImpl(listener);
    CHECK_AND_RETURN(listenerPtr != nullptr);
    avServiceProxy->RegisterAncoMediaSessionListener(listenerPtr);
}

static bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    std::vector<TestFunc> allFuncs = {
        GetSessionFuzzTest,
        GetSessionInnerFuzzTest,
        RegisterAncoMediaSessionListenerFuzzTest,
    };
    OHOS::AVSession::AVServiceProxySendRequestTest();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t len = allFuncs.size();
    if (len > 0) {
        allFuncs[code % len](provider);
    } else {
        SLOGE("%{public}s: The len length is equal to 0", __func__);
    }
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }

    FuzzTest(data, size);
    return 0;
}