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

#include <iostream>
#include <memory>

#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsessionserviceproxy_fuzzer.h"
#include "system_ability_definition.h"
#include "session_listener_client.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_TEST = 8;
static constexpr int32_t MIN_SIZE_NUM = 4;

void AVSessionServiceProxyFuzzer::FuzzDoProxyTaskOne(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy,
    uint8_t* data, size_t size, sptr<IRemoteObject> object)
{
    std::string tag(reinterpret_cast<const char*>(data), size);
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    std::string testBundleName(reinterpret_cast<const char*>(data), size);
    std::string testAbilityName(reinterpret_cast<const char*>(data), size);
    std::string assetId(reinterpret_cast<const char*>(data), size);
    int32_t type = *(reinterpret_cast<const int32_t*>(data));
    int32_t maxSize = *(reinterpret_cast<const int32_t*>(data));
    int32_t maxAppSize = *(reinterpret_cast<const int32_t*>(data));
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(testBundleName);
    elementName.SetAbilityName(testAbilityName);
    std::shared_ptr<AVSession> session = nullptr;
    std::shared_ptr<AVSessionController> controller = nullptr;
    std::vector<AVSessionDescriptor> descriptors;
    std::vector<AVQueueInfo> avQueueInfos;
    MessageParcel reply;
    AVSessionDescriptor descriptor;
    const char* buffer = reinterpret_cast<const char*>(data);
    avServiceProxy->CreateSession(tag, type, elementName);
    avServiceProxy->CreateSession(tag, type, elementName, session);
    avServiceProxy->CreateSessionInner(tag, type, elementName);
    avServiceProxy->CreateSessionInner(tag, type, elementName, object);
    avServiceProxy->GetAllSessionDescriptors(descriptors);
    avServiceProxy->GetSessionDescriptorsBySessionId(sessionId, descriptor);
    avServiceProxy->GetHistoricalSessionDescriptors(maxSize, descriptors);
    avServiceProxy->GetHistoricalAVQueueInfos(maxSize, maxAppSize, avQueueInfos);
    avServiceProxy->UnMarshallingAVQueueInfos(reply, avQueueInfos);
    avServiceProxy->BufferToAVQueueInfoImg(buffer, avQueueInfos);
    avServiceProxy->StartAVPlayback(testBundleName, assetId);
    avServiceProxy->CreateController(assetId, controller);
    avServiceProxy->CreateControllerInner(assetId, object);
    avServiceProxy->Close();
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> castController = nullptr;
    avServiceProxy->GetAVCastController(sessionId, castController);
    avServiceProxy->GetAVCastControllerInner(sessionId, object);
#endif
}

void AVSessionServiceProxyFuzzer::FuzzDoProxyTaskTwo(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy,
    uint8_t* data, size_t size)
{
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    std::string input(reinterpret_cast<const char*>(data), size);
    std::string output(reinterpret_cast<const char*>(data), size);

    auto keyEventHandle = OHOS::MMI::KeyEvent::Create();
    keyEventHandle->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEventHandle->SetActionTime(1);
    keyEventHandle->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    item.SetDownTime(1);
    item.SetPressed(true);
    keyEventHandle->AddKeyItem(item);
    MMI::KeyEvent keyEvent = *(keyEventHandle.get());

    AVControlCommand command;
    int32_t cmd = *(reinterpret_cast<const int32_t*>(data));
    command.SetCommand(cmd);
    SessionToken sessionToken;
    sessionToken.sessionId = sessionId;
    std::vector<AudioStandard::AudioDeviceDescriptor> deviceDescriptor;

    AVSessionServiceProxy::RemoteServiceCommand remoteCommand =
        static_cast<AVSessionServiceProxy::RemoteServiceCommand>(*(reinterpret_cast<const int32_t*>(data)));
    OutputDeviceInfo outputDeviceInfo;

    avServiceProxy->SendSystemAVKeyEvent(keyEvent);
    avServiceProxy->SendSystemControlCommand(command);
    avServiceProxy->CastAudio(sessionToken, deviceDescriptor);
    avServiceProxy->CastAudioForAll(deviceDescriptor);
    avServiceProxy->ProcessCastAudioCommand(remoteCommand, input, output);
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    bool enable = *(reinterpret_cast<const bool*>(data));
    int32_t castDeviceCapability = *(reinterpret_cast<const int32_t*>(data));
    int32_t fd = *(reinterpret_cast<const int32_t*>(data));
    uint32_t maxSize = *(reinterpret_cast<const uint32_t*>(data));
    std::vector<std::string> drmSchemes;
    avServiceProxy->StartCastDiscovery(castDeviceCapability, drmSchemes);
    avServiceProxy->StopCastDiscovery();
    avServiceProxy->SetDiscoverable(enable);
    avServiceProxy->StartDeviceLogging(fd, maxSize);
    avServiceProxy->StopDeviceLogging();
    avServiceProxy->StartCast(sessionToken, outputDeviceInfo);
    avServiceProxy->StopCast(sessionToken);
    avServiceProxy->checkEnableCast(enable);
#endif
}

void AVSessionServiceProxyFuzzer::FuzzDoProxyTask(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy,
    uint8_t* data, size_t size, sptr<IRemoteObject> object)
{
    SLOGI("enter extra fuzz task");
    FuzzDoProxyTaskOne(avServiceProxy, data, size, object);
    FuzzDoProxyTaskTwo(avServiceProxy, data, size);
}

bool AVSessionServiceProxyFuzzer::FuzzSendRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return false;
    }

    uint32_t cmdCode = *(reinterpret_cast<const uint32_t*>(data));
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
    FuzzDoProxyTask(avServiceProxy, data, size, object);
    MessageParcel request;
    CHECK_AND_RETURN_RET_LOG(request.WriteInterfaceToken(avServiceProxy->GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = avServiceProxy->GetRemote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    size -= sizeof(uint32_t);
    request.WriteBuffer(data + sizeof(uint32_t), size);
    request.RewindRead(0);
    int32_t result = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG((result = remote->SendRequest(cmdCode, request, reply, option)) == 0, ERR_IPC_SEND_REQUEST,
        "send request failed");
    return result == AVSESSION_SUCCESS;
}

bool OHOS::AVSession::AVServiceProxySendRequestTest(uint8_t* data, size_t size)
{
    auto avServiceProxy = std::make_unique<AVSessionServiceProxyFuzzer>();
    if (avServiceProxy == nullptr) {
        return false;
    }
    return avServiceProxy->FuzzSendRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AVServiceProxySendRequestTest(data, size);
    return 0;
}