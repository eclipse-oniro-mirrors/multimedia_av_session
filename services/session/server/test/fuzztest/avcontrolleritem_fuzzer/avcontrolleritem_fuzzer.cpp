/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "avsession_item.h"
#include "ipc_skeleton.h"
#include "avcontroller_callback_proxy.h"
#include "avsession_controller_stub.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_service.h"
#include "avcontrolleritem_fuzzer.h"

using namespace std;
namespace OHOS {
namespace AVSession {
static const int32_t MAX_CODE_TEST = 17;
static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;

void AvControllerItemFuzzer::FuzzOnRemoteRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    sptr<AVControllerItem> avControllerItem;
    std::string tag(reinterpret_cast<const char*>(data), size);
    int32_t type = *reinterpret_cast<const int32_t*>(data);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN_LOG(service != nullptr, "service is null");
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    CHECK_AND_RETURN_LOG(avSessionItem != nullptr, "avSessionItem is null");
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    CHECK_AND_RETURN_LOG(code < MAX_CODE_TEST, "Unsupport code");
    sptr<IRemoteObject> avControllerItemObj;
    auto ret = service->CreateControllerInner(avSessionItem->GetSessionId(), avControllerItemObj);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "CreateControllerInner failed");
    avControllerItem = (sptr<AVControllerItem>&)avControllerItemObj;
    CHECK_AND_RETURN_LOG(avControllerItem != nullptr, "avControllerItem is null");
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    if (!dataMessageParcel.WriteInterfaceToken(avControllerItem->GetDescriptor())) {
        return;
    }
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    avControllerItem->OnRemoteRequest(code, dataMessageParcel, reply, option);
    avControllerItem->Destroy();
}

void AvControllerItemRemoteRequestTest(const uint8_t* data, size_t size)
{
    auto avControllerItemFuzzer = std::make_unique<AvControllerItemFuzzer>();
    if (avControllerItemFuzzer == nullptr) {
        return;
    }
    avControllerItemFuzzer->FuzzOnRemoteRequest(data, size);
}

void AvControllerItemDataTest(const uint8_t* data, size_t size)
{
    CHECK_AND_RETURN_LOG((data != nullptr) && (size <= MAX_CODE_LEN) && (size >= MIN_SIZE_NUM), "Invalid data");
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN_LOG(service != nullptr, "service is null");
    std::string tag(reinterpret_cast<const char*>(data), size);
    int32_t type = *reinterpret_cast<const int32_t*>(data);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    CHECK_AND_RETURN_LOG(avSessionItem != nullptr, "avSessionItem is null");
    sptr<AVControllerItem> avControllerItem;
    sptr<IRemoteObject> avControllerItemObj;
    auto ret = service->CreateControllerInner(avSessionItem->GetSessionId(), avControllerItemObj);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "CreateControllerInner fail");
    avControllerItem = (sptr<AVControllerItem>&)avControllerItemObj;
    CHECK_AND_RETURN_LOG(avControllerItem != nullptr, "avControllerItem is null");
    auto avControllerItemFuzzer = std::make_unique<AvControllerItemFuzzer>();
    CHECK_AND_RETURN_LOG(avControllerItemFuzzer != nullptr, "avControllerItemFuzzer is null");
    AVPlaybackState playbackstate;
    avControllerItem->GetAVPlaybackState(playbackstate);
    AVMetaData metaData;
    avControllerItem->GetAVMetaData(metaData);
    std::vector<int32_t> cmds;
    avControllerItem->GetValidCommands(cmds);
    AVPlaybackState::PlaybackStateMaskType playBackFilter;
    playBackFilter.set(*(reinterpret_cast<const int32_t*>(data)));
    avControllerItem->SetPlaybackFilter(playBackFilter);

    AvControllerItemDataTestSecond(avControllerItem, data, size);
}

void AvControllerItemDataTestSecond(sptr<AVControllerItem> avControllerItem, const uint8_t* data, size_t size)
{
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    avControllerItem->GetSessionId();
    avControllerItem->GetPid();
    avControllerItem->HasSession(sessionId);
    auto keyEvent = MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(*(reinterpret_cast<const int32_t*>(data)));
    MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(*(reinterpret_cast<const int32_t*>(data)));
    keyEvent->AddKeyItem(item);
    bool isActive = *(reinterpret_cast<const bool*>(data));
    avControllerItem->IsSessionActive(isActive);
    avControllerItem->SendAVKeyEvent(*(keyEvent.get()));
    AbilityRuntime::WantAgent::WantAgent ability;
    avControllerItem->GetLaunchAbility(ability);
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code <= AVMetaData::META_KEY_MAX) {
        AVMetaData::MetaMaskType metaFilter;
        metaFilter.set(code);
        avControllerItem->SetMetaFilter(metaFilter);
    }
    if (code <= AVControlCommand::SESSION_CMD_MAX) {
        AVControlCommand command;
        command.SetCommand(code);
        avControllerItem->SendControlCommand(command);
    }
    avControllerItem->Destroy();
}

void AvControllerItemTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    std::string tag(reinterpret_cast<const char*>(data), size);
    int32_t type = *reinterpret_cast<const int32_t*>(data);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        SLOGI("avSessionItem is null");
        return;
    }
    sptr<AVControllerItem> avControllerItem;
    sptr<IRemoteObject> avControllerItemObj;
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    auto ret = service->CreateControllerInner(avSessionItem->GetSessionId(), avControllerItemObj);
    if (ret != AVSESSION_SUCCESS) {
        SLOGI("CreateControllerInner fail");
        return;
    }
    avControllerItem = (sptr<AVControllerItem>&)avControllerItemObj;
    if (!avControllerItem) {
        SLOGI("avControllerItem is null");
        return;
    }
    AvControllerItemTestImpl(data, size, avControllerItem);
}

void AvControllerItemTestImpl(const uint8_t* data, size_t size,
    sptr<AVControllerItem> avControllerItem)
{
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    AVPlaybackState controllerBackState;
    controllerBackState.SetState(*(reinterpret_cast<const int32_t*>(data)));
    avControllerItem->HandlePlaybackStateChange(controllerBackState);
    AVMetaData controllerMetaData;
    controllerMetaData.Reset();
    controllerMetaData.SetAssetId(deviceId);
    avControllerItem->HandleMetaDataChange(controllerMetaData);
    avControllerItem->HandleActiveStateChange(*(reinterpret_cast<const bool*>(data)));
    std::vector<int32_t> controlCmds;
    controlCmds.push_back(*(reinterpret_cast<const int32_t*>(data)));
    avControllerItem->HandleValidCommandChange(controlCmds);
    int32_t connectionState = 0;
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = *(reinterpret_cast<const int32_t*>(data));
    deviceInfo.deviceId_ = deviceId;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    avControllerItem->HandleOutputDeviceChange(connectionState, outputDeviceInfo);
    avControllerItem->HandleSessionDestroy();
    avControllerItem->Destroy();
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    AvControllerItemRemoteRequestTest(data, size);
    AvControllerItemDataTest(data, size);
    AvControllerItemTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
