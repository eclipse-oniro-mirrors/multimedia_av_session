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

template<typename T>
class ResourceAutoDestroy {
public:
    explicit ResourceAutoDestroy(T ptr) : ptr_(ptr)
    {
    }

    ~ResourceAutoDestroy()
    {
        if (ptr_) {
            ptr_->Destroy();
        }
    }

private:
    T ptr_;
};

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
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type % MIN_SIZE_NUM, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    CHECK_AND_RETURN_LOG(avSessionItem != nullptr, "avSessionItem is null");
    ResourceAutoDestroy<sptr<AVSessionItem>> avSessionItemRelease(avSessionItem);
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    CHECK_AND_RETURN_LOG(code < MAX_CODE_TEST, "Unsupport code");
    sptr<IRemoteObject> avControllerItemObj;
    auto ret = service->CreateControllerInner(avSessionItem->GetSessionId(), avControllerItemObj);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "CreateControllerInner failed");
    avControllerItem = (sptr<AVControllerItem>&)avControllerItemObj;
    CHECK_AND_RETURN_LOG(avControllerItem != nullptr, "avControllerItem is null");
    ResourceAutoDestroy<sptr<AVControllerItem>> avControllerItemRelease(avControllerItem);

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
    int32_t type = 0;
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type % MIN_SIZE_NUM, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    CHECK_AND_RETURN_LOG(avSessionItem != nullptr, "avSessionItem is null");
    ResourceAutoDestroy<sptr<AVSessionItem>> avSessionItemRelease(avSessionItem);
    sptr<AVControllerItem> avControllerItem;
    sptr<IRemoteObject> avControllerItemObj;
    auto ret = service->CreateControllerInner(avSessionItem->GetSessionId(), avControllerItemObj);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "CreateControllerInner fail");
    avControllerItem = (sptr<AVControllerItem>&)avControllerItemObj;
    CHECK_AND_RETURN_LOG(avControllerItem != nullptr, "avControllerItem is null");
    ResourceAutoDestroy<sptr<AVControllerItem>> avControllerItemRelease(avControllerItem);

    AVPlaybackState playbackstate;
    avControllerItem->GetAVPlaybackState(playbackstate);
    AVMetaData metaData;
    avControllerItem->GetAVMetaData(metaData);
    std::vector<int32_t> cmds;
    avControllerItem->GetValidCommands(cmds);
    AVPlaybackState::PlaybackStateMaskType playBackFilter;
    uint32_t playCode = *(reinterpret_cast<const uint32_t*>(data));
    if (playCode <= AVPlaybackState::PLAYBACK_KEY_MAX) {
        playBackFilter.set(playCode);
    } else {
        playBackFilter.set(AVPlaybackState::PLAYBACK_KEY_STATE);
    }
    avControllerItem->SetPlaybackFilter(playBackFilter);

    AvControllerItemDataTestSecond(avControllerItem, data, size);
    AvControllerItemDataTestThird(avControllerItem, data, size);
    avControllerItem->RegisterCallbackInner(avControllerItemObj);
}

void AvControllerItemDataTestSecond(sptr<AVControllerItem> avControllerItem, const uint8_t* data, size_t size)
{
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    avControllerItem->GetUserId();
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
    AVMetaData::MetaMaskType metaFilter;
    metaFilter.set(code % AVMetaData::META_KEY_MAX);
    avControllerItem->SetMetaFilter(metaFilter);
    AVControlCommand command;
    command.SetCommand(code % AVControlCommand::SESSION_CMD_MAX);
    avControllerItem->SendControlCommand(command);

    AVCallState avCallState;
    avControllerItem->GetAVCallState(avCallState);
    AVCallMetaData callMetaData;
    avControllerItem->GetAVCallMetaData(callMetaData);
}

void AvControllerItemDataTestThird(sptr<AVControllerItem> avControllerItem, const uint8_t* data, size_t size)
{
    std::vector<AVQueueItem> items;
    avControllerItem->GetAVQueueItems(items);

    std::string title;
    avControllerItem->GetAVQueueTitle(title);

    int32_t itemId = *(reinterpret_cast<const int32_t*>(data));
    avControllerItem->SkipToQueueItem(itemId);

    AAFwk::WantParams extras;
    avControllerItem->GetExtras(extras);

    std::string commonCommand(reinterpret_cast<const char*>(data), size);
    avControllerItem->SendCommonCommand(commonCommand, extras);

    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    AVCallMetaData::AVCallMetaMaskType avCallMetaMaskType;
    avCallMetaMaskType.set(code % AVCallMetaData::AVCALL_META_KEY_MAX);
    avControllerItem->SetAVCallMetaFilter(avCallMetaMaskType);
    AVCallState::AVCallStateMaskType avCallStateMaskType;
    avCallStateMaskType.set(code % AVCallState::AVCALL_STATE_KEY_MAX);
    avControllerItem->SetAVCallStateFilter(avCallStateMaskType);
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
    int32_t type = 0;
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type % MIN_SIZE_NUM, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        SLOGI("avSessionItem is null");
        return;
    }
    ResourceAutoDestroy<sptr<AVSessionItem>> avSessionItemRelease(avSessionItem);
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
    ResourceAutoDestroy<sptr<AVControllerItem>> avControllerItemRelease(avControllerItem);
    AvControllerItemTestImpl(data, size, avControllerItem);
    AvControllerItemTestImplSecond(data, size, avControllerItem);
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
}

void AvControllerItemTestImplSecond(const uint8_t* data, size_t size,
    sptr<AVControllerItem> avControllerItem)
{
    AVCallMetaData callMetaData;
    int32_t numberDate = *(reinterpret_cast<const int32_t*>(data));
    std::string dataToS(std::to_string(numberDate));
    std::string strCallMetaData(dataToS);
    callMetaData.SetName(strCallMetaData);
    callMetaData.SetPhoneNumber(strCallMetaData);
    avControllerItem->HandleAVCallMetaDataChange(callMetaData);

    AVCallState avCallState;
    int32_t callState = std::stoi(dataToS);
    avCallState.SetAVCallState(callState);
    bool mute = std::stoi(dataToS);
    avCallState.SetAVCallMuted(mute);
    avControllerItem->HandleAVCallStateChange(avCallState);

    const std::string event(reinterpret_cast<const char*>(data), size);
    const std::string title(reinterpret_cast<const char*>(data), size);
    AAFwk::WantParams wantParams;
    vector<AVQueueItem> items;
    avControllerItem->HandleSetSessionEvent(event, wantParams);
    avControllerItem->HandleQueueItemsChange(items);
    avControllerItem->HandleQueueTitleChange(title);
    avControllerItem->HandleExtrasChange(wantParams);

    std::string sessionId(reinterpret_cast<const char*>(data), size);
    auto releaseCallback = [](AVControllerItem& item) {};
    auto avControllerCallback = std::make_shared<AVControllerObserver>(sessionId);
    avControllerItem->SetServiceCallbackForRelease(releaseCallback);
    avControllerItem->RegisterAVControllerCallback(avControllerCallback);
    std::shared_ptr<AVControllerCallback> callback;
    avControllerItem->RegisterAVControllerCallback(callback);
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
