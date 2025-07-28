/*
* Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "securec.h"
#include "string_wrapper.h"
#include "avsession_item.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_service.h"
#include "avcontrolleritem_fuzzer.h"

using namespace std;
namespace OHOS {
namespace AVSession {
static const int32_t MAX_CODE_TEST = 5;
static const int32_t MAX_CODE_LEN  = 20;
static const int32_t MIN_SIZE_NUM = 10;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_totalSize = 0;
static size_t g_sizePos;

/*
* describe: get data from FUZZ untrusted data(RAW_DATA) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_totalSize - g_sizePos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_sizePos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_sizePos += objectSize;
    return object;
}

std::string GetString()
{
    size_t objectSize = (GetData<int8_t>() % MAX_CODE_LEN) + 1;
    if (RAW_DATA == nullptr || objectSize > g_totalSize - g_sizePos) {
        return "OVER_SIZE";
    }
    char object[objectSize + 1];
    errno_t ret = memcpy_s(object, sizeof(object), RAW_DATA + g_sizePos, objectSize);
    if (ret != EOK) {
        return "";
    }
    g_sizePos += objectSize;
    std::string output(object);
    return output;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        SLOGE("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

typedef void (*TestFuncs[3])();

TestFuncs g_allFuncs = {
    AvControllerItemRemoteRequestTest,
    AvControllerItemDataTest,
    AvControllerItemTest
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    // initialize data
    RAW_DATA = rawData;
    g_totalSize = size;
    g_sizePos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_allFuncs);
    if (len > 0) {
        g_allFuncs[code % len]();
    } else {
        SLOGE("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}

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

void AvControllerItemFuzzer::FuzzOnRemoteRequest()
{
    sptr<AVControllerItem> avControllerItem;
    std::string tag = GetString();
    int32_t type = GetData<int8_t>();
    std::string bundleName = GetString();
    std::string abilityName = GetString();
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN_LOG(service != nullptr, "service is null");
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type % MIN_SIZE_NUM, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    CHECK_AND_RETURN_LOG(avSessionItem != nullptr, "avSessionItem is null");
    ResourceAutoDestroy<sptr<AVSessionItem>> avSessionItemRelease(avSessionItem);
    uint32_t code = GetData<uint32_t>();
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
    dataMessageParcel.WriteBuffer(RAW_DATA, g_sizePos);
    g_sizePos += sizeof(uint32_t);
    dataMessageParcel.RewindRead(0);
    avControllerItem->OnRemoteRequest(code, dataMessageParcel, reply, option);
    service->OnStop();
    SLOGI("FuzzOnRemoteRequest done");
}

void AvControllerItemRemoteRequestTest()
{
    auto avControllerItemFuzzer = std::make_unique<AvControllerItemFuzzer>();
    if (avControllerItemFuzzer == nullptr) {
        return;
    }
    avControllerItemFuzzer->FuzzOnRemoteRequest();
}

void AvControllerItemDataTest()
{
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN_LOG(service != nullptr, "service is null");
    std::string tag = GetString();
    int32_t type = GetData<uint8_t>();
    std::string bundleName = GetString();
    std::string abilityName = GetString();
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type % MIN_SIZE_NUM, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    CHECK_AND_RETURN_LOG(avSessionItem != nullptr, "avSessionItem is null");
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
    uint32_t playCode = GetData<uint32_t>();
    if (playCode <= AVPlaybackState::PLAYBACK_KEY_MAX) {
        playBackFilter.set(playCode);
    } else {
        playBackFilter.set(AVPlaybackState::PLAYBACK_KEY_STATE);
    }
    avControllerItem->SetPlaybackFilter(playBackFilter);

    AvControllerItemDataTestSecond(avControllerItem);
    AvControllerItemDataTestThird(avControllerItem);
    avControllerItem->RegisterCallbackInner(avControllerItemObj);
    service->OnStop();
    SLOGI("AvControllerItemDataTest done");
}

void AvControllerItemDataTestSecond(sptr<AVControllerItem> avControllerItem)
{
    std::string sessionId = GetString();
    avControllerItem->GetUserId();
    avControllerItem->GetSessionId();
    avControllerItem->GetPid();
    avControllerItem->HasSession(sessionId);
    auto keyEvent = MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(GetData<int32_t>());
    MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(GetData<int32_t>());
    keyEvent->AddKeyItem(item);
    bool isActive = GetData<int32_t>();
    avControllerItem->IsSessionActive(isActive);
    avControllerItem->SendAVKeyEvent(*(keyEvent.get()));
    AbilityRuntime::WantAgent::WantAgent ability;
    avControllerItem->GetLaunchAbility(ability);

    uint32_t code = GetData<int32_t>();
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

void AvControllerItemDataTestThird(sptr<AVControllerItem> avControllerItem)
{
    std::vector<AVQueueItem> items;
    avControllerItem->GetAVQueueItems(items);

    std::string title;
    avControllerItem->GetAVQueueTitle(title);

    int32_t itemId = GetData<int32_t>();
    avControllerItem->SkipToQueueItem(itemId);

    AAFwk::WantParams extras;
    avControllerItem->GetExtras(extras);

    std::string commonCommand = GetString();
    avControllerItem->SendCommonCommand(commonCommand, extras);

    uint32_t code = GetData<uint32_t>();
    AVCallMetaData::AVCallMetaMaskType avCallMetaMaskType;
    avCallMetaMaskType.set(code % AVCallMetaData::AVCALL_META_KEY_MAX);
    avControllerItem->SetAVCallMetaFilter(avCallMetaMaskType);
    AVCallState::AVCallStateMaskType avCallStateMaskType;
    avCallStateMaskType.set(code % AVCallState::AVCALL_STATE_KEY_MAX);
    avControllerItem->SetAVCallStateFilter(avCallStateMaskType);
}

void AvControllerItemTest()
{
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    std::string tag = GetString();
    int32_t type = 0;
    std::string bundleName = GetString();
    std::string abilityName = GetString();
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
    std::string sessionId = GetString();
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
    AvControllerItemTestImpl(avControllerItem);
    AvControllerItemTestImplSecond(avControllerItem);
    service->OnStop();
    SLOGI("AvControllerItemTest done");
}

void AvControllerItemTestImpl(sptr<AVControllerItem> avControllerItem)
{
    std::string deviceId = GetString();
    AVPlaybackState controllerBackState;
    controllerBackState.SetState(GetData<int32_t>());
    avControllerItem->HandlePlaybackStateChange(controllerBackState);
    AVMetaData controllerMetaData;
    controllerMetaData.Reset();
    controllerMetaData.SetAssetId(deviceId);
    avControllerItem->HandleMetaDataChange(controllerMetaData);
    avControllerItem->HandleActiveStateChange(GetData<bool>());
    std::vector<int32_t> controlCmds;
    controlCmds.push_back(GetData<int32_t>());
    avControllerItem->HandleValidCommandChange(controlCmds);
    int32_t connectionState = 0;
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = GetData<int32_t>();
    deviceInfo.deviceId_ = deviceId;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    avControllerItem->HandleOutputDeviceChange(connectionState, outputDeviceInfo);
    avControllerItem->HandleSessionDestroy();
}

void AvControllerItemTestImplSecond(sptr<AVControllerItem> avControllerItem)
{
    AVCallMetaData callMetaData;
    int32_t numberDate = GetData<int32_t>();
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

    const std::string event = GetString();
    const std::string title = GetString();
    AAFwk::WantParams wantParams;
    vector<AVQueueItem> items;
    avControllerItem->HandleSetSessionEvent(event, wantParams);
    avControllerItem->HandleQueueItemsChange(items);
    avControllerItem->HandleQueueTitleChange(title);
    avControllerItem->HandleExtrasChange(wantParams);
    wantParams.SetParam("customData", AAFwk::String::Box(GetString()));
    avControllerItem->SendCustomData(wantParams);
    avControllerItem->HandleCustomData(wantParams);

    std::string sessionId = GetString();
    auto releaseCallback = [](AVControllerItem& item) {};
    auto avControllerCallback = std::make_shared<AVControllerObserver>(sessionId);
    avControllerItem->SetServiceCallbackForRelease(releaseCallback);
    avControllerItem->RegisterAVControllerCallback(avControllerCallback);
    std::shared_ptr<AVControllerCallback> callback;
    avControllerItem->RegisterAVControllerCallback(callback);
    avControllerItem->UnregisterAVControllerCallback();
    avControllerItem->RegisterMigrateAVSessionProxyCallback([](const std::string&, AAFwk::WantParams&)->int32_t {
        return 0;
    });

    AVMetaData avMetaData;
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 0, 0, 0, 1};
    mediaPixelMap->SetInnerImgBuffer(imgBuffer);
    avMetaData.SetMediaImage(mediaPixelMap);
    avMetaData.SetAVQueueImage(mediaPixelMap);
    avControllerItem->DoMetadataImgClean(avMetaData);
    avControllerItem->GetElementOfSession();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }
    /* Run your code on data */
    FuzzTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
