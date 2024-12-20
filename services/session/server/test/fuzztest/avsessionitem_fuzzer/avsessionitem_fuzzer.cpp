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

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>

#include "securec.h"
#include "avsession_item.h"
#include "iav_session.h"
#include "iremote_stub.h"
#include "avsession_stub.h"
#include "avsession_callback_proxy.h"
#include "avsession_controller_stub.h"
#include "avsession_service.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avcontrol_command.h"
#include "avcall_meta_data.h"
#include "avcall_state.h"
#include "avsessionitem_fuzzer.h"

using namespace std;
namespace OHOS {
namespace AVSession {
static const int32_t MAX_CODE_TEST = 24;
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

typedef void (*TestFuncs[2])();

TestFuncs g_allFuncs = {
    AvSessionItemOnRemoteRequest,
    AvSessionItemTest
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

void AvSessionItemFuzzer::AvSessionItemFuzzerTest()
{
    uint32_t code = GetData<uint32_t>();
    if (code >= MAX_CODE_TEST) {
        return;
    }
    std::string tag = GetString();
    int32_t type = GetData<int32_t>();
    std::string bundleName = GetString();
    std::string abilityName = GetString();

    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);

    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        SLOGI("avSessionItem is null");
        return;
    }
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    if (!dataMessageParcel.WriteInterfaceToken(IAVSession::GetDescriptor())) {
        return;
    }
    dataMessageParcel.WriteBuffer(RAW_DATA + g_sizePos, sizeof(uint32_t));
    g_sizePos += sizeof(uint32_t);
    dataMessageParcel.RewindRead(0);
    avSessionItem->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void AvSessionItemTest()
{
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    std::string tag("audio");
    int32_t type = 0;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("abilityName");
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        SLOGI("avSessionItem is null");
        return;
    }
    AvSessionItemTestImpl(avSessionItem);
    AvSessionCallItemTest(avSessionItem);
    AvSessionItemTestImplExtension(avSessionItem);
    AvSessionCallItemTestExtension(avSessionItem);
}

void AvSessionItemTestImpl(sptr<AVSessionItem> avSessionItem)
{
    AVPlaybackState avState;
    int32_t state = GetData<int32_t>();
    avState.SetState(state);

    AVMetaData metaData;
    std::string assetId = GetString();
    metaData.SetAssetId(assetId);

    std::vector<int32_t> cmds;
    int32_t fuzzCmds = GetData<int32_t>();
    cmds.push_back(fuzzCmds);

    bool top = GetData<bool>();

    AVControlCommand controlCommand;
    int32_t cmd = GetData<int32_t>();
    controlCommand.SetCommand(cmd);

    OutputDeviceInfo info;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 0;
    std::string deviceId = GetString();
    deviceInfo.deviceId_= deviceId;
    std::string deviceName = GetString();
    deviceInfo.deviceName_ = deviceName;
    info.deviceInfos_.push_back(deviceInfo);

    avSessionItem->ExecuteControllerCommand(controlCommand);
    avSessionItem->SetTop(top);
    avSessionItem->SetOutputDevice(info);
    avSessionItem->GetOutputDevice(info);
    avSessionItem->AddSupportCommand(controlCommand.GetCommand());
    avSessionItem->DeleteSupportCommand(controlCommand.GetCommand());
    avSessionItem->GetSessionId();
    avSessionItem->GetAVMetaData(metaData);
    avSessionItem->SetAVMetaData(metaData);
    avSessionItem->GetAVPlaybackState(avState);
    avSessionItem->Activate();
    avSessionItem->Deactivate();
    avSessionItem->IsActive();
    avSessionItem->Destroy();
    avSessionItem->SetAVPlaybackState(avState);
    avSessionItem->GetPlaybackState();
    avSessionItem->GetMetaData();
    avSessionItem->GetSupportCommand();
    avSessionItem->GetPid();
    avSessionItem->GetUid();
    avSessionItem->GetAbilityName();
    avSessionItem->GetRemoteSource();
}

void AvSessionItemTestImplExtension(sptr<AVSessionItem> avSessionItem)
{
    int32_t state = GetData<int32_t>();
    int32_t itemId = GetData<int32_t>();
    int32_t pid = GetData<int32_t>();
    int32_t uid = GetData<int32_t>();

    OutputDeviceInfo info;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 0;
    std::string deviceId = GetString();
    deviceInfo.deviceId_= deviceId;
    std::string deviceName = GetString();
    deviceInfo.deviceName_ = deviceName;
    info.deviceInfos_.push_back(deviceInfo);

    std::vector<AVQueueItem> avQueueItems;
    AVQueueItem avQueueItem;
    avQueueItem.SetItemId(GetData<int32_t>());
    avQueueItems.push_back(avQueueItem);

    std::string title = GetString();
    std::string commonCommand = GetString();

    auto wantAgentPtr = std::make_shared<AbilityRuntime::WantAgent::WantAgent>();

    AAFwk::WantParams wantParams;

    auto keyEvent = MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(GetData<int32_t>());
    MMI::KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(GetData<int32_t>());
    keyEvent->AddKeyItem(keyItem);

    sptr<AVControllerItem> avControllerItem = new(std::nothrow) AVControllerItem(pid, avSessionItem);
    if (avControllerItem == nullptr) {
        return;
    }

    avSessionItem->SetAVQueueItems(avQueueItems);
    avSessionItem->GetAVQueueItems(avQueueItems);
    avSessionItem->SetAVQueueTitle(title);
    avSessionItem->GetAVQueueTitle(title);
    avSessionItem->SetLaunchAbility(*wantAgentPtr);
    avSessionItem->SetExtras(wantParams);
    avSessionItem->GetExtras(wantParams);
    avSessionItem->HandleMediaKeyEvent(*keyEvent);
    avSessionItem->HandleOutputDeviceChange(state, info);
    avSessionItem->HandleSkipToQueueItem(itemId);
    avSessionItem->ExecueCommonCommand(commonCommand, wantParams);
    avSessionItem->AddController(pid, avControllerItem);
    avSessionItem->SetPid(pid);
    avSessionItem->SetUid(uid);
    avSessionItem->HandleControllerRelease(pid);
}

void AvSessionCallItemTest(sptr<AVSessionItem> avSessionItem)
{
    AVCallMetaData callMetaData;
    int32_t numberDate = GetData<int32_t>();
    std::string dataToS(std::to_string(numberDate));
    std::string strCallMetaData(dataToS);
    callMetaData.SetName(strCallMetaData);
    callMetaData.SetPhoneNumber(strCallMetaData);

    AVCallState avCallState;
    int32_t callState = std::stoi(dataToS);
    avCallState.SetAVCallState(callState);
    bool mute = std::stoi(dataToS);
    avCallState.SetAVCallMuted(mute);

    avSessionItem->SetAVCallMetaData(callMetaData);
    avSessionItem->SetAVCallState(avCallState);
}

void AvSessionCallItemTestExtension(sptr<AVSessionItem> avSessionItem)
{
    string sinkDevice = GetString();
    string event = GetString();

    auto releaseAndStartCallback = [](AVSessionItem& item) {};
    auto updateSessionCallback = [](string str, bool flag) {};

    AAFwk::WantParams wantParams;

    avSessionItem->GetSessionType();
    avSessionItem->DestroyTask();
    avSessionItem->GetDescriptor();
    avSessionItem->GetAVCallState();
    avSessionItem->GetAVCallMetaData();
    avSessionItem->GetQueueItems();
    avSessionItem->GetQueueTitle();
    avSessionItem->GetExtras();
    avSessionItem->GetLaunchAbility();
    avSessionItem->GetBundleName();
    avSessionItem->SetServiceCallbackForRelease(releaseAndStartCallback);
    avSessionItem->SetServiceCallbackForCallStart(releaseAndStartCallback);
    avSessionItem->SourceCancelCastAudio(sinkDevice);
    avSessionItem->SinkCancelCastAudio();
    avSessionItem->SetSessionEvent(event, wantParams);
    avSessionItem->SetServiceCallbackForAVQueueInfo(releaseAndStartCallback);
    avSessionItem->SetServiceCallbackForUpdateSession(updateSessionCallback);
}

void AvSessionItemOnRemoteRequest()
{
    auto avSessionItem = std::make_unique<AvSessionItemFuzzer>();
    if (avSessionItem == nullptr) {
        SLOGI("avSessionItem is null");
        return;
    }
    avSessionItem->AvSessionItemFuzzerTest();
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
