/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "avsession_item.h"
#include "ipc_skeleton.h"
#include "avcontroller_callback_proxy.h"
#include "avsession_controller_stub.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "audio_info.h"
#include "avsession_service.h"
#include "avsessionservice_fuzzer.h"
#include "client_death_proxy.h"
#include "client_death_stub.h"
#include "audio_info.h"
#include "audio_adapter.h"

using namespace std;
using namespace OHOS::AudioStandard;
namespace OHOS {
namespace AVSession {

static constexpr int32_t CAST_ENGINE_SA_ID = 65546;
static constexpr int32_t SESSION_ID = 2;
static constexpr int32_t CLIENT_UID = 1;
static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static sptr<AVSessionService> avsessionService_;
AppExecFwk::ElementName elementName;
sptr<AVSessionItem> avsessionHere_ = nullptr;
std::vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
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
    MockGetTrustedDeviceList,
    AvSessionServiceTest,
    AVSessionServiceStubRemoteRequestTest
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


class FuzzTestISessionListener : public ISessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
    };

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
    };

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
    };

    void OnAudioSessionChecked(const int32_t uid) override
    {
    };

    void OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override
    {
    };

    void OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) override
    {
    };

    void OnDeviceOffline(const std::string& deviceId) override
    {
    };

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
};

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

void MockGetTrustedDeviceList()
{
    OHOS::DistributedHardware::DmDeviceInfo localeDevice;
    memset_s(&localeDevice, sizeof(localeDevice), 0, sizeof(localeDevice));
    strcpy_s(localeDevice.deviceId, sizeof(localeDevice.deviceId) - 1, "<localeDeviceId>");
    strcpy_s(localeDevice.deviceName, sizeof(localeDevice.deviceName) - 1, "<localeDeviceName>");

    OHOS::DistributedHardware::DmDeviceInfo remoteDevice;
    memset_s(&remoteDevice, sizeof(remoteDevice), 0, sizeof(remoteDevice));
    strcpy_s(remoteDevice.deviceId, sizeof(remoteDevice.deviceId) - 1, "<remoteDeviceId>");
    strcpy_s(remoteDevice.deviceName, sizeof(remoteDevice.deviceName) - 1, "<remoteDeviceName>");

    deviceList.clear();
    deviceList.push_back(localeDevice);
    deviceList.push_back(remoteDevice);
}

void GetDeviceInfoTest()
{
    if (avsessionService_ == nullptr) {
        SLOGI("check service null, try create");
        avsessionService_ = new AVSessionService(AVSESSION_SERVICE_ID);
    }
    if (avsessionService_ == nullptr) {
        SLOGE("service is null, return");
        return;
    }
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    auto uid = GetData<int32_t>();
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors;
    avsessionService_->GetDeviceInfo(avsessionHere_, descriptors, descriptors, descriptors);
    avsessionService_->GetTrustedDevicesInfo(deviceList);
    AudioStandard::AudioDeviceDescriptor des;
    avsessionService_->SelectOutputDevice(uid, des);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();

    avsessionService_->OnDump();
    avsessionService_->OnStart();
    avsessionService_->OnStop();
}

void AvSessionServiceSystemAbilityTest(sptr<AVSessionService> service)
{
    static std::vector<int32_t> systemAbilityIdSet {
        SAMGR_DUMP_SAID,
        MULTIMODAL_INPUT_SERVICE_ID,
        AUDIO_POLICY_SERVICE_ID,
        APP_MGR_SERVICE_ID,
        DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        BUNDLE_MGR_SERVICE_SYS_ABILITY_ID,
        CAST_ENGINE_SA_ID,
        BLUETOOTH_HOST_SYS_ABILITY_ID,
        MEMORY_MANAGER_SA_ID,
        COMMON_EVENT_SERVICE_ID,
    };

    int32_t randomNumber = GetData<uint32_t>();
    int32_t systemAbilityId = systemAbilityIdSet[randomNumber % systemAbilityIdSet.size()];
    std::string deviceId = GetString();
    service->OnAddSystemAbility(systemAbilityId, deviceId);
    service->OnRemoveSystemAbility(systemAbilityId, deviceId);
}

void AvSessionServiceGetAVQueueInfosTest(sptr<AVSessionService> service)
{
    int32_t maxSize = GetData<int32_t>();
    int32_t maxAppSize = GetData<int32_t>();
    std::vector<AVQueueInfo> avQueueInfos;
    service->GetHistoricalAVQueueInfos(maxSize, maxAppSize, avQueueInfos);
}

void AvSessionServiceGetDescriptorsTest(sptr<AVSessionService> service)
{
    std::string systemAbilityId = GetString();
    std::vector<AVSessionDescriptor> descriptors;
    AVSessionDescriptor descriptor;
    int32_t maxSize = GetData<int32_t>();

    service->GetAllSessionDescriptors(descriptors);
    service->GetSessionDescriptorsBySessionId(systemAbilityId, descriptor);
    service->GetHistoricalSessionDescriptors(maxSize, descriptors);
    systemAbilityId = "sessionId";

    service->GetSessionDescriptorsBySessionId(systemAbilityId, descriptor);
}

void AvSessionServiceAVPlaybackTest(sptr<AVSessionService> service)
{
    std::string bundleName = GetString();
    std::string assetId = GetString();
    AVMetaData meta = avsessionHere_->GetMetaData();

    service->StartAVPlayback(bundleName, assetId);
    service->DoMetadataImgClean(meta);
}

void CreateNewControllerForSessionTest(sptr<AVSessionService> service)
{
    int32_t pid = GetData<int32_t>();
    
    service->CreateNewControllerForSession(pid, avsessionHere_);
    service->CancelCastAudioForClientExit(pid, avsessionHere_);
}

void AvSessionServiceControllerTest(sptr<AVSessionService> service)
{
    std::string tag = GetString();
    int32_t type = 0;
    std::string bundleName = GetString();
    std::string abilityName = GetString();
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        return;
    }
    ResourceAutoDestroy<sptr<AVSessionItem>> avSessionItemRelease(avSessionItem);
    service->AddAvQueueInfoToFile(*avSessionItem);
    sptr<IRemoteObject> avControllerItemObj;
    std::string sessionId = GetString();
    uint32_t ret = service->CreateControllerInner(avSessionItem->GetSessionId(), avControllerItemObj);
    if (ret != AVSESSION_SUCCESS) {
        return;
    }
    sptr<AVControllerItem> avControllerItem = (sptr<AVControllerItem>&)avControllerItemObj;
    if (!avControllerItem) {
        return;
    }
    ResourceAutoDestroy<sptr<AVControllerItem>> avControllerItemRelease(avControllerItem);
    service->HandleControllerRelease(*avControllerItem);
    service->HandleSessionRelease(avSessionItem->GetSessionId());
    int32_t uid = GetData<int32_t>();

    service->NotifyAudioSessionCheckTrigger(uid);
    service->CreateControllerInner("default", avControllerItemObj);
}

void AvSessionServiceCastTest(sptr<AVSessionService> service)
{
    std::string tag = GetString();
    int32_t type = 0;
    std::string bundleName = GetString();
    std::string abilityName = GetString();
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        return;
    }
    SessionToken token;
    token.sessionId = avSessionItem->GetSessionId();
    token.pid = GetData<int32_t>();
    token.uid = GetData<int32_t>();

    std::vector<AudioStandard::AudioDeviceDescriptor> audioDeviceDescriptors;
    AudioStandard::AudioDeviceDescriptor descriptor;
    descriptor.deviceType_ = OHOS::AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    audioDeviceDescriptors.push_back(descriptor);
    OutputDeviceInfo outputDeviceInfo;
    OHOS::AVSession::DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "deviceId";
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    service->CastAudio(token, audioDeviceDescriptors);
    if (audioDeviceDescriptors.empty()) {
        audioDeviceDescriptors.emplace_back();
    }
    std::string sourceSessionInfo = "SOURCE";
    service->CastAudioForAll(audioDeviceDescriptors);
    service->CastAudioProcess(audioDeviceDescriptors, sourceSessionInfo, avsessionHere_);
    service->CastAudioInner(audioDeviceDescriptors, sourceSessionInfo, avsessionHere_);
    service->CancelCastAudioInner(audioDeviceDescriptors, sourceSessionInfo, avsessionHere_);
    #ifdef CASTPLUS_CAST_ENGINE_ENABLE
    service->StartCast(token, outputDeviceInfo);
    service->StopCast(token);
    #endif
}


void AVSessionServiceSendSystemControlCommandTest(sptr<AVSessionService> service)
{
    AVControlCommand command;
    command.SetCommand(GetData<int32_t>());
    service->SendSystemControlCommand(command);
    sptr<FuzzTestISessionListener> listener = new FuzzTestISessionListener();
    service->RegisterSessionListener(listener);
}

void AvSessionServiceClientTest(sptr<AVSessionService> service)
{
    int32_t pid = GetData<int32_t>();
    service->OnClientDied(pid);

    sptr<IClientDeath> clientDeath = new ClientDeathStub();
    auto func = []() {};
    sptr<ClientDeathRecipient> recipient = new ClientDeathRecipient(func);
    std::vector<AVSessionDescriptor> descriptors;
    AVSessionDescriptor descriptor;
    service->AddClientDeathObserver(pid, clientDeath, recipient);
    service->RegisterClientDeathObserver(clientDeath);

    service->NotifyTopSessionChanged(descriptor);
    service->CreateWantAgent(&descriptor);
}

void AvSessionServiceHandleEventTest(sptr<AVSessionService> service)
{
    std::string sessionId = GetString();
    service->HandleSessionRelease(sessionId);
    service->HandleCallStartEvent();

    int32_t fd = GetData<int32_t>();
    string strArg = GetString();
    std::u16string u16strArg(strArg.begin(), strArg.end());
    std::vector<std::u16string> args;
    args.emplace_back(u16strArg);
    service->Dump(fd, args);
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OutputDeviceInfo outputDeviceInfo;
    OHOS::AVSession::DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "deviceId";
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    avsessionService_->NotifyDeviceAvailable(outputDeviceInfo);
    avsessionService_->UpdateTopSession(avsessionHere_);
    avsessionService_->NotifyMirrorToStreamCast();
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
}

void AvSessionServiceSuperLauncherTest001(sptr<AVSessionService> service)
{
    vector<string> states { "UNKNOWN", "IDLE", "CONNECTING" };
    vector<string> serviceNames {"Unknown", "SuperLauncher-Dual", "HuaweiCast" };
    int32_t randomNumber = 1;
    std::string serviceName = serviceNames[randomNumber % serviceNames.size()];
    std::string state = states[randomNumber % states.size()];
    std::string deviceId = GetString();
    std::string extraInfo = GetString();
    service->SuperLauncher(deviceId, serviceName, extraInfo, state);
    bool on = GetData<bool>();
    service->SetScreenOn(on);
    service->GetScreenOn();
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    avsessionService_->NotifyMirrorToStreamCast();
#endif
}

void StartDefaultAbilityByCall001()
{
    SLOGI("StartDefaultAbilityByCall001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    avsessionService_->UpdateTopSession(avsessionHere_);
    avsessionService_->NotifyMirrorToStreamCast();
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionService_->is2in1_ = true;
    avsessionService_->MirrorToStreamCast(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    AudioRendererChangeInfo info = {};
    info.clientUID = avsessionHere_->GetUid();

    std::shared_ptr<AudioRendererChangeInfo> info_ = std::make_shared<AudioRendererChangeInfo>();
    info_->clientUID = CLIENT_UID;
    info_->sessionId = SESSION_ID;
    info_->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info_));
    avsessionService_->SelectSessionByUid(info);
    avsessionService_->OutputDeviceChangeListener(infos);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionService_->SaveSessionInfoInFile(avsessionHere_->GetSessionId(),
        "audio", elementName);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    std::string sessionId = GetString();
    avsessionService_->SaveSessionInfoInFile(avsessionHere_->GetSessionId(),
        "audio", elementName);
    avsessionService_->StartDefaultAbilityByCall(sessionId);
    std::vector<AVQueueInfo> avQueueInfos_;
    avsessionService_->GetHistoricalAVQueueInfos(0, 0, avQueueInfos_);
    info = {};
    info.clientUID = avsessionHere_->GetUid();
}

void StartAVPlayback001()
{
    SLOGI("StartAVPlayback001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    avsessionService_->is2in1_ = true;
    avsessionService_->MirrorToStreamCast(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    avsessionService_->AddAvQueueInfoToFile(*avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    vector<string> assetNames { "FAKE_ASSET_NAME1", "FAKE_ASSET_NAME2" };
    int32_t randomNumber = GetData<int32_t>();
    std::string assetName = assetNames[randomNumber % assetNames.size()];
    avsessionService_->StartAVPlayback(g_testAnotherBundleName, assetName);
    nlohmann::json value;
    value["bundleName"] = g_testAnotherBundleName;
    avsessionService_->GetSubNode(value, "FAKE_NAME");
    avsessionService_->DeleteHistoricalRecord(g_testAnotherBundleName);
    std::vector<std::u16string> argsList;
    avsessionService_->Dump(1, argsList);
    SLOGI("StartAVPlayback001 end!");
}

void ReportStartCastBegin001()
{
    SLOGI("ReportStartCastBegin001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    avsessionService_->is2in1_ = false;
    avsessionService_->MirrorToStreamCast(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    std::string sourceSessionInfo = "SOURCE";
    std::string sinkSessionInfo = " SINK";
    avsessionService_->ProcessCastAudioCommand(
        OHOS::AVSession::AVSessionServiceStub::RemoteServiceCommand::COMMAND_CAST_AUDIO,
        sourceSessionInfo, sinkSessionInfo);
    OutputDeviceInfo outputDeviceInfo;
    std::string func = GetString();
    auto uid = GetData<int32_t>();
    avsessionService_->ReportStartCastBegin(func, outputDeviceInfo, uid);
    SLOGI("ReportStartCastBegin001 end!");
}

void ReportStartCastEnd001()
{
    SLOGI("ReportStartCastEnd001 begin!");
    std::string sourceSessionInfo = "SOURCE";
    std::string sinkSessionInfo = " SINK";
    avsessionService_->ProcessCastAudioCommand(
        OHOS::AVSession::AVSessionServiceStub::RemoteServiceCommand::COMMAND_CANCEL_CAST_AUDIO,
        sourceSessionInfo, sinkSessionInfo);
    OutputDeviceInfo outputDeviceInfo;
    int32_t ret = AVSESSION_SUCCESS;
    std::string func = GetString();
    auto uid = GetData<int32_t>();
    avsessionService_->ReportStartCastEnd(func, outputDeviceInfo, uid, ret);
    SLOGI("ReportStartCastEnd001 end!");
}

void ReportStartCastEnd002()
{
    SLOGI("ReportStartCastEnd002 begin!");
    OutputDeviceInfo outputDeviceInfo;
    int32_t ret = AVSESSION_ERROR;
    std::string func = GetString();
    auto uid = GetData<int32_t>();
    avsessionService_->ReportStartCastEnd(func, outputDeviceInfo, uid, ret);
    SLOGI("ReportStartCastEnd002 end!");
}

void ConvertKeyCodeToCommand001()
{
    auto keyCode = GetData<int32_t>();
    avsessionService_->ConvertKeyCodeToCommand(keyCode);
    std::vector<std::shared_ptr<AudioDeviceDescriptor>> audioDeviceDescriptors;
    std::shared_ptr<AudioDeviceDescriptor> descriptor = std::make_shared<AudioDeviceDescriptor>();
    descriptor->deviceType_ = OHOS::AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    audioDeviceDescriptors.push_back(descriptor);
    avsessionService_->HandleDeviceChange(audioDeviceDescriptors);
}

void HandleDeviceChange001()
{
    SLOGI("HandleDeviceChange001 begin!");
    DeviceChangeAction deviceChange;
    std::vector<std::shared_ptr<AudioDeviceDescriptor>> audioDeviceDescriptors;
    std::shared_ptr<AudioDeviceDescriptor> descriptor = std::make_shared<AudioDeviceDescriptor>();
    descriptor->deviceType_ = OHOS::AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    int32_t randomNumber = GetData<int32_t>();
    int32_t enumSize = 2;
    deviceChange.type = static_cast<DeviceChangeType>(randomNumber % enumSize);
    deviceChange.flag = static_cast<DeviceFlag>(randomNumber % enumSize);

    audioDeviceDescriptors.push_back(descriptor);
    deviceChange.deviceDescriptors = audioDeviceDescriptors;
    avsessionService_->HandleDeviceChange(audioDeviceDescriptors);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_CANCEL);
    avsessionService_->SendSystemAVKeyEvent(*(keyEvent.get()));
    SLOGI("HandleDeviceChange001 end!");
}

void GetTrustedDeviceName001()
{
    SLOGI("GetTrustedDeviceName001 begin!");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_CANCEL);
    avsessionService_->SendSystemAVKeyEvent(*(keyEvent.get()));
    std::string networkId = "networkId";
    std::string deviceName = GetString();
    avsessionService_->GetTrustedDeviceName(networkId, deviceName);

    deviceName = "LocalDevice";
    avsessionService_->GetTrustedDeviceName(networkId, deviceName);
    networkId = "networkId";
    std::string deviceId = "deviceId";
    avsessionService_->GetService(deviceId);
    std::vector<AudioStandard::AudioDeviceDescriptor> castAudioDescriptors;
    AudioStandard::AudioDeviceDescriptor des;
    castAudioDescriptors.push_back(des);
    avsessionService_->SetDeviceInfo(castAudioDescriptors, avsessionHere_);
    avsessionService_->CastAudioForNewSession(avsessionHere_);
    DetectBluetoothHostObserver detectBluetoothHostObserver(avsessionService_);
    int transport = OHOS::Bluetooth::BTTransport::ADAPTER_BREDR;
    int status = OHOS::Bluetooth::BTStateID::STATE_TURN_ON;
    detectBluetoothHostObserver.OnStateChanged(transport, status);

    transport = OHOS::Bluetooth::BTTransport::ADAPTER_BLE;
    status = OHOS::Bluetooth::BTStateID::STATE_TURN_ON;
    detectBluetoothHostObserver.OnStateChanged(transport, status);

    transport = OHOS::Bluetooth::BTTransport::ADAPTER_BLE;
    status = OHOS::Bluetooth::BTStateID::STATE_TURN_OFF;
    detectBluetoothHostObserver.OnStateChanged(transport, status);

    OHOS::AVSession::AVSessionService* avSessionService = nullptr;
    DetectBluetoothHostObserver detectBluetoothHostObserver_(avSessionService);
    transport = OHOS::Bluetooth::BTTransport::ADAPTER_BREDR;
    status = OHOS::Bluetooth::BTStateID::STATE_TURN_ON;
    detectBluetoothHostObserver_.OnStateChanged(transport, status);
    SLOGI("GetTrustedDeviceName001 end!");
}

class FuzzSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s created", descriptor.sessionId_.c_str());
    }
    
    void OnSessionRelease(const AVSessionDescriptor& descripter) override
    {
        SLOGI("sessionId=%{public}s released", descripter.sessionId_.c_str());
    }

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s be top session", descriptor.sessionId_.c_str());
    }

    void OnAudioSessionChecked(const int32_t uid) override
    {
        SLOGI("uid=%{public}d checked", uid);
    }
};

void handleusereventTest(sptr<AVSessionService> service)
{
    FuzzSessionListener listener;
    avsessionService_->AddInnerSessionListener(&listener);
    avsessionService_->RemoveInnerSessionListener(&listener);
    OHOS::EventFwk::CommonEventData eventData;
    string action = OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON;
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, avsessionService_);
    eventSubscriber.OnReceiveEvent(eventData);
    auto userId = GetData<int32_t>();
    std::string type = GetString();
    service->HandleUserEvent(type, userId);
}

void HandleScreenStatusChangeTest(sptr<AVSessionService> service)
{
    if (service == nullptr) {
        SLOGE("service is null, return");
        return;
    }
    std::string event = GetString();
    service->HandleScreenStatusChange(event);
}

void SetScreenTest(sptr<AVSessionService> service)
{
    if (service == nullptr) {
        SLOGE("service is null, return");
        return;
    }
    auto on = GetData<bool>();
    service->SetScreenOn(on);
    auto isLocked = GetData<bool>();
    service->SetScreenLocked(isLocked);
    service->GetScreenLocked();
    service->SubscribeCommonEvent();
    wptr<IRemoteObject> object = nullptr;
    auto func = []() {};
    sptr<ClientDeathRecipient> recipient = new ClientDeathRecipient(func);
    if (recipient == nullptr) {
        SLOGE("recipient is null, return");
        return;
    }
    recipient->OnRemoteDied(object);
    service->CheckAncoAudio();
}

void AvSessionServiceTest001()
{
    GetDeviceInfoTest();
    StartDefaultAbilityByCall001();
    StartAVPlayback001();
    ReportStartCastBegin001();
    ReportStartCastEnd001();
    ReportStartCastEnd002();
    HandleDeviceChange001();
    GetTrustedDeviceName001();
}

void AvSessionServiceTest()
{
    if (avsessionService_ == nullptr) {
        SLOGI("check service null, try create");
        avsessionService_ = new AVSessionService(AVSESSION_SERVICE_ID);
    }
    if (avsessionService_ == nullptr) {
        SLOGE("service is null, return");
        return;
    }
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    avsessionHere_ = avsessionService_->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    AvSessionServiceSystemAbilityTest(avsessionService_);
    AvSessionServiceGetAVQueueInfosTest(avsessionService_);
    AvSessionServiceGetDescriptorsTest(avsessionService_);
    AvSessionServiceAVPlaybackTest(avsessionService_);
    CreateNewControllerForSessionTest(avsessionService_);
    AvSessionServiceControllerTest(avsessionService_);
    AvSessionServiceCastTest(avsessionService_);
    AVSessionServiceSendSystemControlCommandTest(avsessionService_);
    AvSessionServiceClientTest(avsessionService_);
    AvSessionServiceHandleEventTest(avsessionService_);
    ConvertKeyCodeToCommand001();
    handleusereventTest(avsessionService_);
    HandleScreenStatusChangeTest(avsessionService_);
    SetScreenTest(avsessionService_);

    AvSessionServiceTest001();
}

int32_t AVSessionServiceStubFuzzer::OnRemoteRequestForSessionStub()
{
    uint32_t code = GetData<uint32_t>();
    code %= static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_MAX);

    sptr<IRemoteObject> remoteObject = nullptr;
    std::shared_ptr<AVSessionProxyTestOnServiceFuzzer> avSessionProxy =
        std::make_shared<AVSessionProxyTestOnServiceFuzzer>(remoteObject);
    MessageParcel dataMessageParcelForSession;
    if (!dataMessageParcelForSession.WriteInterfaceToken(avSessionProxy->GetDescriptor())) {
        SLOGE("testAVSession item write interface token error");
        return AVSESSION_ERROR;
    }
    dataMessageParcelForSession.WriteBuffer(RAW_DATA + g_sizePos, sizeof(uint32_t));
    g_sizePos += sizeof(uint32_t);
    dataMessageParcelForSession.RewindRead(0);
    MessageParcel replyForSession;
    MessageOption optionForSession;
    int32_t ret = avsessionService_->OnRemoteRequest(code, dataMessageParcelForSession,
        replyForSession, optionForSession);
    return ret;
}

int32_t AVSessionServiceStubFuzzer::OnRemoteRequest()
{
    uint32_t code = GetData<uint32_t>();
    code %= static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_MAX);

    if (avsessionService_ == nullptr) {
        SLOGI("check service null, try create");
        avsessionService_ = new AVSessionService(AVSESSION_SERVICE_ID);
    }
    if (avsessionService_ == nullptr) {
        SLOGE("service is null, return");
        return AVSESSION_ERROR;
    }
    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(avsessionService_->GetDescriptor())) {
        return AVSESSION_ERROR;
    }
    dataMessageParcel.WriteBuffer(RAW_DATA + g_sizePos, sizeof(uint32_t));
    g_sizePos += sizeof(uint32_t);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = avsessionService_->OnRemoteRequest(code, dataMessageParcel, reply, option);
    return ret;
}

void AVSessionServiceStubRemoteRequestTest()
{
    auto serviceStub = std::make_unique<AVSessionServiceStubFuzzer>();
    if (serviceStub == nullptr) {
        return;
    }
    serviceStub->OnRemoteRequest();
    serviceStub->OnRemoteRequestForSessionStub();
    if (avsessionService_ == nullptr) {
        SLOGI("check service null, try create");
        avsessionService_ = new AVSessionService(AVSESSION_SERVICE_ID);
    }
    if (avsessionService_ == nullptr) {
        SLOGE("service is null, return");
        return;
    }
    avsessionService_->Close();
    avsessionService_ = nullptr;
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
