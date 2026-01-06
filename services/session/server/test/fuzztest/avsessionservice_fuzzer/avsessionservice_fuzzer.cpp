/*
* Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "avsessionservice_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "securec.h"
#include "avsession_item.h"
#include "avsession_errors.h"
#include "avsession_service_proxy.h"
#include "system_ability_definition.h"
#include "audio_info.h"
#include "avsession_service.h"
#include "client_death_proxy.h"
#include "client_death_stub.h"
#include "audio_info.h"
#include "audio_adapter.h"
#include "session_listener_proxy.h"

using namespace std;
using namespace OHOS::AudioStandard;
namespace OHOS {
namespace AVSession {

static constexpr int32_t CAST_ENGINE_SA_ID = 65546;
static constexpr int32_t TEST_SESSION_ID = 2;
static constexpr int32_t CLIENT_UID = 1;
static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static sptr<AVSessionService> avsessionService_;
AppExecFwk::ElementName elementName;
sptr<AVSessionItem> avsessionHere_ = nullptr;
#ifdef DEVICE_MANAGER_ENABLE
std::vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
#endif
static const int32_t MAX_CODE_LEN  = 20;
static const int32_t MIN_SIZE_NUM = 10;
static const int32_t COLLABORATION_SA_ID = 70633;
static const int32_t ANCO_BROKER_SA_ID = 66849;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_totalSize = 0;
static size_t g_sizePos;
static size_t g_dataSize = 0;
static size_t g_pos;
constexpr size_t STRING_MAX_LENGTH = 128;
constexpr uint32_t AVQ_ITEM_COUNT = 2;
constexpr uint32_t LEN_ITEM0 = 3;
constexpr uint32_t LEN_ITEM1 = 2;
constexpr uint32_t IMG_TOTAL_LEN = 5;
constexpr const char DEV_NULL[] = "/dev/null";
constexpr uint32_t LOG_SIZE_PRIM = 4096;
constexpr uint32_t LOG_SIZE_FALL = 2048;
constexpr int PIPE_FD_COUNT = 2;
constexpr int FD_INVALID = -1;
constexpr int PIPE_SUCCESS = 0;
constexpr size_t PIPE_READ_END = 0;
constexpr size_t PIPE_WRITE_END = 1;
FuzzedDataProvider provider(RAW_DATA, g_dataSize);

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

std::string GenerateString(size_t target_len)
{
    if (RAW_DATA == nullptr || target_len == 0) {
        return "";
    }

    const size_t available_len = (g_totalSize > g_sizePos) ? (g_totalSize - g_sizePos) : 0;
    const size_t copy_len = std::min(target_len, available_len);
    if (copy_len == 0) {
        return "";
    }

    std::vector<char> buffer(copy_len + 1, '\n');

    errno_t ret = memcpy_s(buffer.data(), buffer.size(), RAW_DATA + g_sizePos, copy_len);
    if (ret != EOK) {
        return "";
    }

    g_sizePos += copy_len;
    buffer[copy_len] = '\n';
    return std::string(buffer.data(), copy_len + 1);
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

typedef void (*TestFuncs[12])();

TestFuncs g_allFuncs = {
#ifdef DEVICE_MANAGER_ENABLE
    MockGetTrustedDeviceList,
#endif
    AvSessionServiceTest,
    AVSessionServiceStubRemoteRequestTest,
    AVSessionServiceFuzzer::HandleBundleRemoveEventTest,
    AVSessionServiceFuzzer::HandleChangeTopSessionTest,
    AVSessionServiceFuzzer::UpdateOrderTest,
    AVSessionServiceFuzzer::SelectFocusSessionTest,
    AVSessionServiceFuzzer::RegisterAncoMediaSessionListenerTest,
    AVSessionServiceFuzzer::HandleOtherSessionPlayingTest,
    AVSessionServiceFuzzer::GetOtherPlayingSessionTest,
    AVSessionServiceFuzzer::ReportSessionControlTest,
    AVSessionServiceFuzzer::UpdateFrontSessionTest,
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
    ErrCode OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnAudioSessionChecked(const int32_t uid) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnDeviceLogEvent(const int32_t eventId, const int64_t param) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnDeviceOffline(const std::string& deviceId) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnDeviceStateChange(const DeviceState& deviceState) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnRemoteDistributedSessionChange(
        const std::vector<sptr<IRemoteObject>>& sessionControllers) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnActiveSessionChanged(const std::vector<AVSessionDescriptor> &descriptors) override
    {
        return AVSESSION_SUCCESS;
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

#ifdef DEVICE_MANAGER_ENABLE
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
#endif

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
#ifdef DEVICE_MANAGER_ENABLE
    avsessionService_->GetTrustedDevicesInfo(deviceList);
#endif
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
        MULTIMODAL_INPUT_SERVICE_ID,
        AUDIO_POLICY_SERVICE_ID,
        APP_MGR_SERVICE_ID,
        DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        BUNDLE_MGR_SERVICE_SYS_ABILITY_ID,
        CAST_ENGINE_SA_ID,
        MEMORY_MANAGER_SA_ID,
        SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN,
        COMMON_EVENT_SERVICE_ID,
        COLLABORATION_SA_ID,
        ANCO_BROKER_SA_ID,
    };

    auto randomNumber = GetData<uint32_t>();
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
    service->GetSessionDescriptors(SessionCategory::CATEGORY_ALL, descriptors);
    service->GetSessionDescriptorsBySessionId(systemAbilityId, descriptor);
    service->GetHistoricalSessionDescriptors(maxSize, descriptors);
    systemAbilityId = "sessionId";

    service->GetSessionDescriptorsBySessionId(systemAbilityId, descriptor);
}

void AvSessionServiceAVPlaybackTest(sptr<AVSessionService> service)
{
    std::string bundleName = GetString();
    std::string assetId = GetString();
    std::string moduleName = GetString();
    AVMetaData meta = avsessionHere_->GetMetaData();

    service->StartAVPlayback(bundleName, assetId, moduleName);
    service->DoMetadataImgClean(meta);
}

void CreateNewControllerForSessionTest(sptr<AVSessionService> service)
{
    int32_t pid = GetData<int32_t>();

    service->CreateNewControllerForSession(pid, avsessionHere_);
    service->CancelCastAudioForClientExit(pid, avsessionHere_);
}

static void AvSessionServiceControllerTest(sptr<AVSessionService> service)
{
    sptr<AVSessionItem> avSessionItem = avsessionHere_;
    if (avSessionItem == nullptr) {
        std::string tag = GetString();
        int32_t type = 0;
        std::string bundleName = GetString();
        std::string abilityName = GetString();
        sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
        avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
        if (avSessionItem == nullptr) {
            return;
        }
    }
    ResourceAutoDestroy<sptr<AVSessionItem>> avSessionItemRelease(avSessionItem);
    service->AddAvQueueInfoToFile(*avSessionItem);
    sptr<IRemoteObject> avControllerItemObj;
    std::string sessionId = GetString();
    auto ret = service->CreateControllerInner(avSessionItem->GetSessionId(), avControllerItemObj);
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

static void AvSessionServiceCastTest(sptr<AVSessionService> service)
{
    sptr<AVSessionItem> avSessionItem = avsessionHere_;
    if (avSessionItem == nullptr) {
        std::string tag = GetString();
        int32_t type = 0;
        std::string bundleName = GetString();
        std::string abilityName = GetString();
        sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
        avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
        if (avSessionItem == nullptr) {
            return;
        }
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

    std::string info = GetString();
    service->SplitExtraInfo(info);
    bool enable = GetData<bool>();
    service->checkEnableCast(enable);
    service->setInCast(enable);
    #endif
}


void AVSessionServiceSendSystemControlCommandTest(sptr<AVSessionService> service)
{
    AVControlCommand command;
    command.SetCommand(GetData<int32_t>());
    service->SendSystemControlCommand(command);
    sptr<FuzzTestISessionListener> listener = new FuzzTestISessionListener();
    service->RegisterSessionListener(listener);
    service->RegisterSessionListenerForAllUsers(listener);
}

void AvSessionServiceClientTest(sptr<AVSessionService> service)
{
    int32_t pid = GetData<int32_t>();
    int32_t uid = GetData<int32_t>();
    service->OnClientDied(pid, uid);

    sptr<IClientDeath> clientDeath = new ClientDeathStub();
    auto func = []() {};
    sptr<ClientDeathRecipient> recipient = new ClientDeathRecipient(func);
    std::vector<AVSessionDescriptor> descriptors;
    AVSessionDescriptor descriptor;
    service->AddClientDeathObserver(pid, clientDeath, recipient);
    service->RegisterClientDeathObserver(clientDeath);

    service->NotifyTopSessionChanged(descriptor);
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

    static std::vector<DeviceLogEventCode> eventIds {
        DEVICE_LOG_FULL,
        DEVICE_LOG_EXCEPTION
    };
    uint32_t randomNumber = GetData<uint32_t>();
    auto eventId = eventIds[randomNumber % eventIds.size()];
    int64_t param = GetData<int64_t>();
    avsessionService_->NotifyDeviceLogEvent(eventId, param);

    std::string deviceId = GetString();
    avsessionService_->NotifyDeviceOffline(deviceId);
    avsessionService_->IsMirrorToStreamCastAllowed(avsessionHere_);
#endif
}

void AvSessionServiceSuperLauncherTest001(sptr<AVSessionService> service)
{
    vector<string> states { "UNKNOWN", "IDLE", "CONNECTING" };
    vector<string> serviceNames {"Unknown", "SuperLauncher-Dual", "HuaweiCast" };
    auto randomNumber = GetData<uint32_t>();
    std::string serviceName = serviceNames[randomNumber % serviceNames.size()];
    std::string state = states[randomNumber % states.size()];
    std::string deviceId = GetString();
    std::string extraInfo = GetString();
    service->SuperLauncher(deviceId, serviceName, extraInfo, state);
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    avsessionService_->NotifyMirrorToStreamCast();
#endif

    std::string deviceId2 = GetString();
    std::string serviceName2 = serviceNames[randomNumber % serviceNames.size()];
    std::string extraInfo2 = GetString();
    service->SuperLauncher(deviceId2, serviceName2, extraInfo2, state);
    service->ReleaseSuperLauncher(serviceName);
    service->ConnectSuperLauncher(deviceId, serviceName);
    service->SucceedSuperLauncher(deviceId, extraInfo);
}

void StartDefaultAbilityByCall001()
{
    SLOGI("StartDefaultAbilityByCall001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    avsessionService_->UpdateTopSession(avsessionHere_);
    avsessionService_->NotifyMirrorToStreamCast();
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionService_->isCastableDevice_ = true;
    avsessionService_->MirrorToStreamCast(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    AudioRendererChangeInfo info = {};
    info.clientUID = avsessionHere_->GetUid();

    std::shared_ptr<AudioRendererChangeInfo> info_ = std::make_shared<AudioRendererChangeInfo>();
    info_->clientUID = CLIENT_UID;
    info_->sessionId = TEST_SESSION_ID;
    info_->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info_));
    avsessionService_->SelectSessionByUid(info);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionService_->SaveSessionInfoInFile("tag", avsessionHere_->GetSessionId(),
        "audio", elementName);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    std::string sessionId = GetString();
    avsessionService_->SaveSessionInfoInFile("tag", avsessionHere_->GetSessionId(),
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
    avsessionService_->isCastableDevice_ = true;
    avsessionService_->MirrorToStreamCast(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    avsessionService_->AddAvQueueInfoToFile(*avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    vector<string> assetNames { "FAKE_ASSET_NAME1", "FAKE_ASSET_NAME2" };
    vector<string> moduleNames { "FAKE_MODULE_NAME1", "FAKE_MODULE_NAME2" };
    auto randomNumber = GetData<uint32_t>();
    std::string assetName = assetNames[randomNumber % assetNames.size()];
    std::string moduleName = moduleNames[randomNumber % moduleNames.size()];
    avsessionService_->StartAVPlayback(g_testAnotherBundleName, assetName, moduleName);

    cJSON* value = cJSON_CreateObject();
    if (value == nullptr) {
        SLOGE("get value nullptr");
    } else {
        if (cJSON_IsInvalid(value)) {
            SLOGE("get value invalid");
            cJSON_Delete(value);
            value = nullptr;
        } else {
            cJSON_AddStringToObject(value, "bundleName", g_testAnotherBundleName);
        }
    }

    avsessionService_->GetSubNode(value, "FAKE_NAME");
    avsessionService_->DeleteHistoricalRecord(g_testAnotherBundleName);
    std::vector<std::u16string> argsList;
    avsessionService_->Dump(1, argsList);

    cJSON_Delete(value);
    value = nullptr;
    SLOGI("StartAVPlayback001 end!");
}

void ReportStartCastBegin001()
{
    SLOGI("ReportStartCastBegin001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    avsessionService_->isCastableDevice_ = false;
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
    SLOGI("GetTrustedDeviceName001 end!");
}

void CheckInterfaceTokenTest()
{
    constexpr size_t maxRawDataSize = 128 * 1024 * 1024;
    constexpr size_t maxTokenSize = 32;
    FuzzedDataProvider provider(RAW_DATA, min(maxRawDataSize >> 1, g_totalSize));
    MessageParcel dataMessageParcel;
    std::u16string token;
    if (provider.remaining_bytes() < (maxTokenSize << 1)) {
        token = u"";
    }
    token.resize(maxTokenSize);
    for (size_t i = 0; i < maxTokenSize; ++i) {
        uint16_t charVal = provider.ConsumeIntegral<uint16_t>();
        token[i] = static_cast<char16_t>(charVal);
    }
    dataMessageParcel.WriteInterfaceToken(token);
    avsessionService_->CheckInterfaceToken(dataMessageParcel);
}

void GetAVQueueInfosImgLengthTest()
{
    std::vector<AVQueueInfo> avQueueInfos;
    AVQueueInfo avQueueInfo1;
    avQueueInfos.push_back(avQueueInfo1);

    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 1, 0, 1, 1};
    avQueuePixelMap->SetInnerImgBuffer(imgBuffer);
    AVQueueInfo avQueueInfo2;
    avQueueInfo2.avQueueImage_ = avQueuePixelMap;
    avQueueInfos.push_back(avQueueInfo1);
    avsessionService_->GetAVQueueInfosImgLength(avQueueInfos);
}

void HandleRegisterSessionListenerTest()
{
    MessageParcel data;
    MessageParcel reply;
    OHOS::sptr<IRemoteObject> iRemoteObject;
    auto sessionListenerProxy = std::make_shared<SessionListenerProxy>(iRemoteObject);
    data.WriteRemoteObject(sessionListenerProxy->AsObject());
    avsessionService_->HandleRegisterSessionListener(data, reply);
}

void HandleRegisterSessionListenerForAllUsersTest()
{
    MessageParcel data;
    MessageParcel reply;
    OHOS::sptr<IRemoteObject> iRemoteObject;
    auto sessionListenerProxy = std::make_shared<SessionListenerProxy>(iRemoteObject);
    data.WriteRemoteObject(sessionListenerProxy->AsObject());
    avsessionService_->HandleRegisterSessionListenerForAllUsers(data, reply);
}

void HandleRegisterClientDeathObserverTest()
{
    MessageParcel data;
    MessageParcel reply;
    OHOS::sptr<IRemoteObject> iRemoteObject;
    auto clientDeathProxy = std::make_shared<ClientDeathProxy>(iRemoteObject);
    data.WriteRemoteObject(clientDeathProxy->AsObject());
    avsessionService_->HandleRegisterClientDeathObserver(data, reply);
}

void OnStartProcessTest()
{
    avsessionService_->OnStartProcess();
}

void OnIdleTest()
{
    SystemAbilityOnDemandReason reason;
    avsessionService_->OnIdle(reason);
}

void OnActiveTest()
{
    SystemAbilityOnDemandReason reason;
    avsessionService_->OnActive(reason);
}

void HandleRemoveMediaCardEventTest()
{
    SystemAbilityOnDemandReason reason;
    avsessionService_->HandleRemoveMediaCardEvent(0, false);
}

void IsTopSessionPlayingTest()
{
    avsessionService_->IsTopSessionPlaying();
}

void HandleMediaCardStateChangeEventTest()
{
    const string isAppear[] = {"APPEAR", "DISAPPEAR", GetString()};
    const uint32_t isAppearSize = 3;
    avsessionService_->HandleMediaCardStateChangeEvent(isAppear[GetData<uint32_t>() % isAppearSize]);

    int32_t userId = GetData<int32_t>();
    avsessionService_->RegisterBundleDeleteEventForHistory(userId);
}

void PullMigrateStubTest()
{
    avsessionService_->PullMigrateStub();
}

void InitCollaborationTest()
{
    avsessionService_->InitCollaboration();
}

void InitCastEngineServiceTest()
{
    avsessionService_->InitCastEngineService();
}

void LowQualityCheckTest()
{
    StreamUsage usage = static_cast<StreamUsage>(GetData<int32_t>() % StreamUsage::STREAM_USAGE_MAX);
    RendererState state = static_cast<RendererState>(GetData<uint32_t>() % RendererState::RENDERER_PAUSED -
        RendererState::RENDERER_PREPARED);
    std::string abilityName = GetString();
    int32_t uid = GetData<int32_t>();
    int32_t pid = GetData<int32_t>();
    if (avsessionHere_ == nullptr) {
        return;
    }
    avsessionHere_->SetUid(uid);
    avsessionHere_->SetPid(pid);
    AVSessionService::GetContainer().AddSession(pid, abilityName, avsessionHere_);
    avsessionService_->LowQualityCheck(uid, pid, usage, state);
    avsessionService_->PlayStateCheck(uid, usage, state);
    avsessionService_->NotifyBackgroundReportCheck(uid, pid, usage, state);
    avsessionService_->CheckAncoAudio();
}

void StartAVPlaybackTest()
{
    string bundleName = GetString();
    string assetId = GetString();
    string deviceId = GetString();
    avsessionService_->StartAVPlayback(bundleName, assetId, deviceId);
}

void IsHistoricalSessionTest()
{
    string sessionId = GetString();
    avsessionService_->IsHistoricalSession(sessionId);
}

void StartDefaultAbilityByCallTest()
{
    string sessionId = GetString();
    avsessionService_->StartDefaultAbilityByCall(sessionId);
}

void SendSystemAVKeyEventTest()
{
    MMI::KeyEvent keyEvent = static_cast<MMI::KeyEvent>(GetData<int32_t>());
    AAFwk::Want wantParam;
    avsessionService_->SendSystemAVKeyEvent(keyEvent, wantParam);
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


void OnReceiveEventTest(sptr<AVSessionService> service)
{
    const string actions[] = {
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_FOREGROUND,
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED,
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED,
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED,
        EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED,
        EventFwk::CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED,
        GetString()
    };
    FuzzSessionListener listener;
    avsessionService_->AddInnerSessionListener(&listener);
    avsessionService_->RemoveInnerSessionListener(&listener);
    OHOS::EventFwk::CommonEventData eventData;
    string action = actions[GetData<uint32_t>() % 7];
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, avsessionService_);
    eventSubscriber.OnReceiveEvent(eventData);
}

void HandleKeyEventTest()
{
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_CANCEL);
    avsessionService_->HandleKeyEvent(*(keyEvent.get()));
}

void GetAVCastControllerInnerTest(sptr<AVSessionService> service)
{
    sptr<IRemoteObject> avControllerItemObj;
    std::string sessionId = GetString();

    #ifdef CASTPLUS_CAST_ENGINE_ENABLE
    service->GetAVCastControllerInner(sessionId, avControllerItemObj);
    #endif
}

void CastSessionTest(sptr<AVSessionService> service)
{
    auto castHandle = GetData<int64_t>();

    #ifdef CASTPLUS_CAST_ENGINE_ENABLE
    service->CreateSessionByCast(castHandle);
    service->ReleaseCastSession();
    #endif
}

void GetAVQueueDirTest(sptr<AVSessionService> service)
{
    int32_t userId = GetData<int32_t>();
    std::string dirPath = service->GetAVQueueDir(userId);
    SLOGI("GetAVQueueDirTest dirPath=%{public}s", dirPath.c_str());
}

void GetAVSortDirTest(sptr<AVSessionService> service)
{
    int32_t userId = GetData<int32_t>();
    std::string dirPath = service->GetAVSortDir(userId);
    SLOGI("GetAVSortDirTest dirPath=%{public}s", dirPath.c_str());
}

void NotifyMigrateStopTest(sptr<AVSessionService> service)
{
    std::string deviceId = GetString();
    service->NotifyMigrateStop(deviceId);
}

#ifdef DEVICE_MANAGER_ENABLE
void ProcessTargetMigrateTest(sptr<AVSessionService> service)
{
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    memset_s(&deviceInfo, sizeof(deviceInfo), 0, sizeof(deviceInfo));
    constexpr size_t DEVICE_ID_MAX_LEN = sizeof(deviceInfo.deviceId) - 1;
    std::string deviceId = GenerateString(DEVICE_ID_MAX_LEN);
    strncpy_s(deviceInfo.deviceId, sizeof(deviceInfo.deviceId),
             deviceId.c_str(), deviceId.length());

    constexpr size_t DEVICE_NAME_MAX_LEN = sizeof(deviceInfo.deviceName) - 1;
    std::string deviceName = GenerateString(DEVICE_NAME_MAX_LEN);
    strncpy_s(deviceInfo.deviceName, sizeof(deviceInfo.deviceName),
             deviceName.c_str(), deviceName.length());

    deviceInfo.deviceTypeId = GetData<uint16_t>();

    constexpr size_t NETWORK_ID_MAX_LEN = sizeof(deviceInfo.networkId) - 1;
    std::string networkId = GenerateString(NETWORK_ID_MAX_LEN);
    strncpy_s(deviceInfo.networkId, sizeof(deviceInfo.networkId),
             networkId.c_str(), networkId.length());
    deviceInfo.range = GetData<int32_t>();
    deviceInfo.networkType = GetData<int32_t>();
    static std::vector<OHOS::DistributedHardware::DmAuthForm> authForms {
        OHOS::DistributedHardware::DmAuthForm::INVALID_TYPE,
        OHOS::DistributedHardware::DmAuthForm::PEER_TO_PEER,
        OHOS::DistributedHardware::DmAuthForm::IDENTICAL_ACCOUNT,
        OHOS::DistributedHardware::DmAuthForm::ACROSS_ACCOUNT
    };
    auto randomNumber = GetData<uint32_t>();
    deviceInfo.authForm = authForms[randomNumber % authForms.size()];
    deviceInfo.extraData = GetString();
    bool isOnline = GetData<bool>();
    service->ProcessTargetMigrate(isOnline, deviceInfo);
}
#endif

void NotifyRemoteBundleChangeTest(sptr<AVSessionService> service)
{
    std::string bundleName = GetString();
    service->NotifyRemoteBundleChange(bundleName);
}

void AbilityHasSessionTest(sptr<AVSessionService> service)
{
    std::vector<pid_t> pids {
        GetData<int32_t>(),
        getpid()
    };
    auto randomNumber = GetData<uint32_t>();
    service->AbilityHasSession(pids[randomNumber % pids.size()]);
}

void GetPresentControllerTest(sptr<AVSessionService> service)
{
    pid_t pid = GetData<pid_t>();
    std::string sessionId = GetString();
    service->GetPresentController(pid, sessionId);
}

void StartAbilityByCallTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    std::string sessionIdNeeded = provider.ConsumeRandomLengthString();
    std::string sessionId;
    avsessionService_->StartAbilityByCall(sessionIdNeeded, sessionId);
    avsessionService_->IsCapsuleNeeded();
    avsessionService_->NotifyFlowControl();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    avsessionService_->CreateNftRemoveWant(uid, false);
}

void CallbackTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);
    if (avsessionHere_ == nullptr) {
        return;
    }

    DeviceInfo deviceInfo;
    bool isNeedRemove = provider.ConsumeBool();
    avsessionHere_->DealDisconnect(deviceInfo, isNeedRemove);

    AVMetaData meta;
    shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    meta.SetMediaImage(mediaImage);
    avsessionHere_->isMediaChange_ = true;
    avsessionHere_->CheckUseAVMetaData(meta);
    avsessionHere_->isDestroyed_ = false;
    avsessionHere_->Destroy();
}

void AvSessionServiceTest001()
{
    GetDeviceInfoTest();
    StartDefaultAbilityByCall001();
    StartAVPlayback001();
    ReportStartCastBegin001();
    ReportStartCastEnd001();
    ReportStartCastEnd002();
    GetTrustedDeviceName001();
    CheckInterfaceTokenTest();
    GetAVQueueInfosImgLengthTest();
    HandleRegisterSessionListenerTest();
    HandleRegisterSessionListenerForAllUsersTest();
    HandleRegisterClientDeathObserverTest();
    OnStartProcessTest();
    OnIdleTest();
    OnActiveTest();
    HandleRemoveMediaCardEventTest();
    IsTopSessionPlayingTest();
    HandleMediaCardStateChangeEventTest();
    InitCollaborationTest();
    InitCastEngineServiceTest();
    LowQualityCheckTest();
    StartAVPlaybackTest();
    IsHistoricalSessionTest();
    StartDefaultAbilityByCallTest();
    SendSystemAVKeyEventTest();
    HandleKeyEventTest();
    StartAbilityByCallTest();
    CallbackTest();
}

void AvSessionServiceTest002(sptr<AVSessionService> service)
{
    GetAVCastControllerInnerTest(service);
    CastSessionTest(service);
    GetAVQueueDirTest(service);
    GetAVSortDirTest(service);
    NotifyMigrateStopTest(service);
#ifdef DEVICE_MANAGER_ENABLE
    ProcessTargetMigrateTest(service);
#endif
    NotifyRemoteBundleChangeTest(service);
    AbilityHasSessionTest(service);
    GetPresentControllerTest(service);
}

static void AVSessionServiceProxyTest001()
{
    if (avsessionService_ == nullptr) {
        avsessionService_ = new AVSessionService(AVSESSION_SERVICE_ID);
    }
    sptr<IRemoteObject> remote = avsessionService_->AsObject();
    if (remote == nullptr) {
        return;
    }
    sptr<AVSessionServiceProxy> proxy = new AVSessionServiceProxy(remote);
    if (proxy == nullptr) {
        return;
    }

    MessageParcel reply;
    reply.WriteUint32(AVQ_ITEM_COUNT);

    reply.WriteString(GetString());
    reply.WriteString(GetString());
    reply.WriteString(GetString());
    reply.WriteString(GetString());
    reply.WriteUint32(LEN_ITEM0);

    reply.WriteString(GetString());
    reply.WriteString(GetString());
    reply.WriteString(GetString());
    reply.WriteString(GetString());
    reply.WriteUint32(LEN_ITEM1);

    std::vector<AVQueueInfo> infos;
    proxy->UnMarshallingAVQueueInfos(reply, infos);

    std::vector<char> imgBuf(IMG_TOTAL_LEN);
    for (uint32_t i = 0; i < IMG_TOTAL_LEN; ++i) {
        imgBuf[i] = static_cast<char>(GetData<uint8_t>());
    }
    if (infos.size() < AVQ_ITEM_COUNT) {
        infos.resize(AVQ_ITEM_COUNT);
        infos[0].SetAVQueueLength(LEN_ITEM0);
        infos[1].SetAVQueueLength(LEN_ITEM1);
    }
    proxy->BufferToAVQueueInfoImg(imgBuf.data(), infos);
}

static void AVSessionServiceProxyTest002()
{
    if (avsessionService_ == nullptr) {
        avsessionService_ = new AVSessionService(AVSESSION_SERVICE_ID);
    }
    sptr<IRemoteObject> remote = avsessionService_->AsObject();
    if (remote == nullptr) {
        return;
    }
    sptr<AVSessionServiceProxy> proxy = new AVSessionServiceProxy(remote);
    if (proxy == nullptr) {
        return;
    }
    sptr<IAncoMediaSessionListener> ancoMediaSessionListener_;
    if (ancoMediaSessionListener_ != nullptr) {
        proxy->RegisterAncoMediaSessionListener(ancoMediaSessionListener_);
    }

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int fd = open(DEV_NULL, O_RDONLY);
    if (fd >= 0) {
        proxy->StartDeviceLogging(fd, LOG_SIZE_PRIM);
        close(fd);
    } else {
        std::array<int, PIPE_FD_COUNT> fds = { FD_INVALID, FD_INVALID };
        if (pipe(fds.data()) == PIPE_SUCCESS) {
            proxy->StartDeviceLogging(fds[PIPE_READ_END], LOG_SIZE_FALL);
            close(fds[PIPE_READ_END]);
            close(fds[PIPE_WRITE_END]);
        }
    }
#endif
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
    int sessionTagSize = GetData<uint32_t>() % TEST_SESSION_ID + 1;
    std::string sessionTag = GenerateString(sessionTagSize);
    sptr<OHOS::IRemoteObject> sessionGet = nullptr;
    avsessionService_->GetSessionInner(elementName, sessionTag, sessionGet);
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
    OnReceiveEventTest(avsessionService_);
    AvSessionServiceTest001();
    AvSessionServiceTest002(avsessionService_);
    AVSessionServiceProxyTest001();
    AVSessionServiceProxyTest002();
    avsessionService_->OnStop();
    SLOGI("AvSessionServiceTest done");
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
    dataMessageParcel.WriteBuffer(RAW_DATA, g_sizePos);
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

void AVSessionServiceFuzzer::HandleBundleRemoveEventTest()
{
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    std::string bundleName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    avsessionService->HandleBundleRemoveEvent(bundleName);
}

void AVSessionServiceFuzzer::HandleChangeTopSessionTest()
{
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    int32_t infoUid = provider.ConsumeIntegral<int32_t>();
    int32_t infoPid = provider.ConsumeIntegral<int32_t>();
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    avsessionService->HandleChangeTopSession(infoUid, infoPid, userId);
}

void AVSessionServiceFuzzer::UpdateOrderTest()
{
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    AVSessionDescriptor descriptor;
    sptr<OHOS::AVSession::AVSessionItem> sessionItem = new OHOS::AVSession::AVSessionItem(descriptor);
    CHECK_AND_RETURN(sessionItem != nullptr);
    avsessionService->UpdateOrder(sessionItem);
}

void AVSessionServiceFuzzer::SelectFocusSessionTest()
{
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = provider.ConsumeIntegral<int32_t>();
    info.pid = provider.ConsumeIntegral<int32_t>();
    int32_t usage = provider.ConsumeIntegralInRange<int32_t>(0, STREAM_USAGE_MAX);
    info.streamUsage = static_cast<StreamUsage>(usage);
    avsessionService->SelectFocusSession(info);
}

void AVSessionServiceFuzzer::RegisterAncoMediaSessionListenerTest()
{
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    sptr<OHOS::AVSession::IAncoMediaSessionListener> listener{};
    avsessionService->RegisterAncoMediaSessionListener(listener);
}

void AVSessionServiceFuzzer::HandleOtherSessionPlayingTest()
{
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    AVSessionDescriptor descriptor;
    sptr<OHOS::AVSession::AVSessionItem> session = new OHOS::AVSession::AVSessionItem(descriptor);
    CHECK_AND_RETURN(session != nullptr);
    avsessionService->HandleOtherSessionPlaying(session);
}

void AVSessionServiceFuzzer::GetOtherPlayingSessionTest()
{
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    std::string bundleName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    avsessionService->GetOtherPlayingSession(userId, bundleName);
}

void AVSessionServiceFuzzer::ReportSessionControlTest()
{
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    std::string bundleName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t cmd = provider.ConsumeIntegral<int32_t>();
    avsessionService->ReportSessionControl(bundleName, cmd);
#endif
}

void AVSessionServiceFuzzer::UpdateFrontSessionTest()
{
    sptr<AVSessionService> avsessionService = new AVSessionService(provider.ConsumeIntegral<int32_t>());
    CHECK_AND_RETURN(avsessionService != nullptr);
    AVSessionDescriptor descriptor;
    sptr<OHOS::AVSession::AVSessionItem> session = new OHOS::AVSession::AVSessionItem(descriptor);
    CHECK_AND_RETURN(session != nullptr);
    bool isAdd = provider.ConsumeBool();
    avsessionService->UpdateFrontSession(session, isAdd);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
    OHOS::AVSession::AVSessionService service(systemAbilityId);
    service.PullMigrateStub();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }
    SLOGI("the maximum length of size should not be verified");
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    FuzzTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
