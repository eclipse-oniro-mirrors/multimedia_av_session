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

static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t CAST_ENGINE_SA_ID = 65546;
static constexpr int32_t SESSION_ID = 2;
static constexpr int32_t CLIENT_UID = 1;
static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static sptr<AVSessionService> avsessionService_;
AppExecFwk::ElementName elementName;
sptr<AVSessionItem> avsessionHere_ = nullptr;

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

void AvSessionServiceExternalCallTest(const uint8_t* data, size_t size)
{
    if (avsessionService_ == nullptr) {
        SLOGI("check service null, try create");
        avsessionService_ = new AVSessionService(AVSESSION_SERVICE_ID);
    }
    if (avsessionService_ == nullptr) {
        SLOGE("service is null, return");
        return;
    }

    avsessionService_->OnDump();
    avsessionService_->OnStart();
    avsessionService_->OnStop();
}

void AvSessionServiceCloseTest(const uint8_t* data, size_t size)
{
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

void AvSessionServiceSystemAbilityTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
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
    };

    int32_t randomNumber = *(reinterpret_cast<const int32_t *>(data));
    int32_t systemAbilityId = systemAbilityIdSet[randomNumber % systemAbilityIdSet.size()];
    std::string deviceId(reinterpret_cast<const char *>(data), size);
    service->OnAddSystemAbility(systemAbilityId, deviceId);
    service->OnRemoveSystemAbility(systemAbilityId, deviceId);
}

void AvSessionServiceGetAVQueueInfosTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    int32_t maxSize = *(reinterpret_cast<const int32_t *>(data));
    int32_t maxAppSize = *(reinterpret_cast<const int32_t *>(data));
    std::vector<AVQueueInfo> avQueueInfos;
    service->GetHistoricalAVQueueInfos(maxSize, maxAppSize, avQueueInfos);
}

void AvSessionServiceGetDescriptorsTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    std::string systemAbilityId(reinterpret_cast<const char *>(data), size);
    std::vector<AVSessionDescriptor> descriptors;
    AVSessionDescriptor descriptor;
    int32_t maxSize = *(reinterpret_cast<const int32_t *>(data));

    service->GetAllSessionDescriptors(descriptors);
    service->GetSessionDescriptorsBySessionId(systemAbilityId, descriptor);
    service->GetHistoricalSessionDescriptors(maxSize, descriptors);
}

void GetSessionDescriptorsBySessionId001(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    std::string systemAbilityId = "sessionId";
    std::vector<AVSessionDescriptor> descriptors;
    AVSessionDescriptor descriptor;

    service->GetSessionDescriptorsBySessionId(systemAbilityId, descriptor);
}

void AvSessionServiceAVPlaybackTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    std::string bundleName(reinterpret_cast<const char *>(data), size);
    std::string assetId(reinterpret_cast<const char *>(data), size);

    service->StartAVPlayback(bundleName, assetId);
}

void DoMetadataImgCleanTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    AVMetaData meta = avsessionHere_->GetMetaData();

    service->DoMetadataImgClean(meta);
}

void CreateNewControllerForSessionTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    int32_t pid = *(reinterpret_cast<const int32_t*>(data));
    
    service->CreateNewControllerForSession(pid, avsessionHere_);
}

void AvSessionServiceControllerTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    std::string tag(reinterpret_cast<const char*>(data), size);
    int32_t type = 0;
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        return;
    }
    ResourceAutoDestroy<sptr<AVSessionItem>> avSessionItemRelease(avSessionItem);
    service->AddAvQueueInfoToFile(*avSessionItem);
    sptr<IRemoteObject> avControllerItemObj;
    std::string sessionId(reinterpret_cast<const char*>(data), size);
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

    SessionToken token;
    token.sessionId = avSessionItem->GetSessionId();
    token.pid = *(reinterpret_cast<const int32_t *>(data));
    token.uid = *(reinterpret_cast<const int32_t *>(data));
    int32_t uid = *(reinterpret_cast<const int32_t *>(data));

    std::vector<AudioStandard::AudioDeviceDescriptor> audioDeviceDescriptors;
    AudioStandard::AudioDeviceDescriptor descriptor;
    descriptor.deviceType_ = OHOS::AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    audioDeviceDescriptors.push_back(descriptor);
    service->CastAudio(token, audioDeviceDescriptors);
    service->CastAudioForAll(audioDeviceDescriptors);
    service->NotifyAudioSessionCheckTrigger(uid);

    service->CreateControllerInner("default", avControllerItemObj);
}

void AVSessionServiceSendSystemControlCommandTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    AVControlCommand command;
    command.SetCommand(*reinterpret_cast<const int32_t*>(data));
    service->SendSystemControlCommand(command);
    sptr<FuzzTestISessionListener> listener = new FuzzTestISessionListener();
    service->RegisterSessionListener(listener);
}

void AvSessionServiceClientTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    int32_t pid = *reinterpret_cast<const int32_t*>(data);
    service->OnClientDied(pid);

    sptr<IClientDeath> clientDeath = new ClientDeathStub();
    auto func = []() {};
    sptr<ClientDeathRecipient> recipient = new ClientDeathRecipient(func);
    service->AddClientDeathObserver(pid, clientDeath, recipient);
    service->RegisterClientDeathObserver(clientDeath);
}

void AvSessionServiceHandleEventTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    service->HandleSessionRelease(sessionId);
    service->HandleCallStartEvent();

    int32_t fd = *reinterpret_cast<const int32_t*>(data);
    string strArg(reinterpret_cast<const char*>(data), size);
    std::u16string u16strArg(strArg.begin(), strArg.end());
    std::vector<std::u16string> args;
    args.emplace_back(u16strArg);
    service->Dump(fd, args);
}

void AvSessionServiceSuperLauncherTest001(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    vector<string> states {
        "UNKNOWN",
        "IDLE",
        "CONNECTING",
    };
    vector<string> serviceNames {
        "Unknown",
        "SuperLauncher",
        "HuaweiCast",
    };
    int32_t randomNumber = 1;
    std::string serviceName = serviceNames[randomNumber % serviceNames.size()];
    std::string state = states[randomNumber % states.size()];
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string extraInfo(reinterpret_cast<const char*>(data), size);
    service->SuperLauncher(deviceId, serviceName, extraInfo, state);
    bool on = *(reinterpret_cast<const int32_t *>(data));
    service->SetScreenOn(on);
    service->GetScreenOn();
}

void AvSessionServiceSuperLauncherTest002(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    vector<string> states {
        "UNKNOWN",
        "IDLE",
        "CONNECTING",
    };
    vector<string> serviceNames {
        "Unknown",
        "SuperLauncher",
        "HuaweiCast",
    };
    int32_t randomNumber = *(reinterpret_cast<const int32_t *>(data));
    std::string serviceName = serviceNames[randomNumber % serviceNames.size()];
    std::string state = states[randomNumber % states.size()];
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string extraInfo(reinterpret_cast<const char*>(data), size);
    service->SuperLauncher(deviceId, serviceName, extraInfo, state);
    service->SuperLauncher(deviceId, "SuperLauncher", extraInfo, "CONNECTING");
    bool on = *(reinterpret_cast<const int32_t *>(data));
    service->SetScreenOn(on);
    service->GetScreenOn();
}

void NotifyDeviceAvailable001(const uint8_t* data, size_t size)
{
    SLOGI("NotifyDeviceAvailable001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyDeviceAvailable001 in!");
    OutputDeviceInfo outputDeviceInfo;
    OHOS::AVSession::DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "deviceId";
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    avsessionService_->NotifyDeviceAvailable(outputDeviceInfo);
#endif
    SLOGI("NotifyDeviceAvailable001 end!");
}

void NotifyMirrorToStreamCast001(const uint8_t* data, size_t size)
{
    SLOGI("NotifyMirrorToStreamCast001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyMirrorToStreamCast001 in!");
    avsessionService_->NotifyMirrorToStreamCast();
#endif
    SLOGI("NotifyMirrorToStreamCast001 end!");
}

void NotifyMirrorToStreamCast002(const uint8_t* data, size_t size)
{
    SLOGI("NotifyMirrorToStreamCast002 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyMirrorToStreamCast002 in!");
    avsessionService_->UpdateTopSession(avsessionHere_);
    avsessionService_->NotifyMirrorToStreamCast();
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    SLOGI("NotifyMirrorToStreamCast002 end!");
}

void NotifyMirrorToStreamCast003(const uint8_t* data, size_t size)
{
    SLOGI("NotifyMirrorToStreamCast003 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyMirrorToStreamCast002 in!");
    avsessionService_->UpdateTopSession(avsessionHere_);
    avsessionService_->NotifyMirrorToStreamCast();
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    SLOGI("NotifyMirrorToStreamCast003 end!");
}

void RefreshFocusSessionSort001(const uint8_t* data, size_t size)
{
    SLOGI("RefreshFocusSessionSort001 begin!");
    avsessionService_->RefreshFocusSessionSort(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("RefreshFocusSessionSort001 end!");
}

void SelectSessionByUid001(const uint8_t* data, size_t size)
{
    SLOGI("SelectSessionByUid001 begin!");
    AudioRendererChangeInfo info = {};
    info.clientUID = 0;
    avsessionService_->SelectSessionByUid(info);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SelectSessionByUid001 end!");
}

void SelectSessionByUid002(const uint8_t* data, size_t size)
{
    SLOGI("SelectSessionByUid002 begin!");
    AudioRendererChangeInfo info = {};
    info.clientUID = avsessionHere_->GetUid();

    std::unique_ptr<AudioRendererChangeInfo> info_ = std::make_unique<AudioRendererChangeInfo>();
    info_->clientUID = CLIENT_UID;
    info_->sessionId = SESSION_ID;
    info_->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info_));
    avsessionService_->SelectSessionByUid(info);
    avsessionService_->OutputDeviceChangeListener(infos);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SelectSessionByUid002 end!");
}

void InitBMS001(const uint8_t* data, size_t size)
{
    SLOGI("InitBMS001 begin!");
    avsessionService_->InitBMS();
    SLOGI("InitBMS001 end!");
}

void ReleaseCastSession001(const uint8_t* data, size_t size)
{
    SLOGI("ReleaseCastSession001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("ReleaseCastSession001 in!");
    avsessionService_->ReleaseCastSession();
#endif
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("ReleaseCastSession001 end!");
}

void CreateSessionByCast001(const uint8_t* data, size_t size)
{
    SLOGI("CreateSessionByCast001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("CreateSessionByCast001 in!");
    avsessionService_->CreateSessionByCast(0);
    avsessionService_->ClearSessionForClientDiedNoLock(getpid());
#endif
    SLOGI("CreateSessionByCast001 end!");
}

void MirrorToStreamCast001(const uint8_t* data, size_t size)
{
    SLOGI("MirrorToStreamCast001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("MirrorToStreamCast001 in!");
    avsessionService_->is2in1_ = true;
    avsessionService_->MirrorToStreamCast(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    SLOGI("MirrorToStreamCast001 end!");
}

void MirrorToStreamCast002(const uint8_t* data, size_t size)
{
    SLOGI("MirrorToStreamCast002 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("MirrorToStreamCast002 in!");
    avsessionService_->is2in1_ = false;
    avsessionService_->MirrorToStreamCast(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    SLOGI("MirrorToStreamCast002 end!");
}

void MirrorToStreamCast003(const uint8_t* data, size_t size)
{
    SLOGI("MirrorToStreamCast003 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("MirrorToStreamCast003 in!");
    avsessionService_->is2in1_ = true;
    avsessionService_->MirrorToStreamCast(avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    SLOGI("MirrorToStreamCast003 end!");
}

void RefreshSortFileOnCreateSession001(const uint8_t* data, size_t size)
{
    SLOGI("RefreshSortFileOnCreateSession001 begin!");
    avsessionService_->refreshSortFileOnCreateSession(avsessionHere_->GetSessionId(),
        "audio", elementName);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("RefreshSortFileOnCreateSession001 end!");
}

void StartDefaultAbilityByCall001(const uint8_t* data, size_t size)
{
    SLOGI("StartDefaultAbilityByCall001 begin!");
    std::string sessionId(reinterpret_cast<const char *>(data), size);
    avsessionService_->refreshSortFileOnCreateSession(avsessionHere_->GetSessionId(),
        "audio", elementName);
    avsessionService_->StartDefaultAbilityByCall(sessionId);
    SLOGI("StartDefaultAbilityByCall001 end!");
}

void GetHistoricalAVQueueInfos001(const uint8_t* data, size_t size)
{
    SLOGI("GetHistoricalAVQueueInfos001 begin!");
    std::vector<AVQueueInfo> avQueueInfos_;
    avsessionService_->GetHistoricalAVQueueInfos(0, 0, avQueueInfos_);
    SLOGI("GetHistoricalAVQueueInfos001 end!");
}

void SaveAvQueueInfo001(const uint8_t* data, size_t size)
{
    SLOGI("SaveAvQueueInfo001 begin!");
    AVMetaData meta = avsessionHere_->GetMetaData();
    std::string oldContent;
    if (!avsessionService_->LoadStringFromFileEx(avsessionService_->GetAVQueueDir(), oldContent)) {
        SLOGE("SaveAvQueueInfo001 read avqueueinfo fail, Return!");
        return;
    }
    avsessionService_->SaveAvQueueInfo(oldContent, g_testAnotherBundleName, meta,
        avsessionService_->GetUsersManager().GetCurrentUserId());
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SaveAvQueueInfo001 end!");
}

void AddAvQueueInfoToFile001(const uint8_t* data, size_t size)
{
    SLOGI("AddAvQueueInfoToFile001 begin!");
    avsessionService_->AddAvQueueInfoToFile(*avsessionHere_);
    avsessionService_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("AddAvQueueInfoToFile001 end!");
}

void StartAVPlayback001(const uint8_t* data, size_t size)
{
    SLOGI("StartAVPlayback001 begin!");
    avsessionService_->StartAVPlayback(g_testAnotherBundleName, "FAKE_ASSET_NAME");
    SLOGI("StartAVPlayback001 end!");
}

void GetSubNode001(const uint8_t* data, size_t size)
{
    SLOGI("GetSubNode001 begin!");
    nlohmann::json value;
    value["bundleName"] = g_testAnotherBundleName;
    avsessionService_->GetSubNode(value, "FAKE_NAME");
    SLOGI("GetSubNode001 end!");
}

void DeleteHistoricalRecord001(const uint8_t* data, size_t size)
{
    SLOGI("DeleteHistoricalRecord001 begin!");
    avsessionService_->DeleteHistoricalRecord(g_testAnotherBundleName);
    SLOGI("DeleteHistoricalRecord001 end!");
}

void Dump001(const uint8_t* data, size_t size)
{
    SLOGI("Dump001 begin!");
    std::vector<std::u16string> argsList;
    avsessionService_->Dump(1, argsList);
    SLOGI("Dump001 end!");
}

void ProcessCastAudioCommand001(const uint8_t* data, size_t size)
{
    SLOGI("ProcessCastAudioCommand001 begin!");
    std::string sourceSessionInfo = "SOURCE";
    std::string sinkSessionInfo = " SINK";
    avsessionService_->ProcessCastAudioCommand(
        OHOS::AVSession::AVSessionServiceStub::RemoteServiceCommand::COMMAND_CAST_AUDIO,
        sourceSessionInfo, sinkSessionInfo);
    SLOGI("ProcessCastAudioCommand001 end!");
}

void ProcessCastAudioCommand002(const uint8_t* data, size_t size)
{
    SLOGI("ProcessCastAudioCommand002 begin!");
    std::string sourceSessionInfo = "SOURCE";
    std::string sinkSessionInfo = " SINK";
    avsessionService_->ProcessCastAudioCommand(
        OHOS::AVSession::AVSessionServiceStub::RemoteServiceCommand::COMMAND_CANCEL_CAST_AUDIO,
        sourceSessionInfo, sinkSessionInfo);
    SLOGI("ProcessCastAudioCommand002 end!");
}

void ReportStartCastBegin001(const uint8_t* data, size_t size)
{
    SLOGI("ReportStartCastBegin001 begin!");
    OutputDeviceInfo outputDeviceInfo;
    std::string func(reinterpret_cast<const char*>(data), size);
    auto uid = *(reinterpret_cast<const int32_t *>(data));
    avsessionService_->ReportStartCastBegin(func, outputDeviceInfo, uid);
    SLOGI("ReportStartCastBegin001 end!");
}

void ReportStartCastEnd001(const uint8_t* data, size_t size)
{
    SLOGI("ReportStartCastEnd001 begin!");
    OutputDeviceInfo outputDeviceInfo;
    int32_t ret = AVSESSION_SUCCESS;
    std::string func(reinterpret_cast<const char*>(data), size);
    auto uid = *(reinterpret_cast<const int32_t *>(data));
    avsessionService_->ReportStartCastEnd(func, outputDeviceInfo, uid, ret);
    SLOGI("ReportStartCastEnd001 end!");
}

void ReportStartCastEnd002(const uint8_t* data, size_t size)
{
    SLOGI("ReportStartCastEnd002 begin!");
    OutputDeviceInfo outputDeviceInfo;
    int32_t ret = AVSESSION_ERROR;
    std::string func(reinterpret_cast<const char*>(data), size);
    auto uid = *(reinterpret_cast<const int32_t *>(data));
    avsessionService_->ReportStartCastEnd(func, outputDeviceInfo, uid, ret);
    SLOGI("ReportStartCastEnd002 end!");
}

void HandleDeviceChange001(const uint8_t* data, size_t size)
{
    SLOGI("HandleDeviceChange001 begin!");
    DeviceChangeAction deviceChange;
    deviceChange.type = static_cast<DeviceChangeType>(0);
    deviceChange.flag = static_cast<DeviceFlag>(0);
    avsessionService_->HandleDeviceChange(deviceChange);
    SLOGI("HandleDeviceChange001 end!");
}

void HandleDeviceChange002(const uint8_t* data, size_t size)
{
    SLOGI("HandleDeviceChange002 begin!");
    DeviceChangeAction deviceChange;
    std::vector<OHOS::sptr<AudioDeviceDescriptor>> audioDeviceDescriptors;
    OHOS::sptr<AudioDeviceDescriptor> descriptor = new(std::nothrow) AudioDeviceDescriptor();
    descriptor->deviceType_ = OHOS::AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    deviceChange.type = static_cast<DeviceChangeType>(0);
    deviceChange.flag = static_cast<DeviceFlag>(0);

    audioDeviceDescriptors.push_back(descriptor);
    deviceChange.deviceDescriptors = audioDeviceDescriptors;
    avsessionService_->HandleDeviceChange(deviceChange);
    SLOGI("HandleDeviceChange002 end!");
}

void SendSystemAVKeyEvent001(const uint8_t* data, size_t size)
{
    SLOGI("SendSystemAVKeyEvent001 begin!");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_CANCEL);
    avsessionService_->SendSystemAVKeyEvent(*(keyEvent.get()));
    SLOGI("SendSystemAVKeyEvent001 end!");
}

void SendSystemAVKeyEvent002(const uint8_t* data, size_t size)
{
    SLOGI("SendSystemAVKeyEvent001 begin!");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_CANCEL);
    avsessionService_->SendSystemAVKeyEvent(*(keyEvent.get()));
    SLOGI("SendSystemAVKeyEvent002 end!");
}

void GetTrustedDeviceName001(const uint8_t* data, size_t size)
{
    SLOGI("GetTrustedDeviceName001 begin!");
    std::string networkId = "networkId";
    std::string deviceName = "LocalDevice";
    avsessionService_->GetTrustedDeviceName(networkId, deviceName);
    SLOGI("GetTrustedDeviceName001 end!");
}

void GetTrustedDeviceName002(const uint8_t* data, size_t size)
{
    SLOGI("GetTrustedDeviceName002 begin!");
    std::string networkId = "networkId";
    std::string deviceName(reinterpret_cast<const char*>(data), size);
    avsessionService_->GetTrustedDeviceName(networkId, deviceName);
    SLOGI("GetTrustedDeviceName002 end!");
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

void RemoveInnerSessionListener001(const uint8_t* data, size_t size)
{
    SLOGI("RemoveInnerSessionListener001 begin!");
    FuzzSessionListener listener;
    avsessionService_->AddInnerSessionListener(&listener);
    avsessionService_->RemoveInnerSessionListener(&listener);
    SLOGI("RemoveInnerSessionListener001 end!");
}

void AvSessionServiceTest001(const uint8_t* data, size_t size)
{
    NotifyMirrorToStreamCast001(data, size);
    NotifyMirrorToStreamCast002(data, size);
    NotifyMirrorToStreamCast003(data, size);
    RefreshFocusSessionSort001(data, size);
    SelectSessionByUid001(data, size);
    SelectSessionByUid002(data, size);
    InitBMS001(data, size);
    ReleaseCastSession001(data, size);
    CreateSessionByCast001(data, size);
    MirrorToStreamCast001(data, size);
    MirrorToStreamCast002(data, size);
    MirrorToStreamCast003(data, size);
    RefreshSortFileOnCreateSession001(data, size);
    StartDefaultAbilityByCall001(data, size);
    GetHistoricalAVQueueInfos001(data, size);
    SaveAvQueueInfo001(data, size);
    AddAvQueueInfoToFile001(data, size);
    StartAVPlayback001(data, size);
    GetSubNode001(data, size);
    DeleteHistoricalRecord001(data, size);
    Dump001(data, size);
    ProcessCastAudioCommand001(data, size);
    ProcessCastAudioCommand002(data, size);
    ReportStartCastBegin001(data, size);
    ReportStartCastEnd001(data, size);
    ReportStartCastEnd002(data, size);
    HandleDeviceChange001(data, size);
    HandleDeviceChange002(data, size);
    SendSystemAVKeyEvent001(data, size);
    SendSystemAVKeyEvent002(data, size);
    GetTrustedDeviceName001(data, size);
    GetTrustedDeviceName002(data, size);
    RemoveInnerSessionListener001(data, size);
}

void AvSessionServiceTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
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
    AvSessionServiceSystemAbilityTest(data, size, avsessionService_);
    AvSessionServiceGetAVQueueInfosTest(data, size, avsessionService_);
    AvSessionServiceGetDescriptorsTest(data, size, avsessionService_);
    GetSessionDescriptorsBySessionId001(data, size, avsessionService_);
    AvSessionServiceAVPlaybackTest(data, size, avsessionService_);
    DoMetadataImgCleanTest(data, size, avsessionService_);
    CreateNewControllerForSessionTest(data, size, avsessionService_);
    AvSessionServiceControllerTest(data, size, avsessionService_);
    AVSessionServiceSendSystemControlCommandTest(data, size, avsessionService_);
    AvSessionServiceClientTest(data, size, avsessionService_);
    AvSessionServiceHandleEventTest(data, size, avsessionService_);
    AvSessionServiceSuperLauncherTest001(data, size, avsessionService_);
    AvSessionServiceSuperLauncherTest002(data, size, avsessionService_);
    NotifyDeviceAvailable001(data, size);
    
    AvSessionServiceTest001(data, size);
}

int32_t AVSessionServiceStubFuzzer::OnRemoteRequestForSessionStub(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return AVSESSION_ERROR;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    code %= static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_MAX);

    size -= sizeof(uint32_t);
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    std::string tag(reinterpret_cast<const char*>(data), size);
    int32_t type = *(reinterpret_cast<const int32_t*>(data));
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    bool isThirdPartyApp = *(reinterpret_cast<const int32_t *>(data));
    AVSessionDescriptor descriptor;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    descriptor.sessionId_ = sessionId;
    descriptor.sessionTag_ = tag;
    descriptor.sessionType_ = type;
    descriptor.elementName_ = elementName;
    descriptor.isThirdPartyApp_ = isThirdPartyApp;
    sptr<AVSessionItem> avSessionItem = new(std::nothrow) AVSessionItem(descriptor);
    if (!avSessionItem) {
        SLOGI("testAVSession item is null");
        return AVSESSION_ERROR;
    }
    sptr<IRemoteObject> remoteObject = nullptr;
    std::shared_ptr<AVSessionProxyTestOnServiceFuzzer> avSessionProxy =
        std::make_shared<AVSessionProxyTestOnServiceFuzzer>(remoteObject);
    MessageParcel dataMessageParcelForSession;
    if (!dataMessageParcelForSession.WriteInterfaceToken(avSessionProxy->GetDescriptor())) {
        SLOGE("testAVSession item write interface token error");
        return AVSESSION_ERROR;
    }
    dataMessageParcelForSession.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcelForSession.RewindRead(0);
    MessageParcel replyForSession;
    MessageOption optionForSession;
    int32_t ret = avsessionService_->OnRemoteRequest(code, dataMessageParcelForSession,
        replyForSession, optionForSession);
    return ret;
}

int32_t AVSessionServiceStubFuzzer::OnRemoteRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return AVSESSION_ERROR;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    code %= static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_MAX);

    size -= sizeof(uint32_t);
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
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = avsessionService_->OnRemoteRequest(code, dataMessageParcel, reply, option);
    return ret;
}

int32_t AVSessionServiceStubRemoteRequestTest(const uint8_t* data, size_t size)
{
    auto serviceStub = std::make_unique<AVSessionServiceStubFuzzer>();
    if (serviceStub == nullptr) {
        return 0;
    }
    serviceStub->OnRemoteRequest(data, size);
    serviceStub->OnRemoteRequestForSessionStub(data, size);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    AvSessionServiceCloseTest(data, size);
    AvSessionServiceExternalCallTest(data, size);
    AvSessionServiceTest(data, size);
    AVSessionServiceStubRemoteRequestTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
