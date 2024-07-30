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

#define private public
#define protected public
#include "avsession_service.h"
#undef protected
#undef private

#include "avsessionservice_fuzzer.h"
#include "client_death_proxy.h"
#include "audio_info.h"

using namespace std;
namespace OHOS {
namespace AVSession {

static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t CAST_ENGINE_SA_ID = 65546;

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

    void OnDeviceOffline(const std::string& deviceId) override
    {
    };

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
};

void AvSessionServiceExternalCallTest(const uint8_t* data, size_t size)
{
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    service->OnDump();
    service->OnStart();
    service->OnStop();
}

void AvSessionServiceCloseTest(const uint8_t* data, size_t size)
{
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    service->Close();
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

void AvSessionServiceAVPlaybackTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    std::string bundleName(reinterpret_cast<const char *>(data), size);
    std::string assetId(reinterpret_cast<const char *>(data), size);

    service->StartAVPlayback(bundleName, assetId);
}

void AvSessionServiceControllerTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
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
        return;
    }
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
    service->HandleControllerRelease(*avControllerItem);
}

void AVSessionServiceSendSystemControlCommandTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    sptr<FuzzTestISessionListener> listener = new FuzzTestISessionListener();
    if (!listener) {
        return;
    }
    service->RegisterSessionListener(listener);
    AVControlCommand command;
    command.SetCommand(*reinterpret_cast<const int32_t*>(data));
    service->SendSystemControlCommand(command);
}

void AvSessionServiceClientTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    int32_t pid = *reinterpret_cast<const int32_t*>(data);
    service->OnClientDied(pid);
  
    MessageParcel dataMessageParcel;
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    auto remoteObject = dataMessageParcel.ReadRemoteObject();
    if (remoteObject == nullptr) {
        return;
    }
    auto clientDeathObserver = iface_cast<ClientDeathProxy>(remoteObject);
    if (clientDeathObserver == nullptr) {
        return;
    }
    service->RegisterClientDeathObserver(clientDeathObserver);
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

void AvSessionServiceCastAudioTest(const uint8_t* data, size_t size,
    sptr<AVSessionService> service)
{
    SessionToken token;
    std::string sessionId(reinterpret_cast<const char*>(data), size);
    int32_t pid = *(reinterpret_cast<const int32_t *>(data));
    int32_t uid = *(reinterpret_cast<const int32_t *>(data));
    token.sessionId = sessionId;
    token.pid = pid;
    token.uid = uid;

    std::vector<AudioStandard::AudioDeviceDescriptor> audioDeviceDescriptors;
    AudioStandard::AudioDeviceDescriptor descriptor;
    descriptor.deviceType_ = OHOS::AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    audioDeviceDescriptors.push_back(descriptor);
    service->CastAudio(token, audioDeviceDescriptors);
    service->CastAudioForAll(audioDeviceDescriptors);
    service->NotifyAudioSessionCheckTrigger(uid);
}

void AvSessionServiceSuperLauncherTest(const uint8_t* data, size_t size,
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
    bool on = *(reinterpret_cast<const int32_t *>(data));
    service->SetScreenOn(on);
    service->GetScreenOn();
}

void AvSessionServiceTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    AvSessionServiceSystemAbilityTest(data, size, service);
    AvSessionServiceGetAVQueueInfosTest(data, size, service);
    AvSessionServiceGetDescriptorsTest(data, size, service);
    AvSessionServiceAVPlaybackTest(data, size, service);
    AvSessionServiceControllerTest(data, size, service);
    AVSessionServiceSendSystemControlCommandTest(data, size, service);
    AvSessionServiceClientTest(data, size, service);
    AvSessionServiceHandleEventTest(data, size, service);
    AvSessionServiceCastAudioTest(data, size, service);
    AvSessionServiceSuperLauncherTest(data, size, service);
    service->Close();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    AvSessionServiceCloseTest(data, size);
    AvSessionServiceExternalCallTest(data, size);
    AvSessionServiceTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
