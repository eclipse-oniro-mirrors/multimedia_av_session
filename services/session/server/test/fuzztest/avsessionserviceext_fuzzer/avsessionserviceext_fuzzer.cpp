/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>

#include "ipc_skeleton.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_log.h"
#include "audio_info.h"
#include "avsessionserviceext_fuzzer.h"
#include "avsession_service.h"
#include "securec.h"

using namespace std;
namespace OHOS::AVSession {
static const int32_t MAX_CODE_LEN  = 512;
static const int32_t MIN_SIZE_NUM = 4;
static const uint8_t *RAW_DATA = nullptr;
static sptr<AVSessionService> service = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos = 0;

class FuzzExtSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s created", descriptor.sessionId_.c_str());
    }

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s released", descriptor.sessionId_.c_str());
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

class FuzzExtHistoricalRecordListener : public HistoricalRecordListener {
public:
    void OnHistoricalRecordChange() override
    {
        SLOGI("OnHistoricalRecordChange called");
    }
};

class FuzzExtISessionListener : public ISessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override {};
    void OnSessionRelease(const AVSessionDescriptor& descriptor) override {};
    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override {};
    void OnAudioSessionChecked(const int32_t uid) override {};
    void OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override {};
    void OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) override {};
    void OnDeviceOffline(const std::string& deviceId) override {};
    void OnDeviceStateChange(const DeviceState& deviceState) override {};
    void OnRemoteDistributedSessionChange(
        const std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers) override {};
    OHOS::sptr<IRemoteObject> AsObject() override { return nullptr; };
};

void SuperLauncherTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);

    vector<string> states { "UNKNOWN", "IDLE", "CONNECTING" };
    vector<string> serviceNames { "Unknown", "SuperLauncher-Dual", "HuaweiCast" };
    vector<string> deviceIds { " ", "1234567", "7654321" };
    vector<string> extraInfos { "nothings", "reason", "others" };
    std::string state = states[provider.ConsumeIntegral<uint32_t>() % states.size()];
    std::string serviceName = serviceNames[provider.ConsumeIntegral<uint32_t>() % serviceNames.size()];
    std::string deviceId = deviceIds[provider.ConsumeIntegral<uint32_t>() % deviceIds.size()];
    std::string extraInfo = extraInfos[provider.ConsumeIntegral<uint32_t>() % extraInfos.size()];
    service->SuperLauncher(deviceId, serviceName, extraInfo, state);
}

void AVSessionServiceExtFuzzTest001()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);

    FuzzExtSessionListener listener;
    service->AddInnerSessionListener(&listener);
    service->RemoveInnerSessionListener(&listener);

    std::string bundleName = provider.ConsumeRandomLengthString();
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    FuzzExtHistoricalRecordListener historicalListener;
    service->AddHistoricalRecordListener(&historicalListener);
    service->NotifyHistoricalRecordChange(bundleName, userId);
    service->RemoveHistoricalRecordListener(&historicalListener);

    std::string deviceId = provider.ConsumeRandomLengthString();
    service->NotifyMigrateStop(deviceId);
}

void AVSessionServiceExtFuzzTest002()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);

    std::vector<DistributedHardware::DmDeviceType> deviceTypes {
        DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE,
        DistributedHardware::DmDeviceType::DEVICE_TYPE_TV,
        DistributedHardware::DmDeviceType::DEVICE_TYPE_WIFI_CAMERA,
        DistributedHardware::DmDeviceType::DEVICE_TYPE_CAR
    };
    uint32_t randomIndex = provider.ConsumeIntegral<uint32_t>() % deviceTypes.size();
    service->localDeviceType_ = deviceTypes[randomIndex];
    bool isOnline = provider.ConsumeBool();
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    memset_s(&deviceInfo, sizeof(deviceInfo), 0, sizeof(deviceInfo));
    std::string deviceId = provider.ConsumeRandomLengthString(DM_MAX_DEVICE_ID_LEN);
    strncpy_s(deviceInfo.deviceId, sizeof(deviceInfo.deviceId),
            deviceId.c_str(), deviceId.length());
    std::string deviceName = provider.ConsumeRandomLengthString(DM_MAX_DEVICE_NAME_LEN);
    strncpy_s(deviceInfo.deviceName, sizeof(deviceInfo.deviceName),
             deviceName.c_str(), deviceName.length());
    deviceInfo.deviceTypeId = provider.ConsumeIntegral<uint16_t>();
    std::string networkId = provider.ConsumeRandomLengthString(DM_MAX_DEVICE_ID_LEN);
    strncpy_s(deviceInfo.networkId, sizeof(deviceInfo.networkId),
             networkId.c_str(), networkId.length());
    deviceInfo.range = provider.ConsumeIntegral<int32_t>();
    deviceInfo.networkType = provider.ConsumeIntegral<int32_t>();
    deviceInfo.authForm = static_cast<OHOS::DistributedHardware::DmAuthForm>(
        provider.ConsumeIntegralInRange<int32_t>(OHOS::DistributedHardware::DmAuthForm::INVALID_TYPE,
        OHOS::DistributedHardware::DmAuthForm::SHARE));
    deviceInfo.extraData = provider.ConsumeRandomLengthString();

    service->OnAddSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        deviceInfo.deviceId);
    service->ProcessTargetMigrate(isOnline, deviceInfo);
}

void AVSessionServiceExtFuzzTest003()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::string info = "";
    bool isSupportMirrorToStream = provider.ConsumeBool();
    auto deviceId = provider.ConsumeIntegral<int32_t>();
    std::string deviceName = provider.ConsumeRandomLengthString();
    auto deviceType = provider.ConsumeIntegral<int32_t>();
    info = "\"SUPPORT_MIRROR_TO_STREAM\"" + std::string(" : ") + (isSupportMirrorToStream ? "\"true\"" : "\"false\"") +
    ", " + "\"deviceId\"" + std::string(" : ") + std::to_string(deviceId) +
    ", " + "\"deviceName\"" + std::string(" : ") + "\"" + deviceName + "\"" +
    ", " + "\"deviceType\"" + std::string(" : ") + std::to_string(deviceType);
    service->SplitExtraInfo(info);
#endif
}

void AVSessionSystemAbilityLoadCallbackTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);

    AVSessionSystemAbilityLoadCallback callback(service);
    std::string deviceId = provider.ConsumeRandomLengthString();
    sptr<IRemoteObject> remoteObject = nullptr;
    callback.OnLoadSACompleteForRemote(deviceId, AVSESSION_SERVICE_ID, remoteObject);
}

void AVSessionDeviceStateCallbackTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);

    AVSessionDeviceStateCallback callback(service);
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = provider.ConsumeIntegral<int32_t>();
    callback.OnDeviceOnline(deviceInfo);
    callback.OnDeviceReady(deviceInfo);
    callback.OnDeviceOffline(deviceInfo);
    callback.OnDeviceChanged(deviceInfo);
}

void AVSessionServiceExtFuzzer::AVSessionServiceExtFuzzTest(uint8_t* data, size_t size)
{
    if ((size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    if (service == nullptr) {
        SLOGI("check service null, try create");
        service = new AVSessionService(AVSESSION_SERVICE_ID);
    }
    if (service == nullptr) {
        SLOGE("service is null, return");
        return;
    }
    SuperLauncherTest();
    AVSessionServiceExtFuzzTest001();
    AVSessionServiceExtFuzzTest002();
    AVSessionServiceExtFuzzTest003();
    AVSessionSystemAbilityLoadCallbackTest();
    AVSessionDeviceStateCallbackTest();
}

void AVSessionServiceExtRemoteRequest(uint8_t* data, size_t size)
{
    auto avSessionServiceExt = std::make_unique<AVSessionServiceExtFuzzer>();
    if (avSessionServiceExt == nullptr) {
        SLOGI("avSessionServiceExt is null");
        return;
    }
    avSessionServiceExt->AVSessionServiceExtFuzzTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    AVSessionServiceExtRemoteRequest(data, size);
    return 0;
}
}
