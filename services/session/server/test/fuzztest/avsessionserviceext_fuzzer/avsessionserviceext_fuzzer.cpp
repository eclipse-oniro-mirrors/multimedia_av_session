/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
static size_t g_totalSize = 0;
static size_t g_sizePos;
static size_t g_dataSize = 0;
static size_t g_pos = 0;
constexpr size_t STRING_MAX_LENGTH = 128;

/*
* describe: get data from FUZZ untrusted data(RAW_DATA) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

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
    ErrCode OnSessionCreate(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; };
    ErrCode OnSessionRelease(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; };
    ErrCode OnTopSessionChange(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; };
    ErrCode OnAudioSessionChecked(const int32_t uid) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceLogEvent(const int32_t eventId, const int64_t param) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceOffline(const std::string& deviceId) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceStateChange(const DeviceState& deviceState) override { return AVSESSION_SUCCESS; };
    ErrCode OnRemoteDistributedSessionChange(
        const std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers) override { return AVSESSION_SUCCESS; };
    ErrCode OnActiveSessionChanged(
        const std::vector<AVSessionDescriptor> &descriptors) override { return AVSESSION_SUCCESS; };
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

#ifdef DEVICE_MANAGER_ENABLE
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
    std::string localFrontSessionId = provider.ConsumeRandomLengthString(DM_MAX_DEVICE_ID_LEN);

    service->OnAddSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        deviceInfo.deviceId);
    service->ProcessTargetMigrate(isOnline, deviceInfo);
    service->DoConnectProcessWithMigrate(deviceInfo);
    service->DoConnectProcessWithMigrateServer(deviceInfo);
    service->NotifyLocalFrontSessionChangeForMigrate(localFrontSessionId);
    service->DoHisMigrateServerTransform(networkId);
    service->DoDisconnectProcessWithMigrate(deviceInfo);
    service->DoDisconnectProcessWithMigrateServer(deviceInfo);
    service->DoRemoteAVSessionLoad(deviceId);
}
#endif

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
#ifdef DEVICE_MANAGER_ENABLE
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = provider.ConsumeIntegral<int32_t>();
    callback.OnDeviceOnline(deviceInfo);
    callback.OnDeviceReady(deviceInfo);
    callback.OnDeviceOffline(deviceInfo);
    callback.OnDeviceChanged(deviceInfo);
#endif
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
#ifdef DEVICE_MANAGER_ENABLE
    AVSessionServiceExtFuzzTest002();
#endif
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

void AVSessionServiceExtFuzzer::SucceedSuperLauncherFuzzTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    CHECK_AND_RETURN(service != nullptr);
    std::string deviceId = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string extraInfo = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    service->SucceedSuperLauncher(deviceId, extraInfo);
}

void AVSessionServiceExtFuzzer::NotifyDeviceStateChangeFuzzTest()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CHECK_AND_RETURN(service != nullptr);
    auto deviceState = OHOS::AVSession::DeviceState();
    service->NotifyDeviceStateChange(deviceState);
#endif
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
    AVSessionServiceExtFuzzer::SucceedSuperLauncherFuzzTest,
    AVSessionServiceExtFuzzer::NotifyDeviceStateChangeFuzzTest,
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

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (data == nullptr || (size < MIN_SIZE_NUM)) {
        return 0;
    }

    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    AVSessionServiceExtRemoteRequest(data, size);
    FuzzTest(data, size);
    return 0;
}
}
