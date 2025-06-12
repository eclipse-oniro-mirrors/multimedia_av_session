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

#include "migrateavsession_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_service.h"
#include "migrate_avsession_server.h"
#include "migrate_avsession_manager.h"
#include "system_ability_definition.h"
#include "securec.h"

namespace OHOS::AVSession {
static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;
constexpr auto MIN_RANDOM_NUM = 2;

static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;
static std::shared_ptr<MigrateAVSessionServer> migrateServer_;

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

static std::string GenerateString(size_t target_len)
{
    if (RAW_DATA == nullptr || target_len == 0) {
        return "";
    }
    const size_t available_len = (g_dataSize > g_pos) ? (g_dataSize - g_pos) : 0;
    const size_t copy_len = std::min(target_len, available_len);

    if (copy_len == 0) {
        return "";
    }
    std::vector<char> buffer(copy_len + 1, '\0');
    errno_t ret = memcpy_s(buffer.data(), buffer.size(),
                        RAW_DATA + g_pos, copy_len);
    if (ret != EOK) {
        return "";
    }
    g_pos += copy_len;
    return std::string(buffer.data());
}

void ConnectProxyTest()
{
    int32_t sessionId = GetData<uint8_t>();
    std::string scene = std::to_string(GetData<uint8_t>());
    std::string deviceId = std::to_string(GetData<uint8_t>());

    MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(scene, migrateServer_);

    migrateServer_->ConnectProxy(sessionId);
    migrateServer_->OnConnectProxy(deviceId);
    migrateServer_->OnConnectSession(sessionId);
    migrateServer_->OnDisconnectProxy(deviceId);

    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = std::to_string(GetData<uint8_t>());
    descriptor.sessionType_ = GetData<uint8_t>();
    descriptor.sessionTag_ = std::to_string(GetData<uint8_t>());
    descriptor.elementName_.SetBundleName(std::to_string(GetData<uint8_t>()));

    migrateServer_->OnSessionCreate(descriptor);
    migrateServer_->OnSessionRelease(descriptor);
    migrateServer_->OnTopSessionChange(descriptor);
    int32_t uid = GetData<uint8_t>();
    migrateServer_->OnAudioSessionChecked(uid);

    migrateServer_->OnHistoricalRecordChange();
    MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(scene);
}

void HandleFocusMetaDataChangeTest()
{
    std::string sessionId = std::to_string(GetData<uint8_t>());
    AVMetaData data;
    data.SetAVQueueName(std::to_string(GetData<uint8_t>()));
    migrateServer_->HandleFocusMetaDataChange(sessionId, data);
}

void OnMetaDataChangeTest()
{
    constexpr int kMS_PER_SEC = 1000;
    AVMetaData meta;
    auto randomNum = GetData<uint32_t>();
    meta.SetAssetId(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetTitle("titile_" + std::to_string(GetData<uint8_t>()));
    meta.SetArtist(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetAuthor(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetAlbum(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetComposer(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetDuration(GetData<uint8_t>() * kMS_PER_SEC);
    meta.SetPublishDate(GetData<double>());
    meta.SetDisplayTags(GetData<int32_t>());
    meta.SetSkipIntervals(GetData<int32_t>());

    std::vector<std::string> drmSchemes;
    drmSchemes.push_back("drm_" + to_string(GetData<uint32_t>()));
    meta.SetDrmSchemes(drmSchemes);

    std::string playerId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->OnMetaDataChange(playerId, meta);

    std::string sessionId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->HandleFocusMetaDataChange(sessionId, meta);
    migrateServer_->DoMetaDataSyncToRemote(meta);
}

void OnPlaybackStateChangedTest()
{
    AVPlaybackState state;

    std::vector<int32_t> playbackState {
        AVPlaybackState::PLAYBACK_STATE_INITIAL,
        AVPlaybackState::PLAYBACK_STATE_PREPARE,
        AVPlaybackState::PLAYBACK_STATE_PLAY,
        AVPlaybackState::PLAYBACK_STATE_PAUSE,
        AVPlaybackState::PLAYBACK_STATE_FAST_FORWARD,
        AVPlaybackState::PLAYBACK_STATE_REWIND,
        AVPlaybackState::PLAYBACK_STATE_STOP,
        AVPlaybackState::PLAYBACK_STATE_COMPLETED,
        AVPlaybackState::PLAYBACK_STATE_RELEASED,
        AVPlaybackState::PLAYBACK_STATE_ERROR,
        AVPlaybackState::PLAYBACK_STATE_IDLE,
        AVPlaybackState::PLAYBACK_STATE_BUFFERING,
        AVPlaybackState::PLAYBACK_STATE_MAX
    };
    auto randomNum = GetData<uint32_t>();
    state.SetState(playbackState[randomNum % playbackState.size()]);
    state.SetSpeed(GetData<double>());
    state.SetPosition(AVPlaybackState::Position{GetData<int64_t>(), GetData<int64_t>()});
    state.SetBufferedTime(GetData<int64_t>());
    state.SetLoopMode(GetData<int32_t>());
    state.SetFavorite(GetData<bool>());
    state.SetActiveItemId(GetData<int32_t>());
    state.SetVolume(GetData<int32_t>());
    state.SetMaxVolume(GetData<int32_t>());
    state.SetMuted(GetData<bool>());
    state.SetDuration(GetData<int32_t>());
    state.SetVideoWidth(GetData<int32_t>());
    state.SetVideoHeight(GetData<int32_t>());
    state.SetExtras(std::make_shared<AAFwk::WantParams>());

    std::string playerId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->OnPlaybackStateChanged(playerId, state);

    std::string sessionId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->HandleFocusPlaybackStateChange(sessionId, state);
    migrateServer_->DoPlaybackStateSyncToRemote(state);
}

void StopObserveControllerChangedTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string deviceId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->StopObserveControllerChanged(deviceId);
}

void SendRemoteControllerListTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string deviceId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->SendRemoteControllerList(deviceId);
}

void SendRemoteHistorySessionListTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string deviceId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->SendRemoteHistorySessionList(deviceId);
}

void ClearRemoteControllerListTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string deviceId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->ClearRemoteControllerList(deviceId);
}

void ClearRemoteHistorySessionListTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string deviceId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->ClearRemoteHistorySessionList(deviceId);
}

void ResetSupportCrossMediaPlayTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string extraInfo = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->ResetSupportCrossMediaPlay(extraInfo);
}

//migrate_avsession_server_for_next.cpp
void LocalFrontSessionArriveTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string sessionId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->LocalFrontSessionArrive(sessionId);
}

void LocalFrontSessionChangeTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string sessionId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->LocalFrontSessionChange(sessionId);
}

void LocalFrontSessionLeaveTest()
{
    auto randomNum = GetData<uint32_t>();
    std::string sessionId = GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize);
    migrateServer_->LocalFrontSessionLeave(sessionId);
}

void DoMediaImageSyncToRemoteTest()
{
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    if (innerPixelMap == nullptr) {
        SLOGI("innerPixelMap is null");
        return;
    }

    std::vector<uint8_t> imgBuffer;
    for(size_t i = 0; i < g_dataSize; ++i) {
        imgBuffer.push_back(GetData<uint8_t>());
    }
    innerPixelMap->SetInnerImgBuffer(imgBuffer);
    migrateServer_->DoMediaImageSyncToRemote(innerPixelMap);
}

void DoValidCommandsSyncToRemoteTest()
{
    std::vector<int32_t> commands;
    commands.push_back(GetData<int32_t>());
    commands.push_back(GetData<int32_t>());
    commands.push_back(GetData<int32_t>());

    migrateServer_->DoValidCommandsSyncToRemote(commands);
}

void OnBytesReceivedTest()
{
    auto randomNum = GetData<uint32_t>();
    randomNum = (randomNum < MIN_RANDOM_NUM) ? MIN_RANDOM_NUM : randomNum;
    std::string deviceId = GenerateString(randomNum % g_dataSize);
    std::string data = GenerateString(randomNum % g_dataSize);
    std::vector<int32_t> commands {
        SYNC_CONTROLLER_LIST,
        SYNC_CONTROLLER_LIST,
        SYNC_COMMAND,
        SYNC_HEARTBEAT,
        COLD_START
    };
    data[1] = commands[static_cast<uint32_t> (randomNum) % commands.size()];
    migrateServer_->OnBytesReceived(deviceId, data);
}

void ProcFromNextTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);

    std::string deviceId = to_string(provider.ConsumeIntegral<uint32_t>());
    std::string data = provider.ConsumeRandomLengthString();
    if (data.length() < MIN_SIZE_NUM) {
        return;
    }
    data[1]  = static_cast<char>(provider.ConsumeIntegralInRange(SYNC_CONTROLLER_LIST, SYNC_FOCUS_BUNDLE_IMG));
    migrateServer_->ProcFromNext(deviceId, data);
}

void ProcControlCommandFromNextTest()
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "CommandCode", 5);
    cJSON_AddStringToObject(json, "CommandArgs", "test_arg");
    migrateServer_->ProcControlCommandFromNext(json);
    cJSON_Delete(json);
}

void ProcessColdStartFromNextTest()
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "BundleName", "test_bundleName");
    migrateServer_->ProcessColdStartFromNext(json);
    cJSON_Delete(json);
}

void ProcessMediaControlNeedStateFromNextTest()
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "NeedState", "test_needState");
    migrateServer_->ProcessMediaControlNeedStateFromNext(json);
    cJSON_Delete(json);
}

void ConvertAudioDeviceDescriptorsToJsonTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    AudioDeviceDescriptors devices;
    AudioDeviceDescriptorWithSptr device = std::make_shared<AudioDeviceDescriptor>();
    device->deviceType_ = static_cast<AudioStandard::DeviceType>(provider.ConsumeIntegralInRange<int>(0,
        AudioStandard::DeviceType::DEVICE_TYPE_USB_ARM_HEADSET));
    device->macAddress_ = provider.ConsumeRandomLengthString();
    device->networkId_ = provider.ConsumeRandomLengthString();
    device->deviceRole_ = static_cast<AudioStandard::DeviceRole>(provider.ConsumeIntegralInRange<int>(
        AudioStandard::DeviceRole::INPUT_DEVICE,
        AudioStandard::DeviceRole::OUTPUT_DEVICE));
    device->deviceName_ = provider.ConsumeRandomLengthString();
    device->deviceCategory_ = static_cast<AudioStandard::DeviceCategory>(provider.ConsumeIntegralInRange<int>(
        AudioStandard::DeviceCategory::CATEGORY_DEFAULT,
        AudioStandard::DeviceCategory::BT_UNWEAR_HEADPHONE));
    devices.push_back(device);

    MigrateAVSessionServer::ConvertAudioDeviceDescriptorsToJson(devices);
}

void VolumeControlCommandTest()
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "AudioVolume", 50);
    migrateServer_->VolumeControlCommand(json);
    cJSON_Delete(json);
}

void SwitchAudioDeviceCommandTest()
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "AudioDeviceCategory", AudioStandard::DeviceCategory::CATEGORY_DEFAULT);
    cJSON_AddNumberToObject(json, "AudioDeviceType", AudioStandard::DeviceType::DEVICE_TYPE_USB_ARM_HEADSET);
    cJSON_AddNumberToObject(json, "AudioDeviceRole", AudioStandard::DeviceRole::OUTPUT_DEVICE);
    cJSON_AddStringToObject(json, "AudioNetworkId", "test_network_id");
    cJSON_AddStringToObject(json, "AudioDeviceName", "test_device_name");
    cJSON_AddStringToObject(json, "AudioMacAddress", "test_mac_address");
    migrateServer_->SwitchAudioDeviceCommand(json);
    cJSON_Delete(json);
}

void RegisterAudioCallbackAndTriggerTest()
{
    migrateServer_->RegisterAudioCallbackAndTrigger();
    migrateServer_->UnregisterAudioCallback();

    migrateServer_->DoPostTasksClear();
}

void MigrateAVSessionFuzzerTest()
{
    if(migrateServer_ == nullptr) {
        migrateServer_ = std::make_shared<MigrateAVSessionServer>();
    }
    if (migrateServer_ == nullptr) {
        SLOGI("server is null");
        return;
    }
    sptr<AVSessionService> avservice_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    if (!avservice_) {
        SLOGI("service is null");
        return;
    }
    migrateServer_->Init(avservice_);

    ConnectProxyTest();
    HandleFocusMetaDataChangeTest();
    OnMetaDataChangeTest();
    OnPlaybackStateChangedTest();
    SendRemoteControllerListTest();
    SendRemoteHistorySessionListTest();
    ClearRemoteControllerListTest();
    ClearRemoteHistorySessionListTest();
    ResetSupportCrossMediaPlayTest();

    LocalFrontSessionArriveTest();
    LocalFrontSessionChangeTest();
    LocalFrontSessionLeaveTest();
    DoMediaImageSyncToRemoteTest();
    DoValidCommandsSyncToRemoteTest();
    OnBytesReceivedTest();

    ProcFromNextTest();
    ProcControlCommandFromNextTest();
    ProcessColdStartFromNextTest();
    ProcessMediaControlNeedStateFromNextTest();
    ConvertAudioDeviceDescriptorsToJsonTest();
    VolumeControlCommandTest();
    SwitchAudioDeviceCommandTest();
    RegisterAudioCallbackAndTriggerTest();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return 0;
    }

    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    MigrateAVSessionFuzzerTest();
    return 0;
}
} // namespace OHOS::AVSession
