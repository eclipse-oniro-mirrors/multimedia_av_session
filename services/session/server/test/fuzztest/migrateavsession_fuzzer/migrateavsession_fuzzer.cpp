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
AppExecFwk::ElementName elementName;
sptr<AVSessionItem> avsessionHere_ = nullptr;
static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    if (g_pos >= g_dataSize) {
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
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    std::string sessionId = std::to_string(GetData<uint8_t>());
    AVMetaData data;
    data.SetAVQueueName(std::to_string(GetData<uint8_t>()));
    std::shared_ptr<AVSessionPixelMap> mediaImage = make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer;
    constexpr int maxSize = 1024;
    auto size = provider.ConsumeIntegralInRange(1, maxSize);
    imgBuffer.resize(size);
    for (size_t i = 0; i < imgBuffer.size(); ++i) {
        imgBuffer[i] = GetData<uint8_t>();
    }
    mediaImage->SetInnerImgBuffer(imgBuffer);
    data.SetMediaImage(mediaImage);
    migrateServer_->HandleFocusMetaDataChange(sessionId, data);
}

void OnMetaDataChangeTest()
{
    constexpr int kMsPerSec = 1000;
    AVMetaData meta;
    auto randomNum = GetData<uint32_t>();
    meta.SetAssetId(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetTitle("titile_" + std::to_string(GetData<uint8_t>()));
    meta.SetArtist(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetAuthor(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetAlbum(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetComposer(GenerateString(static_cast<uint32_t> (randomNum) % g_dataSize));
    meta.SetDuration(GetData<uint8_t>() * kMsPerSec);
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
    bool binaryChoose = GetData<bool>();
    if (binaryChoose) {
        meta.metaMask_.set(AVMetaData::META_KEY_ARTIST);
    } else {
        meta.metaMask_.set(AVMetaData::META_KEY_SUBTITLE);
    }
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
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    if (innerPixelMap == nullptr) {
        SLOGI("innerPixelMap is null");
        return;
    }

    constexpr size_t maxSize = 1024 * 1024; // 1MB
    auto imgSize = provider.ConsumeIntegralInRange<size_t>(1, maxSize);
    std::vector<uint8_t> imgBuffer(imgSize);
    for (size_t i = 0; i < imgBuffer.size(); ++i) {
        imgBuffer[i] = provider.ConsumeIntegral<uint8_t>();
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
    std::vector<int32_t> messageType {
        SYNC_COMMAND,
        SYNC_SET_VOLUME_COMMAND,
        SYNC_SWITCH_AUDIO_DEVICE_COMMAND,
        COLD_START,
        SYNC_MEDIA_CONTROL_NEED_STATE,
        provider.ConsumeIntegral<int32_t>()
    };
    data[1]  = messageType[provider.ConsumeIntegral<uint32_t>() % messageType.size()];
    migrateServer_->ProcFromNext(deviceId, data);
}

void ProcControlCommandFromNextTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "CommandCode", provider.ConsumeIntegral<int32_t>());
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
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "AudioVolume", provider.ConsumeIntegral<uint32_t>());
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

void UpdateFrontSessionInfoToRemoteTest(sptr<AVSessionService> service)
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    service->AddAvQueueInfoToFile(*avsessionHere_);
    sptr<IRemoteObject> avControllerItemObj;
    std::string sessionId = provider.ConsumeRandomLengthString();
    uint32_t ret = service->CreateControllerInner(avsessionHere_->GetSessionId(), avControllerItemObj);
    if (ret != AVSESSION_SUCCESS) {
        return;
    }
    sptr<AVControllerItem> controller = (sptr<AVControllerItem>&)avControllerItemObj;
    if (!controller) {
        return;
    }
    migrateServer_->UpdateFrontSessionInfoToRemote(controller);
    migrateServer_->DoBundleInfoSyncToRemote(controller);
}

void HandleFocusValidCommandChangeTest()
{
    FuzzedDataProvider provider(RAW_DATA, g_dataSize);
    std::string sessionId = provider.ConsumeRandomLengthString();
    std::vector<int32_t> cmds;
    cmds.push_back(provider.ConsumeIntegral<int32_t>());
    migrateServer_->HandleFocusValidCommandChange(sessionId, cmds);
}

void CoverExceptionPathTest()
{
    if (migrateServer_ == nullptr) {
        return;
    }

    std::vector<int32_t> cmds;
    std::string sessionId = std::to_string(GetData<uint8_t>());
    migrateServer_->HandleFocusValidCommandChange(sessionId, cmds);
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    if (innerPixelMap != nullptr) {
        migrateServer_->DoMediaImageSyncToRemote(innerPixelMap);
    }
    migrateServer_->UpdateEmptyInfoToRemote();
    migrateServer_->ProcFromNext("", "");
    migrateServer_->ProcControlCommandFromNext(nullptr);
    migrateServer_->ProcessColdStartFromNext(nullptr);
    migrateServer_->ProcessMediaControlNeedStateFromNext(nullptr);
    AudioDeviceDescriptors devices;
    devices.push_back(nullptr);
    cJSON *json = MigrateAVSessionServer::ConvertAudioDeviceDescriptorsToJson(devices);
    cJSON_Delete(json);
    migrateServer_->VolumeControlCommand(nullptr);
    migrateServer_->SwitchAudioDeviceCommand(nullptr);
}

void ProcControlCommandFromNextTestExt()
{
    if (migrateServer_ == nullptr) {
        return;
    }

    sptr<AVControllerItem> avcontroller = new (std::nothrow) AVControllerItem(0, nullptr);
    if (avcontroller == nullptr) {
        return;
    }
    std::string sessionId = migrateServer_->lastSessionId_;
    cJSON* json = cJSON_CreateObject();
    if (json == nullptr) {
        return;
    }
    migrateServer_->playerIdToControllerMap_.insert({sessionId, avcontroller});
    cJSON_AddNumberToObject(json, "CommandCode", AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
    cJSON_AddStringToObject(json, "CommandArgs", "test_arg");
    migrateServer_->ProcControlCommandFromNext(json);
    migrateServer_->playerIdToControllerMap_.erase(sessionId);
    cJSON_Delete(json);
}

void ProcessMediaControlNeedStateFromNextExt()
{
    if (migrateServer_ == nullptr) {
        return;
    }

    cJSON* json = cJSON_CreateObject();
    if (json == nullptr) {
        return;
    }
    cJSON_AddBoolToObject(json, NEED_STATE, true);
    migrateServer_->isNeedByRemote.store(false);
    migrateServer_->ProcessMediaControlNeedStateFromNext(json);
    cJSON_Delete(json);
}

void TestFunc()
{
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
    CoverExceptionPathTest();
    ProcControlCommandFromNextTestExt();
    ProcessMediaControlNeedStateFromNextExt();
}

void MigrateAVSessionFuzzerTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size > MAX_CODE_LEN) {
        return;
    }
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;
    if(migrateServer_ == nullptr) {
        migrateServer_ = std::make_shared<MigrateAVSessionServer>();
    }
    if (migrateServer_ == nullptr) {
        return;
    }
    sptr<AVSessionService> avservice_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    if (!avservice_) {
        return;
    }
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    if (avsessionHere_ == nullptr) {
        avsessionHere_ = avservice_->CreateSessionInner(g_testSessionTag,
            AVSession::SESSION_TYPE_AUDIO, false, elementName);
    }
    if (avsessionHere_ == nullptr) {
        return;
    }
    migrateServer_->Init(avservice_);
    TestFunc();
    UpdateFrontSessionInfoToRemoteTest(avservice_);
    avservice_->OnStop();
    SLOGI("MigrateAVSessionFuzzerTest done");
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }

    /* Run your code on data */
    MigrateAVSessionFuzzerTest(data, size);
    return 0;
}
} // namespace OHOS::AVSession
