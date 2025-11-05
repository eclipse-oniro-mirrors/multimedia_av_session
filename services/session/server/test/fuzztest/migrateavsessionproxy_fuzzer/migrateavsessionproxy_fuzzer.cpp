/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "migrateavsessionproxy_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "avsession_service.h"
#include "migrate_avsession_server.h"
#include "int_wrapper.h"
#include "bool_wrapper.h"
#include "string_wrapper.h"
#include "softbus_session_utils.h"

namespace OHOS::AVSession {
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t MAX_STRING_LEN = 8;

static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos = 0;
static std::shared_ptr<MigrateAVSessionProxy> g_MigrateAVSessionProxy {nullptr};
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";

struct CJsonDeleter {
    void operator()(cJSON *json) const
    {
        if (json) {
            cJSON_Delete(json);
        }
    }
};
using CJsonUniquePtr = std::unique_ptr<cJSON, CJsonDeleter>;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || g_pos >= g_dataSize || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

static std::string GenerateString(size_t targetLen)
{
    if (RAW_DATA == nullptr || targetLen == 0) {
        return "";
    }
    const size_t availableLen = (g_dataSize > g_pos) ? (g_dataSize - g_pos) : 0;
    const size_t copyLen = std::min(targetLen, availableLen);
    if (copyLen == 0) {
        return "";
    }
    std::vector<char> buffer(copyLen + 1, '\0');
    errno_t ret = memcpy_s(buffer.data(), buffer.size(), RAW_DATA + g_pos, copyLen);
    if (ret != EOK) {
        return "";
    }
    g_pos += copyLen;
    return std::string(buffer.data());
}

void HandlePlayStateCbTest()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }
    std::string playerId = std::to_string(GetData<uint8_t>());
    std::shared_ptr<AVSessionObserver> cb = std::make_shared<AVSessionObserver>(playerId, g_MigrateAVSessionProxy);
    if (cb == nullptr) {
        return;
    }
    AVControlCommand cmd;
    cb->OnPlay(cmd);
    cb->OnPause();
    cb->OnPlayNext(cmd);
    cb->OnPlayPrevious(cmd);
    std::string mediaId = std::to_string(GetData<uint8_t>());
    cb->OnToggleFavorite(mediaId);
    std::string commonCommand = std::to_string(GetData<uint8_t>());
    AAFwk::WantParams commandArgs = {};
    cb->OnCommonCommand(commonCommand, commandArgs);
}

void HandleControllerCallback()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }
    const static std::vector<std::string> eventMap = {
        AUDIO_SET_VOLUME,
        AUDIO_SELECT_OUTPUT_DEVICE,
        AUDIO_GET_VOLUME,
        AUDIO_GET_AVAILABLE_DEVICES,
        AUDIO_GET_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO,
        SESSION_COLD_START_FROM_PROXY,
        SESSION_SET_MEDIACONTROL_NEED_STATE,
        AUDIO_MAC_ADDRESS
    };
    auto func = g_MigrateAVSessionProxy->MigrateAVSessionProxyControllerCallback();
    if (func) {
        size_t index = (GetData<size_t>()) % eventMap.size();
        AAFwk::WantParams extras = {};
        func(eventMap[index], extras);
    }
}

void HandleControllerCallbackExt()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }

    AAFwk::WantParams extras = {};
    auto volumeNum = OHOS::AAFwk::Integer::Box(GetData<int32_t>());
    extras.SetParam(AUDIO_SET_VOLUME, volumeNum);
    auto deviceStr = OHOS::AAFwk::String::Box(GenerateString(MAX_STRING_LEN));
    extras.SetParam(AUDIO_SELECT_OUTPUT_DEVICE, deviceStr);
    auto isNeed = OHOS::AAFwk::Boolean::Box(GetData<bool>());
    extras.SetParam(MEDIACONTROL_NEED_STATE, isNeed);
    g_MigrateAVSessionProxy->SetVolume(extras);
    g_MigrateAVSessionProxy->SelectOutputDevice(extras);
    g_MigrateAVSessionProxy->NotifyMediaControlNeedStateChange(extras);
    g_MigrateAVSessionProxy->CheckMediaAlive();
}

void ProcessSessionInfoTest()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }

    g_MigrateAVSessionProxy->ProcessSessionInfo(nullptr);

    auto defaultMsg = CJsonUniquePtr(SoftbusSessionUtils::GetNewCJSONObject());
    if (defaultMsg == nullptr) {
        return;
    }
    g_MigrateAVSessionProxy->ProcessSessionInfo(defaultMsg.get());
    std::string bundleName = std::string(g_testAnotherBundleName) + "|" + std::to_string(GetData<int32_t>());
    SoftbusSessionUtils::AddStringToJson(defaultMsg.get(), MIGRATE_BUNDLE_NAME, bundleName);
    SoftbusSessionUtils::AddStringToJson(defaultMsg.get(), MIGRATE_ABILITY_NAME, g_testAnotherAbilityName);
    SoftbusSessionUtils::AddStringToJson(defaultMsg.get(), MIGRATE_SESSION_ID, std::to_string(GetData<uint32_t>()));
    g_MigrateAVSessionProxy->ProcessSessionInfo(defaultMsg.get());
}

void ProcessMetaDataTest()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }

    g_MigrateAVSessionProxy->ProcessMetaData(nullptr);

    auto defaultMsg = CJsonUniquePtr(SoftbusSessionUtils::GetNewCJSONObject());
    if (defaultMsg == nullptr) {
        return;
    }
    SoftbusSessionUtils::AddStringToJson(defaultMsg.get(), METADATA_ASSET_ID, "");
    SoftbusSessionUtils::AddStringToJson(defaultMsg.get(), METADATA_TITLE, "");
    SoftbusSessionUtils::AddStringToJson(defaultMsg.get(), METADATA_ARTIST, "");
    g_MigrateAVSessionProxy->ProcessMetaData(defaultMsg.get());
    SoftbusSessionUtils::AddStringToJson(defaultMsg.get(), METADATA_ASSET_ID, GenerateString(MAX_STRING_LEN));
    g_MigrateAVSessionProxy->ProcessMetaData(defaultMsg.get());
}

void ProcessPlaybackStateTest()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }

    g_MigrateAVSessionProxy->ProcessPlaybackState(nullptr);

    auto defaultMsg = CJsonUniquePtr(SoftbusSessionUtils::GetNewCJSONObject());
    if (defaultMsg == nullptr) {
        return;
    }
    SoftbusSessionUtils::AddIntToJson(defaultMsg.get(), PLAYBACK_STATE, GetData<int32_t>());
    SoftbusSessionUtils::AddBoolToJson(defaultMsg.get(), FAVOR_STATE, GetData<bool>());
    g_MigrateAVSessionProxy->ProcessPlaybackState(defaultMsg.get());
}

void ProcessValidCommandsTest()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }

    g_MigrateAVSessionProxy->ProcessValidCommands(nullptr);

    auto defaultMsg = CJsonUniquePtr(SoftbusSessionUtils::GetNewCJSONObject());
    if (defaultMsg == nullptr) {
        return;
    }
    std::string commandsStr = std::to_string(GetData<uint16_t>());
    SoftbusSessionUtils::AddStringToJson(defaultMsg.get(), VALID_COMMANDS, commandsStr);
    g_MigrateAVSessionProxy->ProcessValidCommands(defaultMsg.get());
}

void ProcessVolumeControlCommandTest()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }

    g_MigrateAVSessionProxy->ProcessVolumeControlCommand(nullptr);

    auto defaultMsg = CJsonUniquePtr(SoftbusSessionUtils::GetNewCJSONObject());
    if (defaultMsg == nullptr) {
        return;
    }
    g_MigrateAVSessionProxy->ProcessVolumeControlCommand(defaultMsg.get());
    SoftbusSessionUtils::AddIntToJson(defaultMsg.get(), AUDIO_VOLUME, GetData<int32_t>());
    g_MigrateAVSessionProxy->ProcessVolumeControlCommand(defaultMsg.get());
}

void ProcessDevicesTest()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }

    g_MigrateAVSessionProxy->ProcessAvailableDevices(nullptr);
    g_MigrateAVSessionProxy->ProcessPreferredOutputDevice(nullptr);

    auto defaultMsg = CJsonUniquePtr(SoftbusSessionUtils::GetNewCJSONObject());
    if (defaultMsg == nullptr) {
        return;
    }
    cJSON *jsonArray = SoftbusSessionUtils::GetNewCJSONArray();
    if (jsonArray == nullptr) {
        return;
    }
    auto device = std::make_shared<AudioDeviceDescriptor>();
    cJSON *jsonObject = MigrateAVSessionServer::ConvertAudioDeviceDescriptorToJson(device);
    cJSON_InsertItemInArray(jsonArray, 0, jsonObject);

    cJSON *jsObject = defaultMsg.get();
    SoftbusSessionUtils::AddJsonArrayToJson(jsObject, MEDIA_AVAILABLE_DEVICES_LIST, jsonArray);
    g_MigrateAVSessionProxy->ProcessAvailableDevices(defaultMsg.get());
    g_MigrateAVSessionProxy->ProcessPreferredOutputDevice(defaultMsg.get());
}

void ProcessImgTest()
{
    if (g_MigrateAVSessionProxy == nullptr) {
        return;
    }

    std::string strImg;
    g_MigrateAVSessionProxy->ProcessBundleImg(strImg);
    g_MigrateAVSessionProxy->ProcessMediaImage(strImg);
    strImg = std::to_string(GetData<uint32_t>()) + "|";
    g_MigrateAVSessionProxy->ProcessBundleImg(strImg);
    g_MigrateAVSessionProxy->ProcessMediaImage(strImg);
    strImg += GenerateString(MAX_STRING_LEN);
    g_MigrateAVSessionProxy->ProcessMediaImage(strImg);
}

void TestFunc()
{
    HandlePlayStateCbTest();
    HandleControllerCallback();
    HandleControllerCallbackExt();
    ProcessSessionInfoTest();
    ProcessMetaDataTest();
    ProcessPlaybackStateTest();
    ProcessValidCommandsTest();
    ProcessVolumeControlCommandTest();
    ProcessDevicesTest();
    ProcessImgTest();
}

void MigrateAVSessionProxyFuzzerTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size > MAX_CODE_LEN) {
        return;
    }
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    if (g_MigrateAVSessionProxy == nullptr) {
        g_MigrateAVSessionProxy = MigrateAVSessionProxyTest::GetInstance().migrateAVSessionProxy_;
        if (g_MigrateAVSessionProxy != nullptr) {
            std::vector<sptr<IRemoteObject>> controllerList;
            g_MigrateAVSessionProxy->GetDistributedSessionControllerList(controllerList);
        }
    }
    TestFunc();
    SLOGI("MigrateAVSessionFuzzerTest done");
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }

    /* Run your code on data */
    MigrateAVSessionProxyFuzzerTest(data, size);
    return 0;
}
} // namespace OHOS::AVSession
