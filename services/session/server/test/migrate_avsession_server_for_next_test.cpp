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

#include <gtest/gtest.h>
#include <chrono>
#include <thread>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_log.h"
#include "migrate_avsession_constant.h"
#include "system_ability_definition.h"
#include "avsession_service.h"
#include "migrate_avsession_manager.h"
#include "migrate_avsession_server.h"
#include "softbus/softbus_session_utils.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static std::shared_ptr<MigrateAVSessionServer> g_MigrateAVSessionServer {nullptr};
static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};
static OHOS::sptr<AVSessionItem> g_AVSessionItem {nullptr};
static OHOS::sptr<AVControllerItem> g_AVControllerItem {nullptr};

class MigrateAVSessionServerForNextTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MigrateAVSessionServerForNextTest::SetUpTestCase()
{
    SLOGI("MigrateAVSessionServerForNextTest SetUpTestCase");
    g_MigrateAVSessionServer = std::make_shared<MigrateAVSessionServer>();
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID, true);
    g_AVSessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    g_AVControllerItem = g_AVSessionService->CreateNewControllerForSession(
        g_AVSessionItem->GetPid(), g_AVSessionItem);
}

void MigrateAVSessionServerForNextTest::TearDownTestCase()
{
    SLOGI("MigrateAVSessionServerForNextTest TearDownTestCase");
    g_AVSessionService->HandleSessionRelease(g_AVSessionItem->GetSessionId());
    g_AVControllerItem->Destroy();
    g_AVSessionItem->Destroy();
}

void MigrateAVSessionServerForNextTest::SetUp()
{
    SLOGI("MigrateAVSessionServerForNextTest SetUp");
}

void MigrateAVSessionServerForNextTest::TearDown()
{
    SLOGI("MigrateAVSessionServerForNextTest TearDown");
}

/**
 * @tc.name: LocalFrontSessionArrive001
 * @tc.desc: input sessionId to LocalFrontSessionArrive
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, LocalFrontSessionArrive001, TestSize.Level0)
{
    std::string sessionId = "";
    g_MigrateAVSessionServer->LocalFrontSessionArrive(sessionId);
    sleep(1);
    EXPECT_EQ(sessionId.size(), 0);
}

/**
 * @tc.name: LocalFrontSessionArrive002
 * @tc.desc: input sessionId to LocalFrontSessionArrive
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, LocalFrontSessionArrive002, TestSize.Level0)
{
    std::string sessionId = "test";
    auto observer = std::make_shared<AVControllerObserver>(sessionId);
    g_MigrateAVSessionServer->playerIdToControllerCallbackMap_.insert({sessionId, observer});
    g_MigrateAVSessionServer->playerIdToControllerMap_.insert({sessionId, g_AVControllerItem});
    g_MigrateAVSessionServer->LocalFrontSessionArrive(sessionId);
    sleep(1);
    EXPECT_EQ(sessionId.size(), 4);
}

/**
 * @tc.name: LocalFrontSessionArrive003
 * @tc.desc: input sessionId to LocalFrontSessionArrive
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, LocalFrontSessionArrive003, TestSize.Level0)
{
    std::string sessionId = "test";
    auto observer = std::make_shared<AVControllerObserver>(sessionId);
    g_MigrateAVSessionServer->playerIdToControllerCallbackMap_.insert({sessionId, observer});
    g_MigrateAVSessionServer->playerIdToControllerMap_.insert({sessionId, g_AVControllerItem});
    g_MigrateAVSessionServer->isSoftbusConnecting_ = true;
    g_MigrateAVSessionServer->LocalFrontSessionArrive(sessionId);
    sleep(1);
    EXPECT_EQ(sessionId.size(), 4);
}

/**
 * @tc.name: LocalFrontSessionArrive004
 * @tc.desc: input sessionId to LocalFrontSessionArrive
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, LocalFrontSessionArrive004, TestSize.Level0)
{
    std::string sessionId = "test";
    auto observer = std::make_shared<AVControllerObserver>(sessionId);
    g_MigrateAVSessionServer->playerIdToControllerCallbackMap_.insert({sessionId, observer});
    g_MigrateAVSessionServer->playerIdToControllerMap_.insert({sessionId, g_AVControllerItem});
    g_MigrateAVSessionServer->isSoftbusConnecting_ = false;
    g_MigrateAVSessionServer->LocalFrontSessionArrive(sessionId);
    sleep(1);
    EXPECT_EQ(sessionId.size(), 4);
}

/**
 * @tc.name: LocalFrontSessionLeave001
 * @tc.desc: input sessionId to LocalFrontSessionLeave
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, LocalFrontSessionLeave001, TestSize.Level0)
{
    std::string sessionId = "";
    g_MigrateAVSessionServer->LocalFrontSessionLeave(sessionId);
    EXPECT_EQ(sessionId.size(), 0);
}

/**
 * @tc.name: LocalFrontSessionLeave002
 * @tc.desc: input sessionId to LocalFrontSessionLeave
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, LocalFrontSessionLeave002, TestSize.Level0)
{
    std::string sessionId = "test";
    g_MigrateAVSessionServer->LocalFrontSessionLeave(sessionId);
    EXPECT_EQ(sessionId.size(), 4);
}

/**
 * @tc.name: DoMetaDataSyncToRemote001
 * @tc.desc: input metadate to DoMetaDataSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoMetaDataSyncToRemote001, TestSize.Level0)
{
    AVMetaData data;
    data.SetAssetId("test");
    data.SetTitle("test");
    g_MigrateAVSessionServer->DoMetaDataSyncToRemote(data);
    EXPECT_EQ(data.GetAssetId(), "test");
}

/**
 * @tc.name: DoMetaDataSyncToRemote002
 * @tc.desc: input metadate to DoMetaDataSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoMetaDataSyncToRemote002, TestSize.Level0)
{
    AVMetaData data;
    data.SetAssetId("test");
    data.SetArtist("test");
    g_MigrateAVSessionServer->DoMetaDataSyncToRemote(data);
    EXPECT_EQ(data.GetAssetId(), "test");
}

/**
 * @tc.name: DoMetaDataSyncToRemote003
 * @tc.desc: input metadate to DoMetaDataSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoMetaDataSyncToRemote003, TestSize.Level0)
{
    AVMetaData data;
    data.SetAssetId("test");
    data.SetAuthor("test");
    g_MigrateAVSessionServer->DoMetaDataSyncToRemote(data);
    EXPECT_EQ(data.GetAssetId(), "test");
}

/**
 * @tc.name: DoMediaImageSyncToRemote001
 * @tc.desc: input innerPixelMap to DoMediaImageSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoMediaImageSyncToRemote001, TestSize.Level0)
{
    std::shared_ptr<AVSessionPixelMap> ptr = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    ptr->SetInnerImgBuffer(vec);
    g_MigrateAVSessionServer->DoMediaImageSyncToRemote(ptr);
    EXPECT_EQ(vec.size() > 0, true);
}

/**
 * @tc.name: DoMediaImageSyncToRemote002
 * @tc.desc: input innerPixelMap to DoMediaImageSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoMediaImageSyncToRemote002, TestSize.Level0)
{
    std::shared_ptr<AVSessionPixelMap> ptr = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {};
    ptr->SetInnerImgBuffer(vec);
    g_MigrateAVSessionServer->DoMediaImageSyncToRemote(ptr);
    EXPECT_EQ(vec.size() == 0, true);
}

/**
 * @tc.name: DoPlaybackStateSyncToRemote001
 * @tc.desc: input metadate to DoPlaybackStateSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoPlaybackStateSyncToRemote001, TestSize.Level0)
{
    AVPlaybackState data;
    data.SetState(1);
    g_MigrateAVSessionServer->DoPlaybackStateSyncToRemote(data);
    EXPECT_EQ(data.GetMask().test(AVPlaybackState::PLAYBACK_KEY_STATE), 1);
}

/**
 * @tc.name: DoPlaybackStateSyncToRemote002
 * @tc.desc: input metadate to DoPlaybackStateSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoPlaybackStateSyncToRemote002, TestSize.Level0)
{
    AVPlaybackState data;
    data.SetFavorite(true);
    g_MigrateAVSessionServer->DoPlaybackStateSyncToRemote(data);
    EXPECT_EQ(data.GetMask().test(AVPlaybackState::PLAYBACK_KEY_IS_FAVORITE), 1);
}

/**
 * @tc.name: DoPlaybackStateSyncToRemote003
 * @tc.desc: input metadate to DoPlaybackStateSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoPlaybackStateSyncToRemote003, TestSize.Level0)
{
    AVPlaybackState data;
    data.SetActiveItemId(1);
    g_MigrateAVSessionServer->DoPlaybackStateSyncToRemote(data);
    EXPECT_EQ(data.GetMask().test(AVPlaybackState::PLAYBACK_KEY_IS_FAVORITE), 0);
}

/**
 * @tc.name: DoBundleInfoSyncToRemote001
 * @tc.desc: input AVControllerItem to DoBundleInfoSyncToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, DoBundleInfoSyncToRemote001, TestSize.Level0)
{
    g_MigrateAVSessionServer->DoBundleInfoSyncToRemote(g_AVControllerItem);
    EXPECT_EQ(g_AVControllerItem != nullptr, true);
}

/**
 * @tc.name: UpdateFrontSessionInfoToRemote001
 * @tc.desc: input AVControllerItem to UpdateFrontSessionInfoToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, UpdateFrontSessionInfoToRemote001, TestSize.Level0)
{
    g_MigrateAVSessionServer->UpdateFrontSessionInfoToRemote(g_AVControllerItem);
    EXPECT_EQ(g_AVControllerItem != nullptr, true);
}

/**
 * @tc.name: UpdateFrontSessionInfoToRemote002
 * @tc.desc: input AVControllerItem to UpdateFrontSessionInfoToRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, UpdateFrontSessionInfoToRemote002, TestSize.Level0)
{
    AVMetaData metaData;
    g_AVSessionItem->SetAVMetaData(metaData);
    AVPlaybackState playbackState;
    g_AVSessionItem->SetAVPlaybackState(playbackState);
    g_MigrateAVSessionServer->UpdateFrontSessionInfoToRemote(g_AVControllerItem);
    EXPECT_EQ(g_AVControllerItem != nullptr, true);
}

/**
 * @tc.name: ProcFromNext001
 * @tc.desc: input string to ProcFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcFromNext001, TestSize.Level0)
{
    std::string deviceId = "";
    std::string data = "";
    g_MigrateAVSessionServer->ProcFromNext(deviceId, data);
    EXPECT_EQ(data.size() == 0, true);
}

/**
 * @tc.name: ProcFromNext002
 * @tc.desc: input string to ProcFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcFromNext002, TestSize.Level0)
{
    std::string deviceId = "0000";
    std::string str1(2, char(SYNC_COMMAND));
    std::string str2 = R"(
        {"test":1}
    )";
    std::string data = str1 + str2;
    g_MigrateAVSessionServer->ProcFromNext(deviceId, data);
    EXPECT_EQ(data.size() > 2, true);
}

/**
 * @tc.name: ProcFromNext003
 * @tc.desc: input string to ProcFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcFromNext003, TestSize.Level0)
{
    std::string deviceId = "0000";
    std::string str1(2, char(SYNC_SET_VOLUME_COMMAND));
    std::string str2 = R"(
        {"test":1}
    )";
    std::string data = str1 + str2;
    g_MigrateAVSessionServer->ProcFromNext(deviceId, data);
    EXPECT_EQ(data.size() > 2, true);
}

/**
 * @tc.name: ProcFromNext004
 * @tc.desc: input string to ProcFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcFromNext004, TestSize.Level0)
{
    std::string deviceId = "0000";
    std::string str1(2, char(SYNC_SWITCH_AUDIO_DEVICE_COMMAND));
    std::string str2 = R"(
        {"test":1}
    )";
    std::string data = str1 + str2;
    g_MigrateAVSessionServer->ProcFromNext(deviceId, data);
    EXPECT_EQ(data.size() > 2, true);
}

/**
 * @tc.name: ProcFromNext005
 * @tc.desc: input string to ProcFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcFromNext005, TestSize.Level0)
{
    std::string deviceId = "0000";
    std::string str1(2, char(COLD_START));
    std::string str2 = R"(
        {"test":1}
    )";
    std::string data = str1 + str2;
    g_MigrateAVSessionServer->ProcFromNext(deviceId, data);
    EXPECT_EQ(data.size() > 2, true);
}

/**
 * @tc.name: ProcFromNext006
 * @tc.desc: input string to ProcFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcFromNext006, TestSize.Level0)
{
    std::string deviceId = "0000";
    std::string str1(2, char(0));
    std::string str2 = R"(
        {"test":1}
    )";
    std::string data = str1 + str2;
    g_MigrateAVSessionServer->ProcFromNext(deviceId, data);
    EXPECT_EQ(data.size() > 2, true);
}

/**
 * @tc.name: ProcControlCommandFromNext001
 * @tc.desc: tset the member of ProcControlCommandFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcControlCommandFromNext001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddIntToJson(jsonValue, COMMAND_CODE, 1)) {
        SLOGE("AddIntToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionServer->ProcControlCommandFromNext(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, COMMAND_CODE), true);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcControlCommandFromNext002
 * @tc.desc: tset the member of ProcControlCommandFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcControlCommandFromNext002, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddIntToJson(jsonValue, COMMAND_ARGS, 1)) {
        SLOGE("AddIntToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionServer->ProcControlCommandFromNext(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, COMMAND_ARGS), true);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcControlCommandFromNext003
 * @tc.desc: tset the member of ProcControlCommandFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcControlCommandFromNext003, TestSize.Level0)
{
    std::string id = "001";
    g_MigrateAVSessionServer->lastSessionId_ = id;
    g_MigrateAVSessionServer->playerIdToControllerMap_[id] = g_AVControllerItem;

    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddIntToJson(jsonValue, COMMAND_CODE, 10)) {
        SLOGE("AddIntToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionServer->ProcControlCommandFromNext(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, COMMAND_CODE), true);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcControlCommandFromNext003
 * @tc.desc: tset the member of ProcControlCommandFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcControlCommandFromNext004, TestSize.Level0)
{
    std::string id = "001";
    g_MigrateAVSessionServer->lastSessionId_ = id;
    g_MigrateAVSessionServer->playerIdToControllerMap_[id] = g_AVControllerItem;

    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddIntToJson(jsonValue, COMMAND_CODE, 0)) {
        SLOGE("AddIntToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionServer->ProcControlCommandFromNext(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, COMMAND_CODE), true);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessColdStartFromNext001
 * @tc.desc: tset the member of ProcessColdStartFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcessColdStartFromNext001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddIntToJson(jsonValue, COMMAND_CODE, 1)) {
        SLOGE("AddIntToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionServer->ProcessColdStartFromNext(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, COMMAND_CODE), true);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessColdStartFromNext002
 * @tc.desc: tset the member of ProcessColdStartFromNext
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ProcessColdStartFromNext002, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_BUNDLE_NAME, "1")) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionServer->ProcessColdStartFromNext(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, MIGRATE_BUNDLE_NAME), true);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ConvertAudioDeviceDescriptorsToJson001
 * @tc.desc: tset the member of ConvertAudioDeviceDescriptorsToJson
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ConvertAudioDeviceDescriptorsToJson001, TestSize.Level0)
{
    AudioDeviceDescriptors ptrs;
    AudioDeviceDescriptorWithSptr ptr {new AudioDeviceDescriptor()};
    ptrs.push_back(ptr);
    EXPECT_EQ(ptrs.size() > 0, true);
    g_MigrateAVSessionServer->ConvertAudioDeviceDescriptorsToJson(ptrs);
}

/**
 * @tc.name: ConvertAudioDeviceDescriptorsToJson002
 * @tc.desc: tset the member of ConvertAudioDeviceDescriptorsToJson
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ConvertAudioDeviceDescriptorsToJson002, TestSize.Level0)
{
    AudioDeviceDescriptors ptrs;
    ptrs.push_back(nullptr);
    EXPECT_EQ(ptrs.size() > 0, true);
    g_MigrateAVSessionServer->ConvertAudioDeviceDescriptorsToJson(ptrs);
}

/**
 * @tc.name: VolumeControlCommand001
 * @tc.desc: tset the member of VolumeControlCommand
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, VolumeControlCommand001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddIntToJson(jsonValue, COMMAND_CODE, 1)) {
        SLOGE("AddIntToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionServer->ProcessColdStartFromNext(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, MIGRATE_BUNDLE_NAME), false);

    g_MigrateAVSessionServer->VolumeControlCommand(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, COMMAND_CODE), true);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: VolumeControlCommand002
 * @tc.desc: tset the member of VolumeControlCommand
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, VolumeControlCommand002, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddIntToJson(jsonValue, AUDIO_VOLUME, 1)) {
        SLOGE("AddIntToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionServer->VolumeControlCommand(jsonValue);
    EXPECT_EQ(cJSON_HasObjectItem(jsonValue, AUDIO_VOLUME), true);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ConvertAudioDeviceDescriptorToJson001
 * @tc.desc: tset the member of ConvertAudioDeviceDescriptorToJson
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ConvertAudioDeviceDescriptorToJson001, TestSize.Level0)
{
    SLOGE("ConvertAudioDeviceDescriptorToJson001 in");
    AudioDeviceDescriptorWithSptr ptr {new AudioDeviceDescriptor()};
    EXPECT_EQ(ptr != nullptr, true);
    cJSON* audioDevJson = g_MigrateAVSessionServer->ConvertAudioDeviceDescriptorToJson(ptr);
    EXPECT_EQ(audioDevJson != nullptr, true);
    SLOGE("ConvertAudioDeviceDescriptorToJson001 out");
}

/**
 * @tc.name: ConvertAudioDeviceDescriptorToJson002
 * @tc.desc: tset the member of ConvertAudioDeviceDescriptorToJson
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionServerForNextTest, ConvertAudioDeviceDescriptorToJson002, TestSize.Level0)
{
    SLOGE("ConvertAudioDeviceDescriptorToJson002 in");
    AudioDeviceDescriptorWithSptr ptr = nullptr;
    cJSON* audioDevJson = g_MigrateAVSessionServer->ConvertAudioDeviceDescriptorToJson(ptr);
    EXPECT_EQ(audioDevJson == nullptr, true);
    SLOGE("ConvertAudioDeviceDescriptorToJson002 out");
}
