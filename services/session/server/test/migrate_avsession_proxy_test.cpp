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
#include "avsession_service.h"
#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_log.h"
#include "migrate_avsession_constant.h"
#include "migrate_avsession_manager.h"
#include "migrate_avsession_proxy.h"
#include "system_ability_definition.h"
#include "softbus/softbus_session_utils.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

static AVSessionService* g_AVSessionService {nullptr};
static std::shared_ptr<MigrateAVSessionProxy> g_MigrateAVSessionProxy {nullptr};
static std::shared_ptr<AVSessionObserver> g_AVSessionObserver {nullptr};

class MigrateAVSessionProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MigrateAVSessionProxyTest::SetUpTestCase()
{
    SLOGI("MigrateAVSessionProxyTest SetUpTestCase");
    g_AVSessionService =  new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    g_MigrateAVSessionProxy = std::make_shared<MigrateAVSessionProxy>(g_AVSessionService);
    g_AVSessionObserver = std::make_shared<AVSessionObserver>();
}

void MigrateAVSessionProxyTest::TearDownTestCase()
{
    SLOGI("MigrateAVSessionProxyTest TearDownTestCase");
    g_MigrateAVSessionProxy = nullptr;
    g_AVSessionService = nullptr;
    g_AVSessionObserver = nullptr;
}

void MigrateAVSessionProxyTest::SetUp()
{
    SLOGI("MigrateAVSessionProxyTest SetUp");
}

void MigrateAVSessionProxyTest::TearDown()
{
    SLOGI("MigrateAVSessionProxyTest TearDown");
}

/**
 * @tc.name: MigrateAVSessionProxyControllerCallback001
 * @tc.desc: not find func
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, MigrateAVSessionProxyControllerCallback001, TestSize.Level0)
{
    MigrateAVSessionProxyControllerCallbackFunc func =
        g_MigrateAVSessionProxy->MigrateAVSessionProxyControllerCallback();
    std::string extraEvent = "";
    OHOS::AAFwk::WantParams extras;
    int32_t ret = func(extraEvent, extras);
    EXPECT_EQ(ret, ERR_COMMAND_NOT_SUPPORT);
}

/**
 * @tc.name: MigrateAVSessionProxyControllerCallback002
 * @tc.desc: find the func
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, MigrateAVSessionProxyControllerCallback002, TestSize.Level0)
{
    auto maps = g_MigrateAVSessionProxy->AUDIO_EVENT_MAPS;
    MigrateAVSessionProxyControllerCallbackFunc func =
        g_MigrateAVSessionProxy->MigrateAVSessionProxyControllerCallback();
    for (auto it = maps.begin(); it != maps.end(); ++it) {
        std::string extraEvent = it->first;
        OHOS::AAFwk::WantParams extras;
        int32_t ret = func(extraEvent, extras);
        EXPECT_EQ(ret, AVSESSION_SUCCESS);
    }
}

/**
 * @tc.name: ProcessSessionInfo001
 * @tc.desc: test the member of ProcessSessionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessSessionInfo001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, "test", "test")) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessSessionInfo(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessSessionInfo002
 * @tc.desc: test the member of ProcessSessionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessSessionInfo002, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_SESSION_ID, "") ||
        !SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_BUNDLE_NAME, "") ||
        !SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_ABILITY_NAME, "")) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessSessionInfo(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessSessionInfo003
 * @tc.desc: test the member of ProcessSessionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessSessionInfo003, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_SESSION_ID, DEFAULT_STRING) ||
        !SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_BUNDLE_NAME, DEFAULT_STRING) ||
        !SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_ABILITY_NAME, DEFAULT_STRING)) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessSessionInfo(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessSessionInfo004
 * @tc.desc: test the member of ProcessSessionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessSessionInfo004, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_SESSION_ID, EMPTY_SESSION) ||
        !SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_BUNDLE_NAME, EMPTY_SESSION) ||
        !SoftbusSessionUtils::AddStringToJson(jsonValue, MIGRATE_ABILITY_NAME, EMPTY_SESSION)) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessSessionInfo(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessMetaData001
 * @tc.desc: test the member of ProcessMetaData
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMetaData001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, METADATA_TITLE) ||
        !SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ARTIST, METADATA_ARTIST)) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessMetaData(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessMetaData002
 * @tc.desc: test the member of ProcessMetaData
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMetaData002, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, "test", "test")) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessMetaData(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessPlaybackState001
 * @tc.desc: test the member of ProcessPlaybackState
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessPlaybackState001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, PLAYBACK_STATE) ||
        !SoftbusSessionUtils::AddStringToJson(jsonValue, FAVOR_STATE, FAVOR_STATE)) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessPlaybackState(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessPlaybackState002
 * @tc.desc: test the member of ProcessPlaybackState
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessPlaybackState002, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, "test", "test")) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessPlaybackState(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessValidCommands001
 * @tc.desc: test the member of ProcessValidCommands
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessValidCommands001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, VALID_COMMANDS, VALID_COMMANDS)) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessValidCommands(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessValidCommands002
 * @tc.desc: test the member of ProcessValidCommands
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessValidCommands002, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, "test", "test")) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessValidCommands(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessVolumeControlCommand001
 * @tc.desc: test the member of ProcessVolumeControlCommand
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessVolumeControlCommand001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, AUDIO_VOLUME, AUDIO_VOLUME)) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessVolumeControlCommand(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessVolumeControlCommand002
 * @tc.desc: test the member of ProcessVolumeControlCommand
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessVolumeControlCommand002, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    EXPECT_NE(jsonValue, nullptr);
    if (jsonValue == nullptr) {
        SLOGE("create jsonvalue nullptr");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(jsonValue, "test", "test")) {
        SLOGE("AddStringToJson fail");
        cJSON_Delete(jsonValue);
        jsonValue = nullptr;
        FAIL();
    }

    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessVolumeControlCommand(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessAvailableDevices001
 * @tc.desc: test the member of ProcessAvailableDevices
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessAvailableDevices001, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->preSetController_ != nullptr, true);

    auto devices = AudioAdapter::GetInstance().GetAvailableDevices();
    cJSON* jsonValue = MigrateAVSessionServer::ConvertAudioDeviceDescriptorsToJson(devices);
    g_MigrateAVSessionProxy->ProcessAvailableDevices(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessPreferredOutputDevice001
 * @tc.desc: test the member of ProcessPreferredOutputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessPreferredOutputDevice001, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->preSetController_ != nullptr, true);

    auto devices = AudioAdapter::GetInstance().GetPreferredOutputDeviceForRendererInfo();
    cJSON* jsonValue = MigrateAVSessionServer::ConvertAudioDeviceDescriptorsToJson(devices);
    g_MigrateAVSessionProxy->ProcessPreferredOutputDevice(jsonValue);
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessBundleImg001
 * @tc.desc: test the member of ProcessBundleImg
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessBundleImg001, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    std::string bundleIconStr = "";
    g_MigrateAVSessionProxy->ProcessBundleImg(bundleIconStr);
}

/**
 * @tc.name: ProcessBundleImg002
 * @tc.desc: test the member of ProcessBundleImg
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessBundleImg002, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    std::string bundleIconStr = "test";
    g_MigrateAVSessionProxy->ProcessBundleImg(bundleIconStr);
}

/**
 * @tc.name: ProcessBundleImg003
 * @tc.desc: test the member of ProcessBundleImg
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessBundleImg003, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    AVMetaData metaData;
    g_MigrateAVSessionProxy->remoteSession_->SetAVMetaData(metaData);
    std::string bundleIconStr = "test";
    g_MigrateAVSessionProxy->ProcessBundleImg(bundleIconStr);
}

/**
 * @tc.name: ProcessMediaImage001
 * @tc.desc: test the member of ProcessMediaImage
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMediaImage001, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    std::string bundleIconStr = "";
    g_MigrateAVSessionProxy->ProcessMediaImage(bundleIconStr);
}

/**
 * @tc.name: ProcessMediaImage002
 * @tc.desc: test the member of ProcessMediaImage
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMediaImage002, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    std::string bundleIconStr = "test";
    g_MigrateAVSessionProxy->ProcessMediaImage(bundleIconStr);
}

/**
 * @tc.name: ProcessMediaImage003
 * @tc.desc: test the member of ProcessMediaImage
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMediaImage003, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    AVMetaData metaData;
    g_MigrateAVSessionProxy->remoteSession_->SetAVMetaData(metaData);
    std::string bundleIconStr = "test";
    g_MigrateAVSessionProxy->ProcessMediaImage(bundleIconStr);
}

/**
 * @tc.name: OnConnectServer001
 * @tc.desc: test the member of OnConnectServer
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, OnConnectServer001, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_TRUE(g_MigrateAVSessionProxy->remoteSession_ != nullptr);
    std::string deviceId = "123";
    g_MigrateAVSessionProxy->OnConnectServer(deviceId);
}

/**
 * @tc.name: OnDisconnectServer001
 * @tc.desc: test the member of OnDisconnectServer
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, OnDisconnectServer001, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_TRUE(g_MigrateAVSessionProxy->remoteSession_ != nullptr);
    std::string deviceId = "123";
    g_MigrateAVSessionProxy->OnDisconnectServer(deviceId);
}

/**
 * @tc.name: OnBytesReceived001
 * @tc.desc: test the member of OnBytesReceived
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, OnBytesReceived001, TestSize.Level0)
{
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_TRUE(g_MigrateAVSessionProxy->remoteSession_ != nullptr);
    std::string deviceId = "123";
    std::string msg = "test";
    g_MigrateAVSessionProxy->OnBytesReceived(deviceId, msg);
}

/**
 * @tc.name: PrepareSessionFromRemote_WhenTargetLoopModeSet_Success
 * @tc.desc: test the member of PrepareSessionFromRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, PrepareSessionFromRemote_WhenTargetLoopModeSet_Success, TestSize.Level0)
{
    int32_t targetLoopMode = 0;
    std::string bundleIconStr = "";
    g_AVSessionObserver->OnSetTargetLoopMode(targetLoopMode);
    ASSERT_TRUE(g_MigrateAVSessionProxy != nullptr);
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_NE(g_MigrateAVSessionProxy->remoteSession_, nullptr);
}

/**
 * @tc.name: PrepareSessionFromRemote_WhenValidBundleIcon_ExpectSuccess
 * @tc.desc: test the member of PrepareSessionFromRemote
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, PrepareSessionFromRemote_WhenValidBundleIcon_Success, TestSize.Level1)
{
    std::string assetId = "test";
    std::string bundleIconStr = "123";
    g_AVSessionObserver->OnPlayWithAssetId(assetId);
    ASSERT_TRUE(g_MigrateAVSessionProxy != nullptr);
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_NE(g_MigrateAVSessionProxy->preSetController_, nullptr);
    g_MigrateAVSessionProxy->ProcessMediaImage(bundleIconStr);
}
