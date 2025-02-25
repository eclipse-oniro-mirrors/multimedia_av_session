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

using namespace testing::ext;
using namespace OHOS::AVSession;

static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};
static std::shared_ptr<MigrateAVSessionProxy> g_MigrateAVSessionProxy {nullptr};

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
    g_AVSessionService =  std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
    g_MigrateAVSessionProxy = std::make_shared<MigrateAVSessionProxy>(g_AVSessionService.get());
}

void MigrateAVSessionProxyTest::TearDownTestCase()
{
    SLOGI("MigrateAVSessionProxyTest TearDownTestCase");
    g_AVSessionService = nullptr;
    g_MigrateAVSessionProxy = nullptr;
}

void MigrateAVSessionProxyTest::SetUp()
{
    SLOGI("MigrateAVSessionProxyTest SetUp");
}

void MigrateAVSessionProxyTest::TearDown()
{
    SLOGI("MigrateAVSessionProxyTest TearDown");
}

void MigrateAVSessionProxyTest::NativeTokenGet(const char *perms[], int size)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = size,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = "migrate_softbus_test";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/**
 * @tc.name: MigrateAVSessionProxyControllerCallback001
 * @tc.desc: not find func
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, MigrateAVSessionProxyControllerCallback001, TestSize.Level1)
{
    MigrateAVSessionProxyControllerCallbackFunc func =
        g_MigrateAVSessionProxy->MigrateAVSessionProxyControllerCallback();
    std::string extraEvent = "";
    AAFwk::WantParams extras;
    int32_t ret = func(extraEvent, extras);
    EXPECT_EQ(ret, ERR_COMMAND_NOT_SUPPORT);
}

/**
 * @tc.name: MigrateAVSessionProxyControllerCallback002
 * @tc.desc: find the func
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, MigrateAVSessionProxyControllerCallback002, TestSize.Level1)
{
    auto maps = g_MigrateAVSessionProxy.AUDIO_EVENT_MAPS;
    MigrateAVSessionProxyControllerCallbackFunc func =
        g_MigrateAVSessionProxy->MigrateAVSessionProxyControllerCallback();
    for (auto it = maps.begin(); it != maps.end(); ++it) {
        std::string extraEvent = "";
        AAFwk::WantParams extras;
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
static HWTEST_F(MigrateAVSessionProxyTest, ProcessSessionInfo001, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue["test"] = "test";
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessSessionInfo(jsonValue);
}

/**
 * @tc.name: ProcessSessionInfo002
 * @tc.desc: test the member of ProcessSessionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessSessionInfo002, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue[MIGRATE_SESSION_ID] = "";
    jsonValue[MIGRATE_BUNDLE_NAME] = "";
    jsonValue[MIGRATE_ABILITY_NAME] = "";
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessSessionInfo(jsonValue);
}

/**
 * @tc.name: ProcessSessionInfo003
 * @tc.desc: test the member of ProcessSessionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessSessionInfo003, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue[MIGRATE_SESSION_ID] = DEFAULT_STRING;
    jsonValue[MIGRATE_BUNDLE_NAME] = DEFAULT_STRING;
    jsonValue[MIGRATE_ABILITY_NAME] = DEFAULT_STRING;
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessSessionInfo(jsonValue);
}

/**
 * @tc.name: ProcessSessionInfo004
 * @tc.desc: test the member of ProcessSessionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessSessionInfo004, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue[MIGRATE_SESSION_ID] = EMPTY_SESSION;
    jsonValue[MIGRATE_BUNDLE_NAME] = EMPTY_SESSION;
    jsonValue[MIGRATE_ABILITY_NAME] = EMPTY_SESSION;
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessSessionInfo(jsonValue);
}

/**
 * @tc.name: ProcessMetaData001
 * @tc.desc: test the member of ProcessMetaData
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMetaData001, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue[METADATA_TITLE] = METADATA_TITLE;
    jsonValue[METADATA_ARTIST] = METADATA_ARTIST;
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessMetaData(jsonValue);
}

/**
 * @tc.name: ProcessMetaData002
 * @tc.desc: test the member of ProcessMetaData
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMetaData002, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue["test"] = "test";
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessMetaData(jsonValue);
}

/**
 * @tc.name: ProcessPlaybackState001
 * @tc.desc: test the member of ProcessPlaybackState
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessPlaybackState001, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue[PLAYBACK_STATE] = PLAYBACK_STATE;
    jsonValue[FAVOR_STATE] = FAVOR_STATE;
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessPlaybackState(jsonValue);
}

/**
 * @tc.name: ProcessPlaybackState002
 * @tc.desc: test the member of ProcessPlaybackState
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessPlaybackState002, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue["test"] = "test";
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessPlaybackState(jsonValue);
}

/**
 * @tc.name: ProcessValidCommands001
 * @tc.desc: test the member of ProcessValidCommands
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessValidCommands001, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue[VALID_COMMANDS] = VALID_COMMANDS;
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessValidCommands(jsonValue);
}

/**
 * @tc.name: ProcessValidCommands002
 * @tc.desc: test the member of ProcessValidCommands
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessValidCommands002, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue["test"] = "test";
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessValidCommands(jsonValue);
}

/**
 * @tc.name: ProcessVolumeControlCommand001
 * @tc.desc: test the member of ProcessVolumeControlCommand
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessVolumeControlCommand001, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue[AUDIO_VOLUME] = AUDIO_VOLUME;
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessVolumeControlCommand(jsonValue);
}

/**
 * @tc.name: ProcessVolumeControlCommand002
 * @tc.desc: test the member of ProcessVolumeControlCommand
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessVolumeControlCommand002, TestSize.Level1)
{
    Json::Value jsonValue;
    jsonValue["test"] = "test";
    g_MigrateAVSessionProxy->PrepareSessionFromRemote();
    EXPECT_EQ(g_MigrateAVSessionProxy->remoteSession_ != nullptr, true);
    g_MigrateAVSessionProxy->ProcessVolumeControlCommand(jsonValue);
}

/**
 * @tc.name: ProcessBundleImg001
 * @tc.desc: test the member of ProcessBundleImg
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyTest, ProcessBundleImg001, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionProxyTest, ProcessBundleImg002, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionProxyTest, ProcessBundleImg003, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMediaImage001, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMediaImage002, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionProxyTest, ProcessMediaImage003, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionProxyTest, OnConnectServer001, TestSize.Level1)
{
    g_MigrateAVSessionProxy->OnConnectServer();
    EXPECT_EQ(g_MigrateAVSessionProxy->servicePtr_ != nullptr, true);
}