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
#define private public
#define protected public
#include "avsession_service.h"
#include "migrate_avsession_manager.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::AVSession;

static const char* g_perms[] = {"ohos.permission.DISTRIBUTED_SOFTBUS_CENTER", "ohos.permission.DISTRIBUTED_DATASYNC",
    "ohos.permission.ACCESS_SERVICE_DM"};
static const int SIZE = 3;
static const int64_t TEST_DURATION = 40000;
static const double TEST_SPEED = 1.5;
static const int64_t TEST_BUFFERED_TIME = 60000;
static const int32_t TEST_LOOG_MODE = 2;
class MigrateAVSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void NativeTokenGet(const char *perms[], int size);

    std::shared_ptr<MigrateAVSessionServer> server_ = nullptr;
    AVSessionService *avservice_ = nullptr;
};

void MigrateAVSessionTest::SetUpTestCase() {}

void MigrateAVSessionTest::TearDownTestCase() {}

void MigrateAVSessionTest::SetUp()
{
    server_ = std::make_shared<MigrateAVSessionServer>();
    avservice_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    NativeTokenGet(g_perms, SIZE);
}

void MigrateAVSessionTest::TearDown()
{
    server_ = nullptr;
    avservice_ = nullptr;
    NativeTokenGet(nullptr, 0);
}

void MigrateAVSessionTest::NativeTokenGet(const char *perms[], int size)
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
* @tc.name: GetCharacteristic001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, GetCharacteristic001, TestSize.Level1)
{
    SLOGI("GetCharacteristic001 begin");
    int32_t ret = server_->GetCharacteristic();
    EXPECT_EQ(ret, MSG_HEAD_MODE);
    SLOGI("GetCharacteristic001 end");
}

void SetMetaDataAndPlaybackState(OHOS::sptr<AVSessionItem> avsession_)
{
    SLOGI("MigrateTest001 SetMetaDataAndPlaybackState");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(TEST_DURATION);
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");
    avsession_->SetAVMetaData(metaData);

    AVPlaybackState playbackState;
    playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    playbackState.SetSpeed(TEST_SPEED);
    playbackState.SetPosition({ 80000, 0 });
    playbackState.SetBufferedTime(TEST_BUFFERED_TIME);
    playbackState.SetLoopMode(TEST_LOOG_MODE);
    playbackState.SetFavorite(true);
    avsession_->SetAVPlaybackState(playbackState);
}

void TestMigrateConnect(AVSessionService *avservice_, std::shared_ptr<MigrateAVSessionServer> server_,
    std::shared_ptr<MigrateAVSessionManager> migrateManager_, int32_t sessionId, std::string deviceId)
{
    SLOGI("MigrateTest001 TestMigrateConnect");
    avservice_->SuperLauncher("", "SuperLauncher", "", "CONNECTING");
    avservice_->AddInnerSessionListener(server_.get());

    server_->Init(avservice_);
    migrateManager_->CreateLocalSessionStub("SuperLauncher", server_);
    EXPECT_EQ(migrateManager_->serverMap_.find("SuperLauncher") != migrateManager_->serverMap_.end(), true);

    migrateManager_->softBusDistributedDataMgr_->SessionOpened(sessionId);
    migrateManager_->softBusDistributedDataMgr_->OnSessionServerOpened(sessionId);
    migrateManager_->softBusDistributedDataMgr_->MessageReceived(sessionId, "");
    migrateManager_->softBusDistributedDataMgr_->OnMessageHandleReceived(sessionId, "");
    server_->ConnectProxy(sessionId);
    server_->OnConnectSession(sessionId);
    server_->OnConnectProxy(deviceId);
    EXPECT_EQ(server_->isSoftbusConnecting_, true);
}

void TestMigrateSendByte(OHOS::sptr<AVSessionItem> avsession_, std::shared_ptr<MigrateAVSessionServer> server_,
    std::string deviceId)
{
    SLOGI("MigrateTest001 TestMigrateSendByte");
    AVSessionDescriptor descriptor = avsession_->GetDescriptor();
    server_->OnSessionCreate(descriptor);
    server_->OnTopSessionChange(descriptor);

    server_->ObserveControllerChanged(deviceId);
    server_->CreateController(descriptor.sessionId_);
    EXPECT_EQ(server_->playerIdToControllerCallbackMap_.find(descriptor.sessionId_) !=
        server_->playerIdToControllerCallbackMap_.end(), true);
    
    OHOS::sptr<AVControllerItem> controller = nullptr;
    int32_t ret = server_->GetControllerById(descriptor.sessionId_, controller);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    server_->SendSpecialKeepaliveData();
    server_->SendRemoteControllerList(deviceId);

    char header[] = {MSG_HEAD_MODE, SYNC_COMMAND};
    int commandList[] = {18, 30, 31, 36, 37, 38, 39, 41, 42, 43, 46, 48, 50};
    for (int command : commandList) {
        std::string data = std::string(header) + "{\"PlayerId\"" + descriptor.sessionId_ +
            "\",\"MediaCommand\":" + std::to_string(command) + ",\"command\":\"\"}";
        server_->OnBytesReceived(deviceId, data);
    }

    server_->OnMetaDataChange(descriptor.sessionId_, avsession_->GetMetaData());
    server_->OnPlaybackStateChanged(descriptor.sessionId_, avsession_->GetPlaybackState());
}

/**
* @tc.name: MigrateTest001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, MigrateTest001, TestSize.Level1)
{
    SLOGI("MigrateTest001 begin");
    std::shared_ptr<MigrateAVSessionManager> migrateManager_ = std::make_shared<MigrateAVSessionManager>();
    int32_t sessionId = 1;
    std::string deviceId = "538CF5694D736D03B42DAF483D5A8C8E432ADECFAD5A75270F70856028219C64";
    TestMigrateConnect(avservice_, server_, migrateManager_, sessionId, deviceId);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr<AVSessionItem> avsession_ =
        avservice_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    SetMetaDataAndPlaybackState(avsession_);
    AVSessionDescriptor descriptor = avsession_->GetDescriptor();
    TestMigrateSendByte(avsession_, server_, deviceId);

    // disconnect release
    avservice_->SuperLauncher("", "SuperLauncher", "", "IDLE");
    avservice_->RemoveInnerSessionListener(server_.get());
    server_->OnSessionRelease(descriptor);
    server_->ClearCacheBySessionId(descriptor.sessionId_);
    EXPECT_EQ(server_->playerIdToControllerCallbackMap_.find(descriptor.sessionId_) ==
        server_->playerIdToControllerCallbackMap_.end(), true);
    avsession_->Destroy();
    server_->DisconnectAllProxy();
    server_->DisconnectProxy(sessionId);
    server_->OnDisConnectSession(sessionId);
    server_->OnDisconnectProxy(deviceId);
    EXPECT_EQ(server_->isSoftbusConnecting_, false);
    migrateManager_->ReleaseLocalSessionStub("SuperLauncher");
    EXPECT_EQ(migrateManager_->serverMap_.find("SuperLauncher") == migrateManager_->serverMap_.end(), true);
    SLOGI("MigrateTest001 end");
}

/**
* @tc.name: CreateController001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, CreateController001, TestSize.Level1)
{
    SLOGI("CreateController001 begin");
    const std::string sessionId = "1111";
    server_->Init(avservice_);
    server_->CreateController(sessionId);
    EXPECT_EQ(server_->playerIdToControllerCallbackMap_.find(sessionId) ==
        server_->playerIdToControllerCallbackMap_.end(), true);
    SLOGI("CreateController001 end");
}

/**
* @tc.name: ClearCacheBySessionId001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, ClearCacheBySessionId001, TestSize.Level1)
{
    SLOGI("ClearCacheBySessionId001 begin");
    const std::string sessionId = "1111";
    server_->ClearCacheBySessionId(sessionId);
    EXPECT_EQ(server_->playerIdToControllerMap_.find(sessionId) == server_->playerIdToControllerMap_.end(), true);
    EXPECT_EQ(server_->playerIdToControllerCallbackMap_.find(sessionId) ==
        server_->playerIdToControllerCallbackMap_.end(), true);
    SLOGI("ClearCacheBySessionId001 end");
}

/**
* @tc.name: StopObserveControllerChanged001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, StopObserveControllerChanged001, TestSize.Level1)
{
    SLOGI("StopObserveControllerChanged001 begin");
    const std::string deviceId = "1111";
    server_->StopObserveControllerChanged(deviceId);
    EXPECT_EQ(server_->playerIdToControllerMap_.size() == 0, true);
    EXPECT_EQ(server_->sortControllerList_.size() == 0, true);
    EXPECT_EQ(server_->playerIdToControllerCallbackMap_.size() == 0, true);
    SLOGI("StopObserveControllerChanged001 end");
}

/**
* @tc.name: GetControllerById001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, GetControllerById001, TestSize.Level1)
{
    SLOGI("GetControllerById001 begin");
    const std::string sessionId = "123";
    OHOS::sptr<AVControllerItem> controller = nullptr;
    int32_t ret = server_->GetControllerById(sessionId, controller);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetControllerById001 end");
}

/**
* @tc.name: GetControllerById002
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, GetControllerById002, TestSize.Level1)
{
    SLOGI("GetControllerById002 begin");
    const std::string sessionId = "123";
    OHOS::sptr<AVControllerItem> controller = nullptr;
    server_->playerIdToControllerMap_[sessionId] = controller;
    int32_t ret = server_->GetControllerById(sessionId, controller);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetControllerById002 end");
}

/**
* @tc.name: ConvertStateFromSingleToDouble001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble001, TestSize.Level1)
{
    SLOGI("ConvertStateFromSingleToDouble001 begin");
    int32_t state = AVPlaybackState::PLAYBACK_STATE_PLAY;
    int32_t ret = server_->ConvertStateFromSingleToDouble(state);
    EXPECT_EQ(ret, MEDIA_SESSION_PLAYBACK_STATE_PLAY);
    SLOGI("ConvertStateFromSingleToDouble001 end");
}

/**
* @tc.name: ConvertStateFromSingleToDouble002
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble002, TestSize.Level1)
{
    SLOGI("ConvertStateFromSingleToDouble002 begin");
    int32_t state = AVPlaybackState::PLAYBACK_STATE_PAUSE;
    int32_t ret = server_->ConvertStateFromSingleToDouble(state);
    EXPECT_EQ(ret, MEDIA_SESSION_PLAYBACK_STATE_PAUSE);
    SLOGI("ConvertStateFromSingleToDouble002 end");
}

/**
* @tc.name: ConvertStateFromSingleToDouble003
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble003, TestSize.Level1)
{
    SLOGI("ConvertStateFromSingleToDouble003 begin");
    int32_t state = AVPlaybackState::PLAYBACK_STATE_STOP;
    int32_t ret = server_->ConvertStateFromSingleToDouble(state);
    EXPECT_EQ(ret, MEDIA_SESSION_PLAYBACK_STATE_STOP);
    SLOGI("ConvertStateFromSingleToDouble003 end");
}

/**
* @tc.name: ConvertStateFromSingleToDouble004
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble004, TestSize.Level1)
{
    SLOGI("ConvertStateFromSingleToDouble004 begin");
    int32_t state = AVPlaybackState::PLAYBACK_STATE_ERROR;
    int32_t ret = server_->ConvertStateFromSingleToDouble(state);
    EXPECT_EQ(ret, MEDIA_SESSION_PLAYBACK_STATE_ERROR);
    SLOGI("ConvertStateFromSingleToDouble004 end");
}

/**
* @tc.name: ConvertStateFromSingleToDouble005
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble005, TestSize.Level1)
{
    SLOGI("ConvertStateFromSingleToDouble005 begin");
    int32_t state = 13;
    int32_t ret = server_->ConvertStateFromSingleToDouble(state);
    EXPECT_EQ(ret, state);
    SLOGI("ConvertStateFromSingleToDouble005 end");
}

/**
* @tc.name: ConvertMetadataToJson001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, ConvertMetadataToJson001, TestSize.Level1)
{
    SLOGI("ConvertMetadataToJson001 begin");
    AVMetaData metadata;
    metadata.SetTitle("song");
    metadata.SetArtist("sing");
    Json::Value ret = server_->ConvertMetadataToJson(metadata);
    EXPECT_EQ(ret[METADATA_TITLE], "song");
    EXPECT_EQ(ret[METADATA_ARTIST], "sing");
    SLOGI("ConvertMetadataToJson001 end");
}

/**
* @tc.name: ConvertMetadataInfoToStr001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MigrateAVSessionTest, ConvertMetadataInfoToStr001, TestSize.Level1)
{
    SLOGI("ConvertMetadataInfoToStr001 begin");
    const std::string playerId = "123";
    int32_t controlCommand = 9;
    AVMetaData metadata;
    metadata.SetDuration(-2);
    Json::Value result;
    result[PLAYER_ID] = playerId;
    result[MEDIA_INFO] = controlCommand;
    result[METADATA_ART] = "";
    result[METADATA_ARTIST] = "";
    result[METADATA_TITLE] = "";
    Json::FastWriter writer;
    std::string msg = "d\002" + writer.write(result);
    std::string ret = server_->ConvertMetadataInfoToStr(playerId, controlCommand, metadata);
    EXPECT_EQ(ret, msg);
    SLOGI("ConvertMetadataInfoToStr001 end");
}