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

#include "cJSON.h"
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
#include "softbus/softbus_session_utils.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

static const char* g_perms[] = {"ohos.permission.DISTRIBUTED_SOFTBUS_CENTER", "ohos.permission.DISTRIBUTED_DATASYNC",
    "ohos.permission.ACCESS_SERVICE_DM"};
static const int SIZE = 3;
static const int64_t TEST_DURATION = 40000;
static const double TEST_SPEED = 1.5;
static const int64_t TEST_BUFFERED_TIME = 60000;
static const int32_t TEST_LOOG_MODE = 2;
static std::shared_ptr<MigrateAVSessionServer> server_;
static AVSessionService *avservice_;

class MigrateAVSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void NativeTokenGet(const char *perms[], int size);
};

void MigrateAVSessionTest::SetUpTestCase()
{
    SLOGI("MigrateAVSessionTest SetUpTestCase");
    server_ = std::make_shared<MigrateAVSessionServer>();
    avservice_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
}

void MigrateAVSessionTest::TearDownTestCase()
{
    SLOGI("MigrateAVSessionTest TearDownTestCase");
    server_ = nullptr;
    avservice_ = nullptr;
}

void MigrateAVSessionTest::SetUp()
{
    SLOGI("MigrateAVSessionTest SetUp");
    NativeTokenGet(g_perms, SIZE);
}

void MigrateAVSessionTest::TearDown()
{
    SLOGI("MigrateAVSessionTest TearDown");
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
static HWTEST_F(MigrateAVSessionTest, GetCharacteristic001, TestSize.Level1)
{
    SLOGI("GetCharacteristic001 begin");
    int32_t ret = server_->GetCharacteristic();
    EXPECT_EQ(ret, MSG_HEAD_MODE);
    SLOGI("GetCharacteristic001 end");
}

/**
 * @tc.name: ResetSupportCrossMediaPlay001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionTest, ResetSupportCrossMediaPlay001, TestSize.Level1)
{
    SLOGI("ResetSupportCrossMediaPlay001 begin");
    server_->ResetSupportCrossMediaPlay("");
    EXPECT_EQ(server_->supportCrossMediaPlay_, false);
    SLOGI("ResetSupportCrossMediaPlay001 end");
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
    avservice_->SuperLauncher("", "SuperLauncher-Dual", "", "CONNECTING");
    avservice_->AddInnerSessionListener(server_.get());

    server_->Init(avservice_);
    migrateManager_->CreateLocalSessionStub("SuperLauncher-Dual", server_);
    EXPECT_EQ(migrateManager_->serverMap_.find("SuperLauncher-Dual") != migrateManager_->serverMap_.end(), true);

    char infoName[] = "Media_Session_RemoteCtrl";
    char infoNetworkId[] = "testInfoNetworkId";
    char infoPkgName[] = "testInfoPkgName";
    PeerSocketInfo info = {
        .name = infoName,
        .networkId = infoNetworkId,
        .pkgName = infoPkgName,
        .dataType = DATA_TYPE_BYTES,
    };
    migrateManager_->softBusDistributedDataMgr_->SessionOpened(sessionId, info);
    migrateManager_->softBusDistributedDataMgr_->OnSessionServerOpened();
    migrateManager_->softBusDistributedDataMgr_->MessageReceived(sessionId, "default");
    migrateManager_->softBusDistributedDataMgr_->OnMessageHandleReceived(sessionId, "default");
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

    server_->ResetSupportCrossMediaPlay("{\"mIsSupportSingleFrameMediaPlay\": true}");
    EXPECT_EQ(server_->supportCrossMediaPlay_, true);

    server_->SendSpecialKeepaliveData();
    server_->SendRemoteControllerList(deviceId);
    server_->SendRemoteHistorySessionList(deviceId);
    server_->ClearRemoteControllerList(deviceId);
    server_->ClearRemoteHistorySessionList(deviceId);

    char header[] = {MSG_HEAD_MODE, SYNC_COMMAND};
    const int commandList[] = {18, 30, 31, 36, 37, 38, 39, 41, 42, 43, 46, 48, 50};
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
static HWTEST_F(MigrateAVSessionTest, MigrateTest001, TestSize.Level1)
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
    avservice_->SuperLauncher("", "SuperLauncher-Dual", "", "IDLE");
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
    migrateManager_->ReleaseLocalSessionStub("SuperLauncher-Dual");
    EXPECT_EQ(migrateManager_->serverMap_.find("SuperLauncher-Dual") == migrateManager_->serverMap_.end(), true);
    SLOGI("MigrateTest001 end");
}

/**
* @tc.name: CreateController001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, CreateController001, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, ClearCacheBySessionId001, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, StopObserveControllerChanged001, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, GetControllerById001, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, GetControllerById002, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble001, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble002, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble003, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble004, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, ConvertStateFromSingleToDouble005, TestSize.Level1)
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
static HWTEST_F(MigrateAVSessionTest, ConvertMetadataToJson001, TestSize.Level1)
{
    SLOGI("ConvertMetadataToJson001 begin");
    AVMetaData metadata;
    metadata.SetTitle("song");
    metadata.SetArtist("sing");
    cJSON* ret = server_->ConvertMetadataToJson(metadata);
    EXPECT_EQ(SoftbusSessionUtils::GetStringFromJson(ret, METADATA_TITLE), "song");
    EXPECT_EQ(SoftbusSessionUtils::GetStringFromJson(ret, METADATA_ARTIST), "sing");
    cJSON_Delete(ret);
    SLOGI("ConvertMetadataToJson001 end");
}

/**
* @tc.name: ConvertMetadataInfoToStr001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ConvertMetadataInfoToStr001, TestSize.Level1)
{
    SLOGI("ConvertMetadataInfoToStr001 begin");
    const std::string playerId = "123";
    int32_t controlCommand = 9;
    AVMetaData metadata;
    metadata.SetDuration(-2);

    cJSON* result = SoftbusSessionUtils::GetNewCJSONObject();
    if (result == nullptr) {
        SLOGE("get result fail");
        FAIL();
    }
    if (!SoftbusSessionUtils::AddStringToJson(result, METADATA_TITLE, "")) {
        SLOGE("AddStringToJson with key:%{public}s fail", METADATA_TITLE);
        cJSON_Delete(result);
        result = nullptr;
    }
    if (!SoftbusSessionUtils::AddStringToJson(result, METADATA_ARTIST, "")) {
        SLOGE("AddStringToJson with key:%{public}s fail", METADATA_ARTIST);
        cJSON_Delete(result);
        result = nullptr;
    }
    if (!SoftbusSessionUtils::AddStringToJson(result, METADATA_IMAGE, "")) {
        SLOGE("AddStringToJson with key:%{public}s fail", METADATA_IMAGE);
        cJSON_Delete(result);
        result = nullptr;
    }
    if (!SoftbusSessionUtils::AddStringToJson(result, PLAYER_ID, playerId)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail", PLAYER_ID, playerId.c_str());
        cJSON_Delete(result);
        result = nullptr;
    }
    if (!SoftbusSessionUtils::AddIntToJson(result, MEDIA_INFO, controlCommand)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}d fail", MEDIA_INFO, controlCommand);
        cJSON_Delete(result);
        result = nullptr;
    }

    std::string msg = "d\002";
    SoftbusSessionUtils::TransferJsonToStr(result, msg);
    std::string ret = server_->ConvertMetadataInfoToStr(playerId, controlCommand, metadata);
    EXPECT_EQ(ret, msg);
    cJSON_Delete(result);
    SLOGI("ConvertMetadataInfoToStr001 end");
}

/**
* @tc.name: CreateLocalSessionStub001
* @tc.desc: test CreateLocalSessionStub
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, CreateLocalSessionStub001, TestSize.Level1)
{
    SLOGI("CreateLocalSessionStub001 begin");
    std::string scene = "test";
    std::shared_ptr<MigrateAVSessionManager> migrateManager_ = std::make_shared<MigrateAVSessionManager>();
    EXPECT_TRUE(migrateManager_ != nullptr);
    migrateManager_->CreateLocalSessionStub(scene, server_);
    SLOGI("CreateLocalSessionStub001 end");
}

/**
* @tc.name: CreateLocalSessionStub002
* @tc.desc: test CreateLocalSessionStub
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, CreateLocalSessionStub002, TestSize.Level1)
{
    SLOGI("CreateLocalSessionStub002 begin");
    std::string scene = "SuperLauncher-Dual";
    std::shared_ptr<MigrateAVSessionManager> migrateManager_ = std::make_shared<MigrateAVSessionManager>();
    EXPECT_TRUE(migrateManager_ != nullptr);
    migrateManager_->CreateLocalSessionStub(scene, server_);
    migrateManager_->CreateLocalSessionStub(scene, server_);
    SLOGI("CreateLocalSessionStub002 end");
}

/**
* @tc.name: ReleaseLocalSessionStub001
* @tc.desc: test ReleaseLocalSessionStub
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ReleaseLocalSessionStub001, TestSize.Level1)
{
    SLOGI("ReleaseLocalSessionStub001 begin");
    std::string scene = "test";
    std::shared_ptr<MigrateAVSessionManager> migrateManager_ = std::make_shared<MigrateAVSessionManager>();
    EXPECT_TRUE(migrateManager_ != nullptr);
    migrateManager_->ReleaseLocalSessionStub(scene);
    SLOGI("ReleaseLocalSessionStub001 end");
}

/**
* @tc.name: ReleaseLocalSessionStub002
* @tc.desc: test ReleaseLocalSessionStub
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ReleaseLocalSessionStub002, TestSize.Level1)
{
    SLOGI("ReleaseLocalSessionStub002 begin");
    std::string scene = "SuperLauncher-Dual";
    std::shared_ptr<MigrateAVSessionManager> migrateManager_ = std::make_shared<MigrateAVSessionManager>();
    EXPECT_TRUE(migrateManager_ != nullptr);
    migrateManager_->CreateLocalSessionStub(scene, server_);
    migrateManager_->ReleaseLocalSessionStub(scene);
    SLOGI("ReleaseLocalSessionStub002 end");
}

/**
* @tc.name: ReleaseLocalSessionStub003
* @tc.desc: test ReleaseLocalSessionStub
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ReleaseLocalSessionStub003, TestSize.Level1)
{
    SLOGI("ReleaseLocalSessionStub003 begin");
    std::string scene = "SuperLauncher-Dual";
    std::shared_ptr<MigrateAVSessionManager> migrateManager_ = std::make_shared<MigrateAVSessionManager>();
    EXPECT_TRUE(migrateManager_ != nullptr);
    migrateManager_->ReleaseLocalSessionStub(scene);
    SLOGI("ReleaseLocalSessionStub003 end");
}

/**
* @tc.name: IncSoftBusRef001
* @tc.desc: test IncSoftBusRef
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, IncSoftBusRef001, TestSize.Level1)
{
    SLOGI("IncSoftBusRef001 begin");
    std::shared_ptr<MigrateAVSessionManager> migrateManager_ = std::make_shared<MigrateAVSessionManager>();
    EXPECT_TRUE(migrateManager_ != nullptr);
    migrateManager_->refs_ = 1;
    migrateManager_->IncSoftBusRef();
    SLOGI("IncSoftBusRef001 end");
}

/**
* @tc.name: ClearCacheBySessionId002
* @tc.desc: test ClearCacheBySessionId
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ClearCacheBySessionId002, TestSize.Level1)
{
    SLOGI("ClearCacheBySessionId002 begin");
    std::string sessionId = "#####";
    EXPECT_TRUE(server_ != nullptr);
    server_->ClearCacheBySessionId(sessionId);
    SLOGI("ClearCacheBySessionId002 end");
}

/**
* @tc.name: ClearCacheBySessionId003
* @tc.desc: test ClearCacheBySessionId
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ClearCacheBySessionId003, TestSize.Level1)
{
    SLOGI("ClearCacheBySessionId003 begin");
    std::string sessionId = "12345";
    OHOS::sptr<AVControllerItem> item = nullptr;
    std::shared_ptr<AVControllerObserver> observer(nullptr);
    EXPECT_TRUE(server_ != nullptr);
    server_->playerIdToControllerMap_[sessionId] = item;
    server_->playerIdToControllerCallbackMap_[sessionId] = observer;
    server_->ClearCacheBySessionId(sessionId);
    SLOGI("ClearCacheBySessionId003 end");
}

/**
* @tc.name: ProcControlCommand001
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand001, TestSize.Level1)
{
    SLOGI("ProcControlCommand001 begin");
    std::string data = R"(##{"PlayerId":"1","MediaCommand":"1"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand001 end");
}

/**
* @tc.name: ProcControlCommand002
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand002, TestSize.Level1)
{
    SLOGI("ProcControlCommand002 begin");
    std::string data = R"(##{"PlayerId":"1","command":"1"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand002 end");
}

/**
* @tc.name: ProcControlCommand003
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand003, TestSize.Level1)
{
    SLOGI("ProcControlCommand003 begin");
    std::string data = R"(##{"MediaCommand":"1","command":"1"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand003 end");
}

/**
* @tc.name: ProcControlCommand004
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand004, TestSize.Level1)
{
    SLOGI("ProcControlCommand004 begin");
    std::string data = R"(##{"MediaCommand":"1"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand004 end");
}

/**
* @tc.name: ProcControlCommand005
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand005, TestSize.Level1)
{
    SLOGI("ProcControlCommand005 begin");
    std::string data = R"(##{"command":"1"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand005 end");
}

/**
* @tc.name: ProcControlCommand006
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand006, TestSize.Level1)
{
    SLOGI("ProcControlCommand006 begin");
    std::string data = R"(##{"PlayerId":"1"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand006 end");
}

/**
* @tc.name: ProcControlCommand007
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand007, TestSize.Level1)
{
    SLOGI("ProcControlCommand007 begin");
    std::string data = R"(##{"PlayerId":"","MediaCommand":1,"command":"1"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand007 end");
}

/**
* @tc.name: ProcControlCommand008
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand008, TestSize.Level1)
{
    SLOGI("ProcControlCommand008 begin");
    server_->CreateController("111");
    std::string data = R"(##{"PlayerId":"111","MediaCommand":30,"command":"1"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand008 end");
}

/**
* @tc.name: ProcControlCommand009
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand009, TestSize.Level1)
{
    SLOGI("ProcControlCommand009 begin");
    server_->CreateController("111");
    std::string data = R"(##{"PlayerId":"111","MediaCommand":31,"command":"1","extras":11})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand009 end");
}

/**
* @tc.name: ProcControlCommand007
* @tc.desc: test ProcControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, ProcControlCommand010, TestSize.Level1)
{
    SLOGI("ProcControlCommand007 begin");
    server_->CreateController("111");
    std::string data = R"(##{"PlayerId":"111","MediaCommand":50,"command":"1","extras":"124"})";
    EXPECT_TRUE(server_ != nullptr);
    server_->ProcControlCommand(data);
    SLOGI("ProcControlCommand007 end");
}

/**
* @tc.name: OnDeviceOffline001
* @tc.desc: OnDeviceOffline
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, OnDeviceOffline001, TestSize.Level1)
{
    SLOGI("OnDeviceOffline001 begin");
    const int64_t param = 1000;
    std::string deviceId = "test";
    const std::string sessionId = "";
    DeviceLogEventCode eventCode = DeviceLogEventCode::DEVICE_LOG_FULL;
    EXPECT_TRUE(server_ != nullptr);
    server_->OnDeviceLogEvent(eventCode, param);
    OHOS::sptr<AVControllerItem> controller = nullptr;
    server_->OnDeviceOffline(deviceId);
    int32_t ret = server_->GetControllerById(sessionId, controller);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("OnDeviceOffline001 end");
}

/**
* @tc.name: OnAudioSessionChecked001
* @tc.desc: OnAudioSessionChecked
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, OnAudioSessionChecked001, TestSize.Level1)
{
    SLOGI("OnAudioSessionChecked001 begin");
    int32_t uid = 1000;
    std::vector<OHOS::sptr<IRemoteObject>> sessionControllers;
    sessionControllers.push_back(nullptr);
    ASSERT_TRUE(server_ != nullptr);
    server_->OnRemoteDistributedSessionChange(sessionControllers);
    server_->OnAudioSessionChecked(uid);
    int32_t ret = server_->GetCharacteristic();
    EXPECT_EQ(ret, MSG_HEAD_MODE);
    SLOGI("OnAudioSessionChecked001 end");
}

/**
* @tc.name: GetControllerById003
* @tc.desc: GetControllerById
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionTest, GetControllerById003, TestSize.Level1)
{
    SLOGI("GetControllerById003 begin");
    const std::string sessionId = "";
    OutputDeviceInfo castOutputDeviceInfo;
    ASSERT_TRUE(server_ != nullptr);
    server_->OnDeviceAvailable(castOutputDeviceInfo);
    OHOS::sptr<AVControllerItem> controller = nullptr;
    int32_t ret = server_->GetControllerById(sessionId, controller);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetControllerById003 end");
}
