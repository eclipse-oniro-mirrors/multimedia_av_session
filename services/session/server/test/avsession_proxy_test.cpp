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

#include <gtest/gtest.h>
#include "avsession_log.h"
#include "avsession_errors.h"
#include "iservice_registry.h"
#include "avmedia_description.h"
#include "av_file_descriptor.h"
#include "system_ability_definition.h"
#include "avsession_callback_proxy.h"
#include "avsession_controller_proxy.h"
#include "avsession_proxy.h"
#include "avsession_service.h"

using namespace OHOS;
using namespace OHOS::AVSession;

class AVSessionProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionProxyTest::SetUpTestCase()
{
}

void AVSessionProxyTest::TearDownTestCase()
{
}

void AVSessionProxyTest::SetUp()
{
}

void AVSessionProxyTest::TearDown()
{
}

static const int32_t DURATION_TIME = 40000;
static OHOS::AVSession::AVMetaData GetAVMetaData()
{
    OHOS::AVSession::AVMetaData g_metaData;
    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(DURATION_TIME);
    g_metaData.SetMediaImageUri("xxxxx");
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("xxxxx");
    return g_metaData;
}


class AVSessionCallbackImpl : public AVSessionCallback {
public:
    void OnPlay() override {};
    void OnPause() override {};
    void OnStop() override {};
    void OnPlayNext() override {};
    void OnPlayPrevious() override {};
    void OnFastForward(int64_t time) override {};
    void OnRewind(int64_t time) override {};
    void OnSeek(int64_t time) override {};
    void OnSetSpeed(double speed) override {};
    void OnSetLoopMode(int32_t loopMode) override {};
    void OnToggleFavorite(const std::string& mediald) override {};
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override {};
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override {};
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override {};
    void OnSkipToQueueItem(int32_t itemId) override {};
    void OnAVCallAnswer() override {};
    void OnAVCallHangUp() override {};
    void OnAVCallToggleCallMute() override {};
    void OnPlayFromAssetId(int64_t assetId) override {};
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override {};

    ~AVSessionCallbackImpl() override {};
};


/**
 * @tc.name: GetSessionId001
 * @tc.desc: Test GetSessionId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetSessionId001, testing::ext::TestSize.Level1)
{
    SLOGI("GetSessionId001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = aVSessionProxy->GetSessionId();
    EXPECT_NE(sessionId, "");

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("GetSessionId001, end");
}

/**
 * @tc.name: GetSessionType001
 * @tc.desc: Test GetSessionType
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetSessionType001, testing::ext::TestSize.Level1)
{
    SLOGI("GetSessionType001, start");
	
    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    std::string typeStr = aVSessionProxy->GetSessionType();
    EXPECT_NE(typeStr, "");

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("GetSessionType001, end");
}

/**
 * @tc.name: SetAVCallMetaData001
 * @tc.desc: Test SetAVCallMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVCallMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallMetaData001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
	
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    AVCallMetaData avCallMetaData;
    ret = aVSessionProxy->SetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetAVCallMetaData001, end");
}

/**
 * @tc.name: SetAVCallMetaData002
 * @tc.desc: Test SetAVCallMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVCallMetaData002, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallMetaData002, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
	

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    AVCallMetaData avCallMetaData;
    avCallMetaData.SetName("name");
    avCallMetaData.SetPhoneNumber("number");
    ret = aVSessionProxy->SetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetAVCallMetaData002, end");
}

/**
 * @tc.name: SetAVCallState001
 * @tc.desc: Test SetAVCallState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVCallState001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallState001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    AVCallState avCallState;
    avCallState.SetAVCallState(AVCallState::AVCALL_STATE_IDLE);
    ret = aVSessionProxy->SetAVCallState(avCallState);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
	
    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetAVCallState001, end");
}

/**
 * @tc.name: SetAVCallState002
 * @tc.desc: Test SetAVCallState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVCallState002, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallState002, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    AVCallState avCallState;
    avCallState.SetAVCallState(-1);
    ret = aVSessionProxy->SetAVCallState(avCallState);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetAVCallState002, end");
}

/**
 * @tc.name: SetAVMetaData001
 * @tc.desc: Test SetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVMetaData001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    AVMetaData meta;
    std::string assetId = "assetId";
    meta.SetAssetId(assetId);
    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 2, 3, 4, 5, 6, 7, 8};
    mediaImage->SetInnerImgBuffer(imgBuffer);
    meta.SetMediaImage(mediaImage);
    ret = aVSessionProxy->SetAVMetaData(meta);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetAVMetaData001, end");
}

/**
 * @tc.name: GetAVMetaData001
 * @tc.desc: Test GetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVMetaData001, start");
    GetAVMetaData();
    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    AVMetaData meta;
    ret = aVSessionProxy->GetAVMetaData(meta);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("GetAVMetaData001, end");
}

/**
 * @tc.name: GetAVPlaybackState001
 * @tc.desc: Test GetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVPlaybackState001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVPlaybackState001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
	
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    AVPlaybackState state;
    ret = aVSessionProxy->GetAVPlaybackState(state);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("GetAVPlaybackState001, end");
}

/**
 * @tc.name: SetAVPlaybackState001
 * @tc.desc: Test SetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVPlaybackState001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVPlaybackState001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    AVPlaybackState avPlaybackState;
    AVPlaybackState::Position position;
    position.elapsedTime_ = 1;
    position.updateTime_ = 1;
    avPlaybackState.SetState(1);
    avPlaybackState.SetSpeed(1);
    avPlaybackState.SetPosition(position);
    avPlaybackState.SetBufferedTime(1);
    avPlaybackState.SetLoopMode(1);
    avPlaybackState.SetFavorite(1);
    avPlaybackState.SetActiveItemId(1);
    avPlaybackState.SetVolume(1);
    avPlaybackState.SetMaxVolume(1);
    avPlaybackState.SetMuted(1);
    avPlaybackState.SetDuration(1);
    avPlaybackState.SetVideoWidth(1);
    avPlaybackState.SetVideoHeight(1);
    ret = aVSessionProxy->SetAVPlaybackState(avPlaybackState);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetAVPlaybackState001, end");
}

/**
 * @tc.name: GetAVQueueItems001
 * @tc.desc: Test GetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVQueueItems001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueItems001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    std::vector<AVQueueItem> items = {};
    ret = aVSessionProxy->GetAVQueueItems(items);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("GetAVQueueItems001, end");
}

/**
 * @tc.name: SetAVQueueItems001
 * @tc.desc: Test SetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVQueueItems001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVQueueItems001, start");
	
    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    std::vector<AVQueueItem> items = {};
    ret = aVSessionProxy->SetAVQueueItems(items);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetAVQueueItems001, end");
}

/**
 * @tc.name: GetAVQueueTitle001
 * @tc.desc: Test GetAVQueueTitle
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVQueueTitle001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueTitle001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
	
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    std::string title = "title";
    ret = aVSessionProxy->GetAVQueueTitle(title);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("GetAVQueueTitle001, end");
}

/**
 * @tc.name: SetAVQueueTitle001
 * @tc.desc: Test SetAVQueueTitle
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVQueueTitle001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVQueueTitle001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
	

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    std::string title = "title";
    ret = aVSessionProxy->SetAVQueueTitle(title);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetAVQueueTitle001, end");
}

/**
 * @tc.name: SetLaunchAbility001
 * @tc.desc: Test SetLaunchAbility
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetLaunchAbility001, testing::ext::TestSize.Level1)
{
    SLOGI("SetLaunchAbility001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    ret = aVSessionProxy->SetLaunchAbility(ability);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
	
    aVSessionProxy = nullptr;

    SLOGI("SetLaunchAbility001, end");
}

/**
 * @tc.name: GetExtras001
 * @tc.desc: Test GetExtras
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetExtras001, testing::ext::TestSize.Level1)
{
    SLOGI("GetExtras001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    OHOS::AAFwk::WantParams extras;
    ret = aVSessionProxy->GetExtras(extras);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("GetExtras001, end");
}

/**
 * @tc.name: SetExtras001
 * @tc.desc: Test SetExtras
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetExtras001, testing::ext::TestSize.Level1)
{
    SLOGI("SetExtras001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> aVSessionProxy = new AVSessionProxy(sessionInner);
    OHOS::AAFwk::WantParams extras;
    ret = aVSessionProxy->SetExtras(extras);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    aVSessionProxy = nullptr;

    SLOGI("SetExtras001, end");
}

/**
 * @tc.name: Activate001
 * @tc.desc: Test Activate
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, Activate001, testing::ext::TestSize.Level1)
{
    SLOGI("Activate001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
	
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);

    ret = avSessionProxy->Activate();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Activate001, end");
}

/**
 * @tc.name: Deactivate001
 * @tc.desc: Test Deactivate
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, Deactivate001, testing::ext::TestSize.Level1)
{
    SLOGI("Deactivate001, start");

    int32_t ret = AVSESSION_ERROR;
    bool retBool = false;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
	
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);

    ret = avSessionProxy->Activate();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    retBool = avSessionProxy->IsActive();
    EXPECT_EQ(retBool, true);
    ret = avSessionProxy->Deactivate();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    retBool = avSessionProxy->IsActive();
    EXPECT_EQ(retBool, false);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Deactivate001, end");
}

/**
 * @tc.name: SetSessionEvent001
 * @tc.desc: Test SetSessionEvent
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetSessionEvent001, testing::ext::TestSize.Level1)
{
    SLOGI("SetSessionEvent001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
	
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string event = "AVSessionCallback";
    OHOS::AAFwk::WantParams args;
    ret = avSessionProxy->SetSessionEvent(event, args);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionInner = nullptr;
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("SetSessionEvent001, end");
}

/**
 * @tc.name: AddSupportCommand001
 * @tc.desc: Test AddSupportCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, AddSupportCommand001, testing::ext::TestSize.Level1)
{
    SLOGI("AddSupportCommand001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);

    int32_t cmd = AVControlCommand::SESSION_CMD_PLAY;
    ret = avSessionProxy->AddSupportCommand(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
	
    sessionInner = nullptr;
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("AddSupportCommand001, end");
}

/**
 * @tc.name: DeleteSupportCommand001
 * @tc.desc: Test DeleteSupportCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, DeleteSupportCommand001, testing::ext::TestSize.Level1)
{
    SLOGI("DeleteSupportCommand001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);

    int32_t cmd = AVControlCommand::SESSION_CMD_PLAY;
    ret = avSessionProxy->AddSupportCommand(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    ret = avSessionProxy->DeleteSupportCommand(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("DeleteSupportCommand001, end");
}

/**

 * @tc.name: GetController001
 * @tc.desc: Test GetController
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetController001, testing::ext::TestSize.Level1)
{
    SLOGI("GetController001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = iface_cast<AVSessionProxy>(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(controllerInner != nullptr);

    std::shared_ptr<AVSessionController> avSessionController = avSessionProxy->GetController();

    sessionService->HandleSessionRelease(sessionId);
    sessionService->OnStop();
    sessionInner = nullptr;
    avSessionProxy = nullptr;
    controllerInner = nullptr;
    sessionService = nullptr;

    SLOGI("GetController001, end");
}

/**
 * @tc.name: RegisterCallback001
 * @tc.desc: Test RegisterCallback
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, RegisterCallback001, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterCallback001, start");

    int32_t ret = AVSESSION_ERROR;

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    sptr<AVSessionProxy> avSessionProxy = iface_cast<AVSessionProxy>(sessionInner);

    std::shared_ptr<AVSessionCallback> avSessionCallbackImpl = std::make_shared<AVSessionCallbackImpl>();
    ret = avSessionProxy->RegisterCallback(avSessionCallbackImpl);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string sessionId = avSessionProxy->GetSessionId();
    sessionService->HandleSessionRelease(sessionId);
    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;
    avSessionCallbackImpl = nullptr;

    SLOGI("RegisterCallback001, end");
}