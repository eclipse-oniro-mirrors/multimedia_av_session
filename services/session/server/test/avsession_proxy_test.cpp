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


namespace OHOS::AVSession {

static std::shared_ptr<AVSessionService> g_AVSessionService;
static sptr<AVSessionProxy> g_AVSessionProxy;

class AVSessionProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionProxyTest::SetUpTestCase()
{
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
    std::string deviceId = "deviceId";
    std::string bundleName = "testItem.ohos.avsession";
    std::string abilityName = "testItem.ability";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    sptr<IRemoteObject> obj = g_AVSessionService->CreateSessionInner("test",
        AVSession::SESSION_TYPE_AUDIO, elementName);
    g_AVSessionProxy = iface_cast<AVSessionProxy>(obj);
    g_AVSessionProxy->Activate();
}

void AVSessionProxyTest::TearDownTestCase()
{
    g_AVSessionProxy->Deactivate();
    g_AVSessionService->Close();
}

void AVSessionProxyTest::SetUp()
{
}

void AVSessionProxyTest::TearDown()
{
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
    std::string sessionId = g_AVSessionProxy->GetSessionId();
    EXPECT_NE(sessionId, "");
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
    std::string typeStr = g_AVSessionProxy->GetSessionType();
    EXPECT_NE(typeStr, "");
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
    AVCallMetaData avCallMetaData;
    int32_t ret = g_AVSessionProxy->SetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(ret, AVSESSION_ERROR);
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
    AVCallMetaData avCallMetaData;
    avCallMetaData.SetName("name");
    avCallMetaData.SetPhoneNumber("number");
    int32_t ret = g_AVSessionProxy->SetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    g_AVSessionService->OnStop();
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
    AVCallState avCallState;
    avCallState.SetAVCallState(AVCallState::AVCALL_STATE_IDLE);
    int32_t ret = g_AVSessionProxy->SetAVCallState(avCallState);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    AVCallState avCallState;
    avCallState.SetAVCallState(-1);
    int32_t ret = g_AVSessionProxy->SetAVCallState(avCallState);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    AVMetaData meta;
    std::string assetId = "assetId";
    meta.SetAssetId(assetId);
    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 2, 3, 4, 5, 6, 7, 8};
    mediaImage->SetInnerImgBuffer(imgBuffer);
    meta.SetMediaImage(mediaImage);
    int32_t ret = g_AVSessionProxy->SetAVMetaData(meta);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    AVMetaData meta;
    int32_t ret = g_AVSessionProxy->GetAVMetaData(meta);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    AVPlaybackState state;
    int32_t ret = g_AVSessionProxy->GetAVPlaybackState(state);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    int32_t ret = g_AVSessionProxy->SetAVPlaybackState(avPlaybackState);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    std::vector<AVQueueItem> items = {};
    int32_t ret = g_AVSessionProxy->GetAVQueueItems(items);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    std::vector<AVQueueItem> items = {};
    int32_t ret = g_AVSessionProxy->SetAVQueueItems(items);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    std::string title = "title";
    int32_t ret = g_AVSessionProxy->GetAVQueueTitle(title);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    std::string title = "title";
    int32_t ret = g_AVSessionProxy->SetAVQueueTitle(title);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    int32_t ret = g_AVSessionProxy->SetLaunchAbility(ability);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    OHOS::AAFwk::WantParams extras;
    int32_t ret = g_AVSessionProxy->GetExtras(extras);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    OHOS::AAFwk::WantParams extras;
    int32_t ret = g_AVSessionProxy->SetExtras(extras);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetExtras001, end");
}

/**
 * @tc.name: isActivate001
 * @tc.desc: Test Deactivate
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, isActivate001, testing::ext::TestSize.Level1)
{
    SLOGI("isActivate001, start");
    int32_t ret = g_AVSessionProxy->IsActive();
    EXPECT_EQ(ret, true);
    SLOGI("isActivate001, end");
}

/**
 * @tc.name: SetSessionEvent001
 * @tc.desc: Test SetSessionEvent
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetSessionEvent001, testing::ext::TestSize.Level1)
{
    SLOGI("SetSessionEvent001, start");
    std::string event = "AVSessionCallback";
    OHOS::AAFwk::WantParams args;
    int32_t ret = g_AVSessionProxy->SetSessionEvent(event, args);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    int32_t cmd = AVControlCommand::SESSION_CMD_PLAY;
    int32_t ret = g_AVSessionProxy->AddSupportCommand(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    int32_t cmd = AVControlCommand::SESSION_CMD_PLAY;
    int32_t ret = g_AVSessionProxy->AddSupportCommand(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    ret = g_AVSessionProxy->DeleteSupportCommand(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
    std::string sessionId = g_AVSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    int32_t ret = g_AVSessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    std::shared_ptr<AVSessionController> avSessionController = g_AVSessionProxy->GetController();
    EXPECT_EQ(avSessionController, nullptr);
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
    std::shared_ptr<AVSessionCallback> avSessionCallbackImpl = std::make_shared<AVSessionCallbackImpl>();
    int32_t ret = g_AVSessionProxy->RegisterCallback(avSessionCallbackImpl);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("RegisterCallback001, end");
}


/**
 * @tc.name: SetAVMetaData002
 * @tc.desc: Test SetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVMetaData002, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVMetaData002, start");
    AVMetaData meta;
    std::string assetId = "assetId";
    meta.SetAssetId(assetId);
    
    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 2, 3, 4};
    mediaImage->SetInnerImgBuffer(imgBuffer);
    meta.SetMediaImage(mediaImage);

    std::shared_ptr<AVSessionPixelMap> avQueuePixel = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> pixelBuffer = {1, 2, 3, 4};
    avQueuePixel->SetInnerImgBuffer(pixelBuffer);
    meta.SetAVQueueImage(avQueuePixel);

    int32_t ret = g_AVSessionProxy->SetAVMetaData(meta);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetAVMetaData002, end");
}

/**
 * @tc.name: SetAVMetaData003
 * @tc.desc: Test SetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVMetaData003, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVMetaData003, start");
    AVMetaData meta;
    std::string assetId = "assetId";
    meta.SetAssetId(assetId);
    int32_t ret = g_AVSessionProxy->SetAVMetaData(meta);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetAVMetaData003, end");
}

/**
 * @tc.name: GetAVQueueItems002
 * @tc.desc: Test GetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVQueueItems002, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueItems002, start");
    std::vector<AVQueueItem> setItems;
    AVQueueItem item;
    setItems.push_back(item);
    g_AVSessionProxy->SetAVQueueItems(setItems);
    
    std::vector<AVQueueItem> getItems;
    int32_t ret = g_AVSessionProxy->GetAVQueueItems(getItems);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetAVQueueItems002, end");
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
/**
 * @tc.name: GetAVCastController001
 * @tc.desc: Test GetAVCastController
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVCastController001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVCastController001, start");
    auto ret = g_AVSessionProxy->GetAVCastController();
    EXPECT_EQ(ret, nullptr);
    SLOGI("GetAVCastController001, end");
}

/**
 * @tc.name: GetAllCastDisplays001
 * @tc.desc: Test GetAllCastDisplays
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAllCastDisplays001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAllCastDisplays001, start");
    std::vector<CastDisplayInfo> castDisplays;
    auto ret = g_AVSessionProxy->GetAllCastDisplays(castDisplays);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetAllCastDisplays001, end");
}
#endif

} //OHOS::AVSESSION