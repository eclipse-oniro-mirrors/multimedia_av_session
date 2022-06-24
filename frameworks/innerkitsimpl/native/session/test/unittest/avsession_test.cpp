/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "avsession_manager.h"
#include "avsession_errors.h"
#include "want_agent.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avsession_log.h"
#include "avcontrol_command.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
int32_t g_onCall = AVSESSION_ERROR;
int32_t g_sessionId = AVSESSION_ERROR;
AVMetaData g_metaData;
AVPlaybackState g_playbackState;
static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";

class AvsessionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<AVSession> avsession_ = nullptr;
    std::shared_ptr<AVSessionController> controller_ = nullptr;
};

void AvsessionTest::SetUpTestCase(void)
{}

void AvsessionTest::TearDownTestCase(void)
{}

void AvsessionTest::SetUp(void)
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    avsession_ = AVSessionManager::CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(avsession_, nullptr);
    g_sessionId++;
    controller_ = AVSessionManager::CreateController(avsession_->GetSessionId());
    ASSERT_NE(controller_, nullptr);
}

void AvsessionTest::TearDown(void)
{
    int32_t ret = AVSESSION_ERROR;
    if (avsession_ != nullptr) {
        ret = avsession_->Destroy();
        ASSERT_EQ(AVSESSION_SUCCESS, ret);
    }
    if (controller_ != nullptr) {
        ret = controller_->Release();
        ASSERT_EQ(AVSESSION_SUCCESS, ret);
    }
    g_onCall = AVSESSION_ERROR;
}

class AVSessionCallbackImpl : public AVSessionCallback {
public:
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward() override;
    void OnRewind() override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediald) override;
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override;

    ~AVSessionCallbackImpl() override;
};

void AVSessionCallbackImpl::OnPlay()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPlay %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnPause()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPause %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnStop()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnStop %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnPlayNext()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPlayNext %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnPlayPrevious()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPlayPrevious %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnFastForward()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnFastForward %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnRewind()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnRewind %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnSeek(int64_t time)
{
    SLOGE("OnSeek %{public}" PRIu64, time);
    g_onCall = AVSESSION_SUCCESS;
}
void AVSessionCallbackImpl::OnSetSpeed(double speed)
{
    SLOGE("OnSetSpeed %{public}f", speed);
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnSetSpeed %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnSetLoopMode(int32_t loopMode)
{
    SLOGE("OnSetLoopMode %{public}d", loopMode);
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnSetLoopMode %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnToggleFavorite(const std::string& mediald)
{
    SLOGE("OnToggleFavorite %{public}s", mediald.c_str());
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnToggleFavorite %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent)
{
    SLOGE("OnMediaKeyEvent");
    g_onCall = AVSESSION_SUCCESS;
}
AVSessionCallbackImpl::~AVSessionCallbackImpl()
{
}

/**
* @tc.name: GetSessionId001
* @tc.desc: Return is Session ID
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, GetSessionId001, TestSize.Level1)
{
    SLOGE("GetSessionId001 Begin");
    int32_t ret = -1;
    ret = avsession_->GetSessionId();
    EXPECT_EQ(g_sessionId >= 0, true);
    SLOGE("GetSessionId001 End");
}

/**
* @tc.name: SetAVMetaData001
* @tc.desc: Return the result of set av meta data
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVMetaData001, TestSize.Level1)
{
    SLOGE("SetAVMetaData001 Begin");
    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(40000);
    g_metaData.SetMediaImageUri("https://baidu.yinyue.com");
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("https://baidu.yinyue.com");
    EXPECT_EQ(avsession_->SetAVMetaData(g_metaData), AVSESSION_SUCCESS);
    SLOGE("SetAVMetaData001 End");
}

/**
* @tc.name: GetAVMetaData001
* @tc.desc: Return get av meta data result
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, GetAVMetaData001, TestSize.Level1)
{
    SLOGE("GetAVMetaData001 Begin");
    EXPECT_EQ(avsession_->SetAVMetaData(g_metaData), AVSESSION_SUCCESS);
    AVMetaData metaData;
    metaData.Reset();
    EXPECT_EQ(avsession_->GetAVMetaData(metaData), AVSESSION_SUCCESS);
    EXPECT_EQ(metaData.GetAssetId(), g_metaData.GetAssetId());
    std::string title1 = metaData.GetTitle();
    SLOGE("title1 %{public}s", title1.c_str());
    std::string title2 = g_metaData.GetTitle();
    SLOGE("title2 %{public}s", title2.c_str());
    EXPECT_EQ(title1, title2);
    EXPECT_EQ(metaData.GetTitle(), g_metaData.GetTitle());
    EXPECT_EQ(metaData.GetArtist(), g_metaData.GetArtist());
    EXPECT_EQ(metaData.GetAuthor(), g_metaData.GetAuthor());
    EXPECT_EQ(metaData.GetAlbum(), g_metaData.GetAlbum());
    EXPECT_EQ(metaData.GetWriter(), g_metaData.GetWriter());
    EXPECT_EQ(metaData.GetComposer(), g_metaData.GetComposer());
    EXPECT_EQ(metaData.GetDuration(), g_metaData.GetDuration());
    EXPECT_EQ(metaData.GetMediaImageUri(), g_metaData.GetMediaImageUri());
    EXPECT_EQ(metaData.GetSubTitle(), g_metaData.GetSubTitle());
    EXPECT_EQ(metaData.GetDescription(), g_metaData.GetDescription());
    EXPECT_EQ(metaData.GetLyric(), g_metaData.GetLyric());
    SLOGE("GetAVMetaData001 End");
}

/**
* @tc.name: SetAVPlaybackState001
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState001, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState001 Begin");
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({ 80000, 0 });
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState001 End");
}

/**
* @tc.name: GetAVPlaybackState001
* @tc.desc: Return the result of get av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, GetAVPlaybackState001, TestSize.Level1)
{
    SLOGE("GetAVPlaybackState001 Begin");
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    AVPlaybackState state;
    EXPECT_EQ(avsession_->GetAVPlaybackState(state), AVSESSION_SUCCESS);
    EXPECT_EQ(state.GetState(), g_playbackState.GetState());
    EXPECT_EQ(state.GetSpeed(), g_playbackState.GetSpeed());
    EXPECT_EQ(state.GetPosistion().elapsedTime_, g_playbackState.GetPosistion().elapsedTime_);
    EXPECT_EQ(state.GetBufferedTime(), g_playbackState.GetBufferedTime());
    EXPECT_EQ(state.GetLoopMode(), g_playbackState.GetLoopMode());
    EXPECT_EQ(state.GetFavorite(), g_playbackState.GetFavorite());
    SLOGE("GetAVPlaybackState001 End");
}

/**
* @tc.name: SetLaunchAbility001
* @tc.desc: Return the result of set av launch ability
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetLaunchAbility001, TestSize.Level1)
{
    SLOGE("SetLaunchAbility001 Begin");
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    EXPECT_EQ(avsession_->SetLaunchAbility(ability), AVSESSION_SUCCESS);
    SLOGE("SetLaunchAbility001 End");
}

/**
* @tc.name: GetController001
* @tc.desc: Return shared_ptr of controller
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, GetController001, TestSize.Level1)
{
    SLOGE("GetController001 Begin");
    auto controller = avsession_->GetController();
    EXPECT_NE(controller, nullptr);
    SLOGE("GetController001 End");
}

/**
* @tc.name: RegisterCallback001
* @tc.desc: register avsession callback
* @tc.type: FUNC
* @tc.require: AR000H31JG
*/
HWTEST_F(AvsessionTest, RegisterCallback001, TestSize.Level1)
{
    SLOGE("RegisterCallback001 Begin");
    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);
    SLOGE("RegisterCallback001 End");
}

/**
* @tc.name: RegisterCallback002
* @tc.desc: register avsession callback
* @tc.type: FUNC
* @tc.require: AR000H31JG
*/
HWTEST_F(AvsessionTest, RegisterCallback002, TestSize.Level1)
{
    SLOGE("RegisterCallback002 Begin");
    std::shared_ptr<AVSessionCallback> callback = nullptr;
    EXPECT_NE(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);
    SLOGE("RegisterCallback002 End");
}

/**
* @tc.name: RegisterCallback003
* @tc.desc: register avsession callback
* @tc.type: FUNC
* @tc.require: AR000H31JG
*/
HWTEST_F(AvsessionTest, RegisterCallback003, TestSize.Level1)
{
    SLOGE("RegisterCallback003 Begin");
    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY), AVSESSION_SUCCESS);
    AVControlCommand cmd;
    EXPECT_EQ(cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->SendControlCommand(cmd), AVSESSION_SUCCESS);
    sleep(1);
    EXPECT_EQ(g_onCall, AVSESSION_SUCCESS);
    SLOGE("RegisterCallback003 End");
}

/**
* @tc.name: RegisterCallback004
* @tc.desc: register avsession callback
* @tc.type: FUNC
* @tc.require: AR000H31JG
*/
HWTEST_F(AvsessionTest, RegisterCallback004, TestSize.Level1)
{
    SLOGE("RegisterCallback004 Begin");
    std::shared_ptr<AVSessionCallback> callback001 = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_NE(callback001, nullptr);
    EXPECT_EQ(avsession_->RegisterCallback(callback001), AVSESSION_SUCCESS);
    EXPECT_EQ(avsession_->RegisterCallback(callback001), AVSESSION_SUCCESS);
    std::shared_ptr<AVSessionCallback> callback002 = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_NE(callback002, nullptr);
    EXPECT_EQ(avsession_->RegisterCallback(callback002), AVSESSION_SUCCESS);
    SLOGE("RegisterCallback004 End");
}

/**
* @tc.name: Active001
* @tc.desc: Return the active result
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, Active001, TestSize.Level1)
{
    SLOGE("Active001 Begin");
    bool isActive = false;
    EXPECT_EQ(avsession_->Activate(), AVSESSION_SUCCESS);
    isActive = avsession_->IsActive();
    EXPECT_EQ(isActive, true);
    SLOGE("Active001 End");
}

/**
* @tc.name: Disactive001
* @tc.desc: Return is Session Actived
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, Disactive001, TestSize.Level1)
{
    SLOGE("Disactive001 Begin");
    bool isActive = true;
    EXPECT_EQ(avsession_->Deactivate(), AVSESSION_SUCCESS);
    isActive = avsession_->IsActive();
    EXPECT_EQ(isActive, false);
    SLOGE("Disactive001 End");
}

/**
* @tc.name: AddSupportCommand001
* @tc.desc: add supported commands
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, AddSupportCommand001, TestSize.Level1)
{
    SLOGE("AddSupportCommand001 Begin");
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY), AVSESSION_SUCCESS);
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PAUSE), AVSESSION_SUCCESS);
    SLOGE("AddSupportCommand001 End");
}

/**
* @tc.name: AddSupportCommand002
* @tc.desc: add supported commands
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, AddSupportCommand002, TestSize.Level1)
{
    SLOGE("AddSupportCommand002 Begin");
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_INVALID), AVSESSION_ERROR);
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_MAX), AVSESSION_ERROR);
    SLOGE("AddSupportCommand002 End");
}

/**
* @tc.name: Destroy001
* @tc.desc: Return is Session Actived
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, Destroy001, TestSize.Level1)
{
    SLOGE("Destroy001 Begin");
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    SLOGE("Destroy001 End");
}