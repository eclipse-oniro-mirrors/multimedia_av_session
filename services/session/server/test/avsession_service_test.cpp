/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <memory>
#include <fstream>
#include <cstdio>

#include "avsession_log.h"
#include "input_manager.h"
#include "key_event.h"
#include "avsession_manager.h"
#include "avsession_errors.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avsession_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "system_ability_definition.h"
#include "system_ability_ondemand_reason.h"
#include "audio_info.h"
#include "avsession_callback_client.h"
#include "avsession_pixel_map.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_info.h"
#include "params_config_operator.h"
#include "avcontrol_command.h"
#include "want_agent_helper.h"

#define private public
#define protected public
#include "avsession_service.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AudioStandard;
static AVMetaData g_metaData;
static AVPlaybackState g_playbackState;
static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static int32_t g_playOnCall = AVSESSION_ERROR;
static int32_t g_pauseOnCall = AVSESSION_ERROR;
static int32_t g_nextOnCall = AVSESSION_ERROR;
static int32_t g_previousOnCall = AVSESSION_ERROR;
static AVSessionService *avservice_;
static AVControlCommand *avcommand_;

class AVSessionServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AVSession> avsession_ = nullptr;
};

void AVSessionServiceTest::SetUpTestCase()
{
    SLOGI("set up AVSessionServiceTest");
    system("killall -9 com.example.hiMusicDemo");
    sleep(1);
    avservice_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    avservice_->InitKeyEvent();
}

void AVSessionServiceTest::TearDownTestCase()
{
}

void AVSessionServiceTest::SetUp()
{
    SLOGI("set up test function in AVSessionServiceTest");
}

void AVSessionServiceTest::TearDown()
{
    SLOGI("tear down test function in AVSessionServiceTest");
    [[maybe_unused]] int32_t ret = AVSESSION_ERROR;
    if (avsession_ != nullptr) {
        ret = avsession_->Destroy();
        avsession_ = nullptr;
    }
}

class AVSessionCallbackImpl : public AVSessionCallback {
public:
    void OnPlay(const AVControlCommand& cmd) override;
    void OnPause() override;
    void OnStop() override {};
    void OnPlayNext(const AVControlCommand& cmd) override;
    void OnPlayPrevious(const AVControlCommand& cmd) override;
    void OnFastForward(int64_t time, const AVControlCommand& cmd) override {};
    void OnRewind(int64_t time, const AVControlCommand& cmd) override {};
    void OnSeek(int64_t time) override {};
    void OnSetSpeed(double speed) override {};
    void OnSetLoopMode(int32_t loopMode) override {};
    void OnSetTargetLoopMode(int32_t targetLoopMode) override {};
    void OnToggleFavorite(const std::string& mediaId) override {};
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override {};
    void OnOutputDeviceChange(const int32_t connectionState,
        const OHOS::AVSession::OutputDeviceInfo& outputDeviceInfo) override {};
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override {};
    void OnSkipToQueueItem(int32_t itemId) override {};
    void OnAVCallAnswer() override {};
    void OnAVCallHangUp() override {};
    void OnAVCallToggleCallMute() override {};
    void OnPlayFromAssetId(int64_t assetId) override {};
    void OnPlayWithAssetId(const std::string& assetId) override {};
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override {};

    ~AVSessionCallbackImpl() override;
};

void AVSessionCallbackImpl::OnPlay(const AVControlCommand& cmd)
{
    g_playOnCall = AVSESSION_SUCCESS;
    SLOGI("OnPlay %{public}d", g_playOnCall);
}

void AVSessionCallbackImpl::OnPause()
{
    g_pauseOnCall = AVSESSION_SUCCESS;
    SLOGI("OnPause %{public}d", g_pauseOnCall);
}

void AVSessionCallbackImpl::OnPlayNext(const AVControlCommand& cmd)
{
    g_nextOnCall = AVSESSION_SUCCESS;
    SLOGI("OnPlayNext %{public}d", g_nextOnCall);
}

void AVSessionCallbackImpl::OnPlayPrevious(const AVControlCommand& cmd)
{
    g_previousOnCall = AVSESSION_SUCCESS;
    SLOGI("OnPlayPrevious %{public}d", g_previousOnCall);
}

AVSessionCallbackImpl::~AVSessionCallbackImpl()
{
}

/**
* @tc.name: SendSystemAVKeyEvent001
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent001, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent001 with level0 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->Activate();
    avservice_->UpdateTopSession(avsessionHere_);

    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(40000);
    g_metaData.SetMediaImageUri("xxxxx");
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("xxxxx");
    avsessionHere_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsessionHere_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    OHOS::sptr<IAVSessionCallback> callbackClient = new(std::nothrow) AVSessionCallbackClient(callback);
    EXPECT_EQ(avsessionHere_->RegisterCallbackInner(callbackClient), AVSESSION_SUCCESS);

    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    item.SetDownTime(0);
    item.SetPressed(true);
    keyEvent->AddPressedKeyItems(item);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    sleep(1);
    EXPECT_EQ(g_pauseOnCall, AVSESSION_SUCCESS);
    g_pauseOnCall = false;
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SendSystemAVKeyEvent001 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent002
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent002, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->Activate();
    avservice_->UpdateTopSession(avsessionHere_);

    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(40000);
    g_metaData.SetMediaImageUri("xxxxx");
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("xxxxx");
    avsessionHere_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PAUSE);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsessionHere_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    OHOS::sptr<IAVSessionCallback> callbackClient = new(std::nothrow) AVSessionCallbackClient(callback);
    EXPECT_EQ(avsessionHere_->RegisterCallbackInner(callbackClient), AVSESSION_SUCCESS);

    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    item.SetDownTime(0);
    item.SetPressed(true);
    keyEvent->AddPressedKeyItems(item);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    sleep(1);
    EXPECT_EQ(g_playOnCall, AVSESSION_SUCCESS);
    g_playOnCall = false;
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SendSystemAVKeyEvent002 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent003
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent003, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent003 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->Activate();
    avservice_->UpdateTopSession(avsessionHere_);

    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(40000);
    g_metaData.SetMediaImageUri("xxxxx");
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("xxxxx");
    avsessionHere_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsessionHere_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    OHOS::sptr<IAVSessionCallback> callbackClient = new(std::nothrow) AVSessionCallbackClient(callback);
    EXPECT_EQ(avsessionHere_->RegisterCallbackInner(callbackClient), AVSESSION_SUCCESS);

    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    item.SetDownTime(0);
    item.SetPressed(true);
    keyEvent->AddPressedKeyItems(item);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    sleep(1);
    EXPECT_EQ(g_nextOnCall, AVSESSION_SUCCESS);
    g_nextOnCall = false;
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SendSystemAVKeyEvent003 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent004
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent004, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent004 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->Activate();
    avservice_->UpdateTopSession(avsessionHere_);
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(40000);
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("xxxxx");
    avsessionHere_->SetAVMetaData(g_metaData);
    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsessionHere_->SetAVPlaybackState(g_playbackState);
    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    OHOS::sptr<IAVSessionCallback> callbackClient = new(std::nothrow) AVSessionCallbackClient(callback);
    EXPECT_EQ(avsessionHere_->RegisterCallbackInner(callbackClient), AVSESSION_SUCCESS);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    item.SetDownTime(0);
    item.SetPressed(true);
    keyEvent->AddPressedKeyItems(item);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    sleep(1);
    EXPECT_EQ(g_previousOnCall, AVSESSION_SUCCESS);
    g_previousOnCall = false;
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SendSystemAVKeyEvent004 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent005
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent005, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent005 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->Activate();
    avservice_->UpdateTopSession(avsessionHere_);
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(40000);
    g_metaData.SetMediaImageUri("xxxxx");
    g_metaData.SetDescription("for friends");
    avsessionHere_->SetAVMetaData(g_metaData);
    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsessionHere_->SetAVPlaybackState(g_playbackState);
    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    OHOS::sptr<IAVSessionCallback> callbackClient = new(std::nothrow) AVSessionCallbackClient(callback);
    EXPECT_EQ(avsessionHere_->RegisterCallbackInner(callbackClient), AVSESSION_SUCCESS);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    item.SetDownTime(0);
    item.SetPressed(true);
    keyEvent->AddPressedKeyItems(item);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    sleep(1);
    EXPECT_EQ(g_previousOnCall, AVSESSION_SUCCESS);
    g_previousOnCall = false;
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SendSystemAVKeyEvent005 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent006
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent006, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent006 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->Activate();
    avservice_->UpdateTopSession(avsessionHere_);
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(40000);
    avsessionHere_->SetAVMetaData(g_metaData);
    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsessionHere_->SetAVPlaybackState(g_playbackState);
    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    OHOS::sptr<IAVSessionCallback> callbackClient = new(std::nothrow) AVSessionCallbackClient(callback);
    EXPECT_EQ(avsessionHere_->RegisterCallbackInner(callbackClient), AVSESSION_SUCCESS);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HEADSETHOOK);
    item.SetDownTime(0);
    item.SetPressed(true);
    keyEvent->AddPressedKeyItems(item);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    sleep(1);
    EXPECT_EQ(g_nextOnCall, AVSESSION_SUCCESS);
    g_nextOnCall = false;
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    sleep(1);
    EXPECT_EQ(g_pauseOnCall, AVSESSION_SUCCESS);
    g_pauseOnCall = false;
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("SendSystemAVKeyEvent006 end!");
}

static HWTEST_F(AVSessionServiceTest, NotifyDeviceAvailable001, TestSize.Level0)
{
    SLOGI("NotifyDeviceAvailable001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyDeviceAvailable001 in!");
    OutputDeviceInfo outputDeviceInfo;
    OHOS::AVSession::DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "deviceId";
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    avservice_->NotifyDeviceAvailable(outputDeviceInfo);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("NotifyDeviceAvailable001 end!");
}

static HWTEST_F(AVSessionServiceTest, NotifyMirrorToStreamCast001, TestSize.Level0)
{
    SLOGI("NotifyMirrorToStreamCast001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyMirrorToStreamCast001 in!");
    avservice_->NotifyMirrorToStreamCast();
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("NotifyMirrorToStreamCast001 end!");
}

static HWTEST_F(AVSessionServiceTest, NotifyMirrorToStreamCast002, TestSize.Level0)
{
    SLOGI("NotifyMirrorToStreamCast002 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyMirrorToStreamCast002 in!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->UpdateTopSession(avsessionHere_);
    avservice_->NotifyMirrorToStreamCast();
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("NotifyMirrorToStreamCast002 end!");
}

static HWTEST_F(AVSessionServiceTest, NotifyMirrorToStreamCast003, TestSize.Level0)
{
    SLOGI("NotifyMirrorToStreamCast003 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyMirrorToStreamCast002 in!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->UpdateTopSession(avsessionHere_);
    avservice_->NotifyMirrorToStreamCast();
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("NotifyMirrorToStreamCast003 end!");
}

static HWTEST_F(AVSessionServiceTest, RefreshFocusSessionSort001, TestSize.Level0)
{
    SLOGI("RefreshFocusSessionSort001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->RefreshFocusSessionSort(avsessionHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("RefreshFocusSessionSort001 end!");
}

static HWTEST_F(AVSessionServiceTest, SelectSessionByUid001, TestSize.Level0)
{
    SLOGI("SelectSessionByUid001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    AudioRendererChangeInfo info = {};
    info.clientUID = 0;
    avservice_->SelectSessionByUid(info);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("SelectSessionByUid001 end!");
}

static HWTEST_F(AVSessionServiceTest, SelectSessionByUid002, TestSize.Level0)
{
    SLOGI("SelectSessionByUid002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    AudioRendererChangeInfo info = {};
    info.clientUID = avsessionHere_->GetUid();
    avservice_->SelectSessionByUid(info);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("SelectSessionByUid002 end!");
}

static HWTEST_F(AVSessionServiceTest, InitBMS001, TestSize.Level0)
{
    SLOGI("InitBMS001 begin!");
    avservice_->InitBMS();
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("InitBMS001 end!");
}

static HWTEST_F(AVSessionServiceTest, ReleaseCastSession001, TestSize.Level0)
{
    SLOGI("ReleaseCastSession001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("ReleaseCastSession001 in!");
    avservice_->ReleaseCastSession();
#endif
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("ReleaseCastSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateSessionByCast001, TestSize.Level0)
{
    SLOGI("CreateSessionByCast001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("CreateSessionByCast001 in!");
    avservice_->CreateSessionByCast(0);
    avservice_->ClearSessionForClientDiedNoLock(getpid(), false);
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("CreateSessionByCast001 end!");
}

static HWTEST_F(AVSessionServiceTest, MirrorToStreamCast001, TestSize.Level0)
{
    SLOGI("MirrorToStreamCast001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("MirrorToStreamCast001 in!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->isCastableDevice_ = true;
    avservice_->MirrorToStreamCast(avsessionHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("MirrorToStreamCast001 end!");
}

static HWTEST_F(AVSessionServiceTest, MirrorToStreamCast002, TestSize.Level0)
{
    SLOGI("MirrorToStreamCast002 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("MirrorToStreamCast002 in!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->isCastableDevice_ = false;
    avservice_->MirrorToStreamCast(avsessionHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("MirrorToStreamCast002 end!");
}

static HWTEST_F(AVSessionServiceTest, MirrorToStreamCast003, TestSize.Level0)
{
    SLOGI("MirrorToStreamCast003 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("MirrorToStreamCast003 in!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->isCastableDevice_ = true;
    avservice_->MirrorToStreamCast(avsessionHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("MirrorToStreamCast003 end!");
}

static HWTEST_F(AVSessionServiceTest, SaveSessionInfoInFile001, TestSize.Level0)
{
    SLOGI("SaveSessionInfoInFile001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->SaveSessionInfoInFile("RemoteCast", avsessionHere_->GetSessionId(),
        "audio", elementName);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("SaveSessionInfoInFile001 end!");
}

static HWTEST_F(AVSessionServiceTest, HandleSystemKeyColdStart001, TestSize.Level0)
{
    SLOGI("HandleSystemKeyColdStart001 begin");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_EQ(avsessionHere_ != nullptr, true);
    AVControlCommand command;
    avservice_->HandleSystemKeyColdStart(command);
    EXPECT_NE(avsessionHere_, avservice_->topSession_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleSystemKeyColdStart001 end");
}

static HWTEST_F(AVSessionServiceTest, HandleSystemKeyColdStart002, TestSize.Level0)
{
    SLOGD("HandleSystemKeyColdStart002 begin");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_EQ(avsessionHere != nullptr, true);
    AVControlCommand command;
    command.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    avservice_->HandleSystemKeyColdStart(command);
    command.SetCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
    avservice_->HandleSystemKeyColdStart(command);
    command.SetCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
    avservice_->HandleSystemKeyColdStart(command);
    EXPECT_NE(avsessionHere, avservice_->topSession_);
    avservice_->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    SLOGD("HandleSystemKeyColdStart002 end");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalAVQueueInfos001, TestSize.Level0)
{
    SLOGI("GetHistoricalAVQueueInfos001 begin!");
    std::vector<AVQueueInfo> avQueueInfos_;
    avservice_->GetHistoricalAVQueueInfos(0, 0, avQueueInfos_);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalAVQueueInfos001 end!");
}

static HWTEST_F(AVSessionServiceTest, SaveAvQueueInfo001, TestSize.Level0)
{
    SLOGI("SaveAvQueueInfo001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    AVMetaData meta = avsessionHere_->GetMetaData();
    std::string oldContent;
    if (!avservice_->LoadStringFromFileEx(avservice_->GetAVQueueDir(), oldContent)) {
        SLOGE("SaveAvQueueInfo001 read avqueueinfo fail, Return!");
    } else {
        avservice_->SaveAvQueueInfo(oldContent, g_testAnotherBundleName, meta,
            avservice_->GetUsersManager().GetCurrentUserId());
        avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
        EXPECT_EQ(0, AVSESSION_SUCCESS);
        SLOGI("SaveAvQueueInfo001 end!");
    }
}

static HWTEST_F(AVSessionServiceTest, AddAvQueueInfoToFile001, TestSize.Level0)
{
    SLOGI("AddAvQueueInfoToFile001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->AddAvQueueInfoToFile(*avsessionHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("AddAvQueueInfoToFile001 end!");
}

static HWTEST_F(AVSessionServiceTest, StartAVPlayback001, TestSize.Level0)
{
    SLOGI("StartAVPlayback001 begin!");
    std::string moduleName = "moduleName";
    avservice_->StartAVPlayback(g_testAnotherBundleName, "FAKE_ASSET_NAME", moduleName);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("StartAVPlayback001 end!");
}

static HWTEST_F(AVSessionServiceTest, StartAVPlayback002, TestSize.Level0)
{
    SLOGI("StartAVPlayback002 begin!");
    std::string deviceId = "123";
    std::string moduleName = "moduleName";
    avservice_->StartAVPlayback(g_testAnotherBundleName, "FAKE_ASSET_NAME", moduleName, deviceId);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("StartAVPlayback002 end!");
}

static HWTEST_F(AVSessionServiceTest, StartAVPlayback003, TestSize.Level1)
{
    SLOGI("StartAVPlayback003 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("ancoMediaSession", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->SaveSessionInfoInFile("ancoMediaSession", avsessionHere_->GetSessionId(),
        "audio", elementName);
    avservice_->isAudioBrokerStart_ = true;
    std::string moduleName = "moduleName";
    auto ret = avservice_->StartAVPlayback(g_testAnotherBundleName, "FAKE_ASSET_NAME", moduleName);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    avservice_->isAudioBrokerStart_ = false;
    avsessionHere_->Destroy();
    SLOGI("StartAVPlayback003 end!");
}

static HWTEST_F(AVSessionServiceTest, GetSubNode001, TestSize.Level0)
{
    SLOGI("GetSubNode001 begin!");

    cJSON* value = cJSON_CreateObject();
    if (value == nullptr) {
        SLOGE("get value nullptr");
        FAIL();
    }
    if (cJSON_IsInvalid(value)) {
        SLOGE("get value invalid");
        cJSON_Delete(value);
        value = nullptr;
        FAIL();
    }
    cJSON_AddStringToObject(value, "bundleName", g_testAnotherBundleName);
    avservice_->GetSubNode(value, "FAKE_NAME");
    EXPECT_EQ(0, AVSESSION_SUCCESS);

    cJSON_Delete(value);
    value = nullptr;
    SLOGI("GetSubNode001 end!");
}

static HWTEST_F(AVSessionServiceTest, Close001, TestSize.Level0)
{
    SLOGI("Close001 begin!");
    avservice_->Close();
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("Close001 end!");
}

static HWTEST_F(AVSessionServiceTest, DeleteHistoricalRecord001, TestSize.Level0)
{
    SLOGI("DeleteHistoricalRecord001 begin!");
    avservice_->DeleteHistoricalRecord(g_testAnotherBundleName);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("DeleteHistoricalRecord001 end!");
}

static HWTEST_F(AVSessionServiceTest, Dump001, TestSize.Level0)
{
    SLOGI("Dump001 begin!");
    std::vector<std::u16string> argsList;
    avservice_->Dump(1, argsList);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("Dump001 end!");
}

static HWTEST_F(AVSessionServiceTest, ProcessCastAudioCommand001, TestSize.Level0)
{
    SLOGI("ProcessCastAudioCommand001 begin!");
    std::string sourceSessionInfo = "SOURCE";
    std::string sinkSessionInfo = " SINK";
    avservice_->ProcessCastAudioCommand(
        OHOS::AVSession::AVSessionServiceStub::RemoteServiceCommand::COMMAND_CAST_AUDIO,
        sourceSessionInfo, sinkSessionInfo);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("ProcessCastAudioCommand001 end!");
}

static HWTEST_F(AVSessionServiceTest, ProcessCastAudioCommand002, TestSize.Level0)
{
    SLOGI("ProcessCastAudioCommand002 begin!");
    std::string sourceSessionInfo = "SOURCE";
    std::string sinkSessionInfo = " SINK";
    avservice_->ProcessCastAudioCommand(
        OHOS::AVSession::AVSessionServiceStub::RemoteServiceCommand::COMMAND_CANCEL_CAST_AUDIO,
        sourceSessionInfo, sinkSessionInfo);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("ProcessCastAudioCommand002 end!");
}

static HWTEST_F(AVSessionServiceTest, OnReceiveEvent001, TestSize.Level1)
{
    SLOGI("OnReceiveEvent001 begin!");
    OHOS::EventFwk::CommonEventData eventData;
    string action = OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON;
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, avservice_);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("OnReceiveEvent001 end!");
}

static HWTEST_F(AVSessionServiceTest, OnReceiveEvent002, TestSize.Level0)
{
    SLOGI("OnReceiveEvent002 begin!");
    OHOS::EventFwk::CommonEventData eventData;
    string action = OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF;
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, avservice_);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("OnReceiveEvent002 end!");
}

static HWTEST_F(AVSessionServiceTest, OnReceiveEvent004, TestSize.Level1)
{
    SLOGD("OnReceiveEvent004 begin!");
    OHOS::EventFwk::CommonEventData eventData;
    string action = "usual.event.PACKAGE_REMOVED";
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    want.SetElement(elementName);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, avservice_);
    eventSubscriber.OnReceiveEvent(eventData);
    SLOGD("OnReceiveEvent004 end!");
}

static HWTEST_F(AVSessionServiceTest, OnReceiveEvent005, TestSize.Level1)
{
    SLOGD("OnReceiveEvent005 begin!");
    OHOS::EventFwk::CommonEventData eventData;
    string action = "usual.event.CAST_SESSION_CREATE";
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, avservice_);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_TRUE(avservice_ != nullptr);
    SLOGD("OnReceiveEvent005 end!");
}

static HWTEST_F(AVSessionServiceTest, UnSubscribeCommonEvent001, TestSize.Level0)
{
    SLOGI("SubscribeCommonEvent001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    avservice_->SubscribeCommonEvent();
    avservice_->UnSubscribeCommonEvent();
    SLOGI("SubscribeCommonEvent001 end!");
}

static HWTEST_F(AVSessionServiceTest, UnSubscribeCommonEvent002, TestSize.Level0)
{
    SLOGI("SubscribeCommonEvent002 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    avservice_->UnSubscribeCommonEvent();
    SLOGI("SubscribeCommonEvent002 end!");
}

static HWTEST_F(AVSessionServiceTest, OnRemoveSystemAbility001, TestSize.Level0)
{
    SLOGI("OnRemoveSystemAbility001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    int32_t systemAbilityId = 65546;
    std::string deviceId = "";
    avservice_->OnRemoveSystemAbility(systemAbilityId, deviceId);
    SLOGI("OnRemoveSystemAbility001 end!");
}

static HWTEST_F(AVSessionServiceTest, OnRemoveSystemAbility002, TestSize.Level0)
{
    SLOGI("OnRemoveSystemAbility002 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    int32_t systemAbilityId = 111222;
    std::string deviceId = "";
    avservice_->OnRemoveSystemAbility(systemAbilityId, deviceId);
    SLOGI("OnRemoveSystemAbility002 end!");
}

static HWTEST_F(AVSessionServiceTest, OnRemoveSystemAbility003, TestSize.Level1)
{
    SLOGI("OnRemoveSystemAbility003 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    int32_t systemAbilityId = 66849;
    std::string deviceId = "";
    avservice_->OnRemoveSystemAbility(systemAbilityId, deviceId);
    EXPECT_EQ(avservice_->isAudioBrokerStart_, false);
    SLOGI("OnRemoveSystemAbility003 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptorsFromFile001, TestSize.Level0)
{
    SLOGI("GetHistoricalSessionDescriptorsFromFile001 begin!");
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = avservice_->GetHistoricalSessionDescriptorsFromFile(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalSessionDescriptorsFromFile001 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptorsFromFile002, TestSize.Level1)
{
    SLOGI("GetHistoricalSessionDescriptorsFromFile002 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("ancoMediaSession", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->SaveSessionInfoInFile("ancoMediaSession", avsessionHere_->GetSessionId(),
        "audio", elementName);
    avservice_->isAudioBrokerStart_ = false;
    std::vector<AVSessionDescriptor> descriptors;
    auto ret = avservice_->GetHistoricalSessionDescriptorsFromFile(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    avservice_->isAudioBrokerStart_ = true;
    ret = avservice_->GetHistoricalSessionDescriptorsFromFile(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    avsessionHere_->Destroy();
    SLOGI("GetHistoricalSessionDescriptorsFromFile002 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptors001, TestSize.Level0)
{
    SLOGI("GetHistoricalSessionDescriptors001 begin!");
    int32_t maxSize = -1;
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = avservice_->GetHistoricalSessionDescriptors(maxSize, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalSessionDescriptors001 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptors002, TestSize.Level0)
{
    SLOGI("GetHistoricalSessionDescriptors002 begin!");
    int32_t maxSize = 50;
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = avservice_->GetHistoricalSessionDescriptors(maxSize, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalSessionDescriptors002 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptors003, TestSize.Level0)
{
    SLOGI("GetHistoricalSessionDescriptors003 begin!");
    int32_t maxSize = 10;
    std::vector<AVSessionDescriptor> descriptors;
    for (int i = 0; i <= maxSize; i++) {
        AVSessionDescriptor aVSessionDescriptor;
        descriptors.emplace_back(aVSessionDescriptor);
    }
    int32_t ret = avservice_->GetHistoricalSessionDescriptors(maxSize, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalSessionDescriptors003 end!");
}

static HWTEST_F(AVSessionServiceTest, DoMetadataImgClean001, TestSize.Level0)
{
    SLOGI("DoMetadataImgClean001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AVSession::AVMetaData metaData;

    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 1, 0, 1, 1};
    avQueuePixelMap->SetInnerImgBuffer(imgBuffer);
    metaData.SetAVQueueImage(avQueuePixelMap);

    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer2 = {1, 0, 0, 0, 1};
    mediaPixelMap->SetInnerImgBuffer(imgBuffer2);
    metaData.SetMediaImage(mediaPixelMap);
    
    avservice_->DoMetadataImgClean(metaData);
    SLOGI("DoMetadataImgClean001 end!");
}

static HWTEST_F(AVSessionServiceTest, DoMetadataImgClean002, TestSize.Level0)
{
    SLOGI("DoMetadataImgClean002 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AVSession::AVMetaData metaData;
    avservice_->DoMetadataImgClean(metaData);
    SLOGI("DoMetadataImgClean002 end!");
}

static HWTEST_F(AVSessionServiceTest, Dump002, TestSize.Level0)
{
    SLOGI("Dump002 begin!");
    int32_t fd = -1;
    std::vector<std::u16string> argsList;
    int32_t ret = avservice_->Dump(fd, argsList);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("Dump002 end!");
}

static HWTEST_F(AVSessionServiceTest, GetTrustedDeviceName001, TestSize.Level0)
{
    SLOGI("GetTrustedDeviceName001 begin!");
    std::string networkId = "";
    std::string deviceName = "";
    int32_t ret = avservice_->GetTrustedDeviceName(networkId, deviceName);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetTrustedDeviceName001 end!");
}

static HWTEST_F(AVSessionServiceTest, HandleFocusSession001, TestSize.Level0)
{
    SLOGI("HandleFocusSession001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    int32_t pid = 201;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->SetUid(pid);
    avservice_->UpdateTopSession(avsessionHere_);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = pid;
    avservice_->HandleFocusSession(info, false);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleFocusSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, HandleFocusSession002, TestSize.Level0)
{
    SLOGI("HandleFocusSession002 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    int32_t pid = 202;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    avsessionHere_->SetUid(pid);
    avservice_->UpdateTopSession(avsessionHere_);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 203;
    avservice_->HandleFocusSession(info, false);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleFocusSession002 end!");
}

static HWTEST_F(AVSessionServiceTest, UpdateFrontSession001, TestSize.Level0)
{
    SLOGI("HandleFocusSession001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    int32_t pid = 203;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->SetUid(pid);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = pid;
    avservice_->HandleFocusSession(info, false);
    avservice_->UpdateFrontSession(avsessionHere_, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleFocusSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, UpdateFrontSession002, TestSize.Level0)
{
    SLOGI("UpdateFrontSession002 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    int32_t pid = 204;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->SetUid(pid);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 205;
    avservice_->HandleFocusSession(info, false);
    avservice_->UpdateFrontSession(avsessionHere_, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("UpdateFrontSession002 end!");
}

static HWTEST_F(AVSessionServiceTest, SelectFocusSession001, TestSize.Level0)
{
    SLOGI("SelectFocusSession001 begin!");
    int32_t pid = 205;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->SetUid(pid);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.pid = avsessionHere_->GetPid();
    bool ret = avservice_->SelectFocusSession(info);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, true);
    SLOGI("SelectFocusSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, SelectFocusSession002, TestSize.Level0)
{
    SLOGI("SelectFocusSession002 begin!");
    int32_t pid = 206;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->SetUid(pid);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 207;
    bool ret = avservice_->SelectFocusSession(info);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, false);
    SLOGI("SelectFocusSession002 end!");
}

static HWTEST_F(AVSessionServiceTest, SelectSessionByUid003, TestSize.Level0)
{
    SLOGI("SelectSessionByUid003 begin!");
    int32_t pid = 207;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avsessionHere_->SetUid(pid);
    AudioRendererChangeInfo info = {};
    info.clientUID = 208;
    auto ret = avservice_->SelectSessionByUid(info);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, nullptr);
    SLOGI("SelectSessionByUid003 end!");
}

static HWTEST_F(AVSessionServiceTest, GetSessionDescriptorsBySessionId001, TestSize.Level0)
{
    SLOGI("GetSessionDescriptorsBySessionId001 begin!");
    int32_t pid = 206;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->SetUid(pid);
    std::string sessionId = "";
    AVSessionDescriptor descriptor;
    int32_t ret = avservice_->GetSessionDescriptorsBySessionId(sessionId, descriptor);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetSessionDescriptorsBySessionId001 end!");
}

static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent007, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent007 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool ret = avservice_->SendSystemAVKeyEvent(*keyEvent);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SendSystemAVKeyEvent007 end!");
}


static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent008, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent008 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    avservice_->UpdateTopSession(avsessionHere_);
    bool ret = avservice_->SendSystemAVKeyEvent(*keyEvent);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SendSystemAVKeyEvent008 end!");
}

static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent009, TestSize.Level0)
{
    SLOGI("SendSystemAVKeyEvent009 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    OHOS::AAFwk::Want bluetoothWant;
    std::string activeAddress = "00:00:00:00:00:00";
    bluetoothWant.SetParam("deviceId", activeAddress);
    bool ret = avservice_->SendSystemAVKeyEvent(*keyEvent, bluetoothWant);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SendSystemAVKeyEvent009 end!");
}

static HWTEST_F(AVSessionServiceTest, PullMigrateStub001, TestSize.Level0)
{
    SLOGI("PullMigrateStub001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    avservice_->PullMigrateStub();
    SLOGI("PullMigrateStub001 end!");
}

static HWTEST_F(AVSessionServiceTest, UpdateFrontSession003, TestSize.Level0)
{
    SLOGI("UpdateFrontSession003 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    int32_t pid = 304;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    avsessionHere_->SetUid(pid);
    avservice_->UpdateFrontSession(avsessionHere_, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("UpdateFrontSession003 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateSessionInner001, TestSize.Level0)
{
    SLOGI("CreateSessionInner001 begin!");
    OHOS::sptr<AVSessionItem> sessionItem = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("######");
    elementName.SetAbilityName(g_testAnotherAbilityName);
    int32_t ret = avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO,
                    false, elementName, sessionItem);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("CreateSessionInner001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateSessionInner002, TestSize.Level0)
{
    SLOGI("CreateSessionInner001 begin!");
    OHOS::sptr<AVSessionItem> sessionItem = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName("######");
    int32_t ret = avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO,
                    false, elementName, sessionItem);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("CreateSessionInner001 end!");
}

static HWTEST_F(AVSessionServiceTest, ReportSessionInfo001, TestSize.Level0)
{
    SLOGI("ReportSessionInfo001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::sptr<AVSessionItem> avsessionHere_ = nullptr;
    avservice_->ReportSessionInfo(avsessionHere_, true);
    SLOGI("ReportSessionInfo001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateNewControllerForSession001, TestSize.Level0)
{
    SLOGI("CreateNewControllerForSession001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    pid_t pid = 2222;
    auto ret = avservice_->CreateNewControllerForSession(pid, avsessionHere_);
    EXPECT_NE(ret, nullptr);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("CreateNewControllerForSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, IsHistoricalSession001, TestSize.Level0)
{
    SLOGI("IsHistoricalSession001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    std::string sessionId = avsessionHere_->GetSessionId();
    bool ret = avservice_->IsHistoricalSession(sessionId);
    EXPECT_EQ(ret, false);
    avservice_->HandleSessionRelease(sessionId);
    avsessionHere_->Destroy();
    SLOGI("IsHistoricalSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, StartDefaultAbilityByCall001, TestSize.Level0)
{
    SLOGI("StartDefaultAbilityByCall001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    std::string sessionId = avsessionHere_->GetSessionId();
    int32_t ret = avservice_->StartDefaultAbilityByCall(sessionId);
    // startability may go with mediaintent, will return AVSESSION_ERROR
    EXPECT_EQ(ret == ERR_ABILITY_NOT_AVAILABLE || ret == AVSESSION_SUCCESS || ret == AVSESSION_ERROR||
        ret == ERR_START_ABILITY_TIMEOUT, true);
    avservice_->HandleSessionRelease(sessionId);
    avsessionHere_->Destroy();
    SLOGI("StartDefaultAbilityByCall001 end!");
}

static HWTEST_F(AVSessionServiceTest, StartAbilityByCall001, TestSize.Level0)
{
    SLOGI("StartAbilityByCall001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    std::string sessionIdNeeded = "";
    std::string sessionId = "";
    int32_t ret = avservice_->StartAbilityByCall(sessionIdNeeded, sessionId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    avsessionHere_->Destroy();
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    SLOGI("StartAbilityByCall001 end!");
}

static HWTEST_F(AVSessionServiceTest, SendSystemControlCommand001, TestSize.Level0)
{
    SLOGI("SendSystemControlCommand001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avservice_->UpdateFrontSession(avsessionHere_, true);
    AVControlCommand command;
    command.SetCommand(1000);
    int32_t ret = avservice_->SendSystemControlCommand(command);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SendSystemControlCommand001 end!");
}

static HWTEST_F(AVSessionServiceTest, HandleControllerRelease001, TestSize.Level0)
{
    SLOGI("HandleControllerRelease001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    OHOS::sptr<AVControllerItem> avcontrollerHere_ =
        avservice_->CreateNewControllerForSession(avsessionHere_->GetPid(), avsessionHere_);
    avservice_->HandleControllerRelease(*avcontrollerHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleControllerRelease001 end!");
}

static HWTEST_F(AVSessionServiceTest, GetDeviceInfo001, TestSize.Level0)
{
    SLOGI("GetDeviceInfo001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors;
    avservice_->GetDeviceInfo(avsessionHere_, descriptors, descriptors, descriptors);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("GetDeviceInfo001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateControllerInner001, TestSize.Level0)
{
    SLOGI("CreateControllerInner001 begin!");
    std::string sessionId = "default";
    OHOS::sptr<IRemoteObject> object = nullptr;
    int32_t ret = avservice_->CreateControllerInner(sessionId, object);
    // startability may go with mediaintent, will return AVSESSION_ERROR
    EXPECT_EQ(ret == ERR_ABILITY_NOT_AVAILABLE || ret == AVSESSION_SUCCESS
        || ret == AVSESSION_ERROR || ret == ERR_SESSION_NOT_EXIST, true);
    SLOGI("CreateControllerInner001 end!");
}

static HWTEST_F(AVSessionServiceTest, ClearControllerForClientDiedNoLock001, TestSize.Level0)
{
    SLOGI("ClearControllerForClientDiedNoLock001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::string sessionId = avsessionHere_->GetSessionId();
    OHOS::sptr<IRemoteObject> object = nullptr;
    int32_t ret = avservice_->CreateControllerInner(sessionId, object);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    avservice_->ClearControllerForClientDiedNoLock(avsessionHere_->GetPid());
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("ClearControllerForClientDiedNoLock001 end!");
}

static HWTEST_F(AVSessionServiceTest, LoadStringFromFileEx001, TestSize.Level0)
{
    SLOGI("LoadStringFromFileEx001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);

    std::string filePath = avservice_->GetUsersManager().GetDirForCurrentUser() + "test1.txt";
    std::string content;
    bool ret = avservice_->LoadStringFromFileEx(filePath, content);
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("LoadStringFromFileEx001 end!");
}

static HWTEST_F(AVSessionServiceTest, LoadStringFromFileEx002, TestSize.Level0)
{
    SLOGI("LoadStringFromFileEx002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    int32_t maxFileLength = 32 * 1024 * 1024;
    std::string filePath = avservice_->GetUsersManager().GetDirForCurrentUser() + "test2.txt";
    std::ofstream ofs;
    ofs.open(filePath, std::ios::out);
    for (int32_t i = 0; i <= maxFileLength; i++) {
        ofs << "A";
    }
    ofs.close();
    std::string content;
    bool ret = avservice_->LoadStringFromFileEx(filePath, content);
    EXPECT_EQ(ret, false);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("LoadStringFromFileEx002 end!");
}

static HWTEST_F(AVSessionServiceTest, LoadStringFromFileEx003, TestSize.Level0)
{
    SLOGI("LoadStringFromFileEx003 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);

    std::string filePath = "/test3.txt";
    std::string content;
    std::ifstream file(filePath, std::ios_base::in);
    bool ret = avservice_->LoadStringFromFileEx(filePath, content);
    file.close();
    EXPECT_EQ(ret, false);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("LoadStringFromFileEx003 end!");
}

static HWTEST_F(AVSessionServiceTest, CheckStringAndCleanFile001, TestSize.Level0)
{
    SLOGI("CheckStringAndCleanFile001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);

    std::string filePath = avservice_->GetUsersManager().GetDirForCurrentUser() + "test6.txt";
    bool ret = avservice_->CheckStringAndCleanFile(filePath);
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("CheckStringAndCleanFile001 end!");
}

static HWTEST_F(AVSessionServiceTest, CheckStringAndCleanFile002, TestSize.Level0)
{
    SLOGI("CheckStringAndCleanFile002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);

    std::string filePath = avservice_->GetUsersManager().GetDirForCurrentUser() + "adcdXYZ123/test7.txt";
    std::ifstream file(filePath, std::ios_base::in);
    bool ret = avservice_->CheckStringAndCleanFile(filePath);
    file.close();
    // file not exist for ifstream file can not create file in non-existent folder
    EXPECT_EQ(ret, false);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("CheckStringAndCleanFile002 end!");
}

static HWTEST_F(AVSessionServiceTest, ReportStartCastEnd001, TestSize.Level0)
{
    SLOGI("NotifyDeviceAvailable001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    std::string func = "";
    int32_t uid = avsessionHere_->GetUid();
    int ret = 1;
    OutputDeviceInfo outputDeviceInfo;
    OHOS::AVSession::DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "deviceId";
    avservice_->ReportStartCastEnd(func, outputDeviceInfo, uid, ret);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("NotifyDeviceAvailable001 end!");
}

#ifdef BLUETOOTH_ENABLE
static HWTEST_F(AVSessionServiceTest, OnReceiveEvent003, TestSize.Level0)
{
    SLOGD("OnReceiveEvent003 begin!");
    OHOS::EventFwk::CommonEventData eventData;
    string action = OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED;
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, avservice_);
    eventSubscriber.OnReceiveEvent(eventData);
    int32_t ret = action.compare(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    EXPECT_EQ(ret, 0);
    SLOGD("OnReceiveEvent003 end!");
}

static HWTEST_F(AVSessionServiceTest, UpdateFrontSession004, TestSize.Level0)
{
    SLOGD("UpdateFrontSession004 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    EXPECT_EQ(avsessionHere != nullptr, true);
    avservice_->UpdateTopSession(avsessionHere);
    avservice_->UpdateFrontSession(avsessionHere, false);
    avservice_->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    SLOGD("UpdateFrontSession004 end!");
}

static HWTEST_F(AVSessionServiceTest, CheckAncoAudio001, TestSize.Level0)
{
    SLOGD("CheckAncoAudio001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    bool ret = avservice_->CheckAncoAudio();
    EXPECT_EQ(ret, false);
    avsessionHere->Destroy();
    SLOGD("CheckAncoAudio001 end!");
}

static HWTEST_F(AVSessionServiceTest, SendSystemControlCommand002, TestSize.Level0)
{
    SLOGD("SendSystemControlCommand002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avservice_->UpdateTopSession(avsessionHere);
    AVControlCommand command;
    command.SetCommand(1000);
    int32_t ret = avservice_->SendSystemControlCommand(command);
    avservice_->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGD("SendSystemControlCommand002 end!");
}

/**
* @tc.name: SendSystemControlCommand003
* @tc.desc: Verifying the SendSystemControlCommand method with valid parameters.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTest, SendSystemControlCommand003, TestSize.Level0)
{
    SLOGI("SendSystemControlCommand003 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    std::vector<int> tempAudioPlayingUids {1, 2};
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(avsessionHere != nullptr);
    tempAudioPlayingUids.push_back(avsessionHere->GetUid());
    avservice_->focusSessionStrategy_.SetAudioPlayingUids(tempAudioPlayingUids);

    AVControlCommand command;
    command.SetCommand(1000);
    int32_t ret = avservice_->SendSystemControlCommand(command);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    avservice_->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    SLOGI("SendSystemControlCommand003 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateWantAgent001, TestSize.Level0)
{
    SLOGD("CreateWantAgent001 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor(nullptr);
    auto ret = avservice_->CreateWantAgent(histroyDescriptor.get());
    EXPECT_EQ(ret, nullptr);
    SLOGD("CreateWantAgent001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateWantAgent002, TestSize.Level0)
{
    SLOGD("CreateWantAgent001 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto ret = avservice_->CreateWantAgent(histroyDescriptor.get());
    EXPECT_EQ(ret, nullptr);
    SLOGD("CreateWantAgent001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateWantAgent003, TestSize.Level0)
{
    SLOGD("CreateWantAgent003 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avservice_->UpdateTopSession(avsessionHere);
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor(nullptr);
    auto ret = avservice_->CreateWantAgent(histroyDescriptor.get());
    avsessionHere->Destroy();
    EXPECT_EQ(ret, nullptr);
    SLOGD("CreateWantAgent003 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateWantAgent004, TestSize.Level0)
{
    SLOGD("CreateWantAgent004 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avservice_->UpdateTopSession(avsessionHere);
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto ret = avservice_->CreateWantAgent(histroyDescriptor.get());
    avsessionHere->Destroy();
    EXPECT_EQ(ret, nullptr);
    SLOGD("CreateWantAgent004 end!");
}
#endif

static HWTEST_F(AVSessionServiceTest, CreateWantAgent005, TestSize.Level1)
{
    SLOGD("CreateWantAgent005 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_NE(avsessionHere, nullptr);
    avsessionHere->SetUid(5557);
    avservice_->UpdateTopSession(avsessionHere);
    EXPECT_NE(avservice_->topSession_, nullptr);
    auto wantAgent = avservice_->CreateWantAgent(nullptr);
    EXPECT_EQ(wantAgent, nullptr);
    avsessionHere->Destroy();
    SLOGD("CreateWantAgent005 end!");
}

/**
 * @tc.name: UpdateOrder001
 * @tc.desc: Verifying the UpdateOrder.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, UpdateOrder001, TestSize.Level1)
{
    SLOGI("UpdateOrder001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    bool ret = avservice_->UpdateOrder(avsessionHere_);
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("UpdateOrder001 end!");
}
 
/**
 * @tc.name: UpdateOrder002
 * @tc.desc: Verifying the UpdateOrder.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, UpdateOrder002, TestSize.Level1)
{
    SLOGI("UpdateOrder002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avservice_->UpdateFrontSession(avsessionHere_, true);
    bool ret = avservice_->UpdateOrder(avsessionHere_);
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("UpdateOrder002 end!");
}
 
/**
 * @tc.name: HandleOtherSessionPlaying001
 * @tc.desc: Verifying the HandleOtherSessionPlaying.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleOtherSessionPlaying001, TestSize.Level1)
{
    SLOGI("HandleOtherSessionPlaying001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avservice_->HandleOtherSessionPlaying(avsessionHere_);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleOtherSessionPlaying001 end!");
}
 
/**
 * @tc.name: HandleOtherSessionPlaying002
 * @tc.desc: Verifying the HandleOtherSessionPlaying.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleOtherSessionPlaying002, TestSize.Level1)
{
    SLOGI("HandleOtherSessionPlaying002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    int32_t ancoUid = 1041;
    avsessionHere_->SetUid(ancoUid);
    avservice_->HandleOtherSessionPlaying(avsessionHere_);
    bool check = avsessionHere_->GetUid() == ancoUid;
    EXPECT_EQ(check, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleOtherSessionPlaying002 end!");
}
 
/**
 * @tc.name: HandleOtherSessionPlaying003
 * @tc.desc: Verifying the HandleOtherSessionPlaying.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleOtherSessionPlaying003, TestSize.Level1)
{
    SLOGI("HandleOtherSessionPlaying003 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    avservice_->HandleOtherSessionPlaying(avsessionHere_);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleOtherSessionPlaying003 end!");
}
 
/**
 * @tc.name: GetOtherPlayingSession001
 * @tc.desc: Verifying the GetOtherPlayingSession.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, GetOtherPlayingSession001, TestSize.Level1)
{
    SLOGI("GetOtherPlayingSession001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    std::string bundleName = "test";
    int32_t userId = 0;
    bool ret = avservice_->GetOtherPlayingSession(userId, bundleName) == nullptr;
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("GetOtherPlayingSession001 end!");
}

/**
 * @tc.name: GetOtherPlayingSession002
 * @tc.desc: Verifying the GetOtherPlayingSession.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, GetOtherPlayingSession002, TestSize.Level1)
{
    SLOGI("GetOtherPlayingSession002 begin!");
    int32_t userId = 0;
    static char gTestFrontBundleName[] = "testFront.ohos.avsession";
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionFront_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avservice_->UpdateFrontSession(avsessionFront_, true);
    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    avsessionFront_->SetAVPlaybackState(g_playbackState);
    bool ret = avservice_->GetOtherPlayingSession(userId, gTestFrontBundleName) == nullptr;
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionFront_->GetSessionId());
    avsessionFront_->Destroy();
    SLOGI("GetOtherPlayingSession002 end!");
}
 
/**
 * @tc.name: GetOtherPlayingSession003
 * @tc.desc: Verifying the GetOtherPlayingSession.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, GetOtherPlayingSession003, TestSize.Level1)
{
    SLOGI("GetOtherPlayingSession003 begin!");
    int32_t userId = 0;
    static char gTestFrontBundleName[] = "testFront.ohos.avsession";
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionFront_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avservice_->UpdateFrontSession(avsessionFront_, true);
    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    avsessionFront_->SetAVPlaybackState(g_playbackState);
    avsessionFront_->castHandle_ = 1;
    bool ret = avservice_->GetOtherPlayingSession(userId, gTestFrontBundleName) == nullptr;
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionFront_->GetSessionId());
    avsessionFront_->Destroy();
    SLOGI("GetOtherPlayingSession003 end!");
}

/**
 * @tc.name: OnIdleWithSessions001
 * @tc.desc: Verifying the OnIdle method with a valid idle reason.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, OnIdleWithSessions001, TestSize.Level0)
{
    SLOGD("OnIdleWithSessions001 begin!");
    const OHOS::SystemAbilityOnDemandReason idleReason(
        OHOS::OnDemandReasonId::INTERFACE_CALL, "INTERFACE_CALL", "TestValue", 12345);
    int32_t result = avservice_->OnIdle(idleReason);
    EXPECT_EQ(result, 0);
    SLOGD("OnIdleWithSessions001 end!");
}

/**
 * @tc.name: CheckAndUpdateAncoMediaSession001
 * @tc.desc: update anco media session without anco uid.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CheckAndUpdateAncoMediaSession001, TestSize.Level1)
{
    SLOGD("CheckAndUpdateAncoMediaSession001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    OHOS::AppExecFwk::ElementName newElementName;
    newElementName.SetBundleName("bundleName");
    newElementName.SetAbilityName("AbilityName");
    avservice_->CheckAndUpdateAncoMediaSession(newElementName);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGD("CheckAndUpdateAncoMediaSession001 end!");
}

/**
 * @tc.name: CheckSessionHandleKeyEvent001
 * @tc.desc: check which session handle key event.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CheckSessionHandleKeyEvent001, TestSize.Level1)
{
    SLOGD("CheckSessionHandleKeyEvent001 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_NE(avsessionHere_, nullptr);
    AVControlCommand cmd;
    cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto ret = avservice_->CheckSessionHandleKeyEvent(true, cmd, *keyEvent, avsessionHere_);
    EXPECT_EQ(ret, true);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_MEDIA_PLAY);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    ret = avservice_->CheckSessionHandleKeyEvent(false, cmd, *keyEvent, avsessionHere_);
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGD("CheckSessionHandleKeyEvent001 end!");
}

/**
 * @tc.name: CheckSessionHandleKeyEvent002
 * @tc.desc: check which session handle key event.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CheckSessionHandleKeyEvent002, TestSize.Level1)
{
    SLOGD("CheckSessionHandleKeyEvent002 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_NE(avsessionHere_, nullptr);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 1041;
    info.pid = 1041;
    avservice_->HandleFocusSession(info, true);
    AVControlCommand cmd;
    cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto ret = avservice_->CheckSessionHandleKeyEvent(true, cmd, *keyEvent, avsessionHere_);
    EXPECT_EQ(ret, true);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_MEDIA_PLAY);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    ret = avservice_->CheckSessionHandleKeyEvent(false, cmd, *keyEvent, avsessionHere_);
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGD("CheckSessionHandleKeyEvent002 end!");
}

/**
 * @tc.name: UpdateSessionTimestamp001
 * @tc.desc: update timestamp for session item.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, UpdateSessionTimestamp001, TestSize.Level1)
{
    SLOGD("UpdateSessionTimestamp001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->UpdateSessionTimestamp(avsessionHere_);
    EXPECT_NE(avsessionHere_->GetPlayingTime(), 0);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGD("UpdateSessionTimestamp001 end!");
}

/**
 * @tc.name: GetLocalTitle001
 * @tc.desc: get local title.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, GetLocalTitle001, TestSize.Level1)
{
    SLOGD("GetLocalTitle001 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_NE(avsessionHere_, nullptr);
    avservice_->UpdateTopSession(avsessionHere_);
    EXPECT_NE(avservice_->topSession_, nullptr);
    AVMetaData metadata;
    metadata.SetAssetId("mediaId");
    metadata.SetDescription("title;artist");
    avsessionHere_->SetAVMetaData(g_metaData);
    std::string songName = avservice_->GetLocalTitle();
    EXPECT_EQ(songName, "title");
    avsessionHere_->Destroy();
    SLOGD("GetLocalTitle001 end!");
}

/**
 * @tc.name: GetLocalTitle002
 * @tc.desc: get local title.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, GetLocalTitle002, TestSize.Level1)
{
    SLOGD("GetLocalTitle002 begin!");
    ASSERT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_NE(avsessionHere_, nullptr);
    avsessionHere_->SetUid(5557);
    avservice_->UpdateTopSession(avsessionHere_);
    EXPECT_NE(avservice_->topSession_, nullptr);
    AVMetaData metadata;
    metadata.SetAssetId("mediaId");
    metadata.SetTitle("title");
    metadata.SetDescription("title-artist");
    avsessionHere_->SetAVMetaData(g_metaData);
    std::string songName = avservice_->GetLocalTitle();
    EXPECT_EQ(songName, "title");
    avsessionHere_->Destroy();
    SLOGD("GetLocalTitle002 end!");
}

static HWTEST_F(AVSessionServiceTest, GetSessionDescriptors001, TestSize.Level0)
{
    SLOGI("GetSessionDescriptors001 begin!");
    std::vector<AVSessionDescriptor> descriptors;
    int ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_ACTIVE, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(descriptors.size(), 0);

    ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_NOT_ACTIVE, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(descriptors.size(), 0);

    ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_ALL, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(descriptors.size(), 0);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
         avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_NE(avsessionHere_, nullptr);
    avsessionHere_->Activate();

    ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_ACTIVE, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_NOT_ACTIVE, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_ALL, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    avsessionHere_->Destroy();
    SLOGI("GetSessionDescriptors001 end!");
}

static HWTEST_F(AVSessionServiceTest, GetSessionDescriptors002, TestSize.Level0)
{
    SLOGI("GetSessionDescriptors002 begin!");
    std::vector<AVSessionDescriptor> descriptors;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
         avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_NE(avsessionHere_, nullptr);

    int ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_ACTIVE, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_NOT_ACTIVE, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    ret = avservice_->GetSessionDescriptors(SessionCategory::CATEGORY_ALL, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    avsessionHere_->Destroy();
    SLOGI("GetSessionDescriptors002 end!");
}

/**
 * @tc.name: HandleRemoveMediaCardEvent001
 * @tc.desc: Verifying the HandleRemoveMediaCardEvent method with a valid session.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleRemoveMediaCardEvent001, TestSize.Level0)
{
    SLOGD("HandleRemoveMediaCardEvent001 begin!");
    const int32_t uid = 5557;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
         avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_NE(avsessionHere_, nullptr);
    avservice_->UpdateTopSession(avsessionHere_);
    EXPECT_NE(avservice_->topSession_, nullptr);
    avsessionHere_->SetUid(uid);
    AVPlaybackState playbackState;
    playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    avservice_->HandleRemoveMediaCardEvent();
    playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PAUSE);
    avservice_->HandleRemoveMediaCardEvent();
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(avservice_->topSession_, nullptr);
    SLOGD("HandleRemoveMediaCardEvent001 end!");
}

/**
 * @tc.name: HandleRemoveMediaCardEvent002
 * @tc.desc: Verifying the HandleRemoveMediaCardEvent method with a valid session.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleRemoveMediaCardEvent002, TestSize.Level0)
{
    SLOGD("HandleRemoveMediaCardEvent002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    avservice_->topSession_ =
         avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    bool ret = avservice_->topSession_->IsCasting();
    avservice_->HandleRemoveMediaCardEvent();
    EXPECT_EQ(ret, false);
    SLOGD("HandleRemoveMediaCardEvent002 end!");
}

/**
 * @tc.name: HandleRemoveMediaCardEvent003
 * @tc.desc: Verifying the HandleRemoveMediaCardEvent method with a null session.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleRemoveMediaCardEvent003, TestSize.Level0)
{
    SLOGD("HandleRemoveMediaCardEvent003 begin!");
    avservice_->topSession_ = nullptr;
    avservice_->HandleRemoveMediaCardEvent();
    EXPECT_EQ(avservice_->topSession_, nullptr);
    SLOGD("HandleRemoveMediaCardEvent003 end!");
}

/**
 * @tc.name: IsTopSessionPlaying001
 * @tc.desc: Verifying the IsTopSessionPlaying method with a null top session.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, IsTopSessionPlaying001, TestSize.Level0)
{
    SLOGD("IsTopSessionPlaying001 begin!");
    avservice_->topSession_ = nullptr;
    bool ret = avservice_->IsTopSessionPlaying();
    EXPECT_EQ(ret, false);
    SLOGD("IsTopSessionPlaying001 end!");
}

/**
 * @tc.name: IsTopSessionPlaying002
 * @tc.desc: Verifying the IsTopSessionPlaying method with a valid top session.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, IsTopSessionPlaying002, TestSize.Level0)
{
    SLOGD("IsTopSessionPlaying002 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    avservice_->topSession_ = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);
    EXPECT_NE(avservice_->topSession_, nullptr);
    bool ret = avservice_->IsTopSessionPlaying();
    EXPECT_EQ(ret, false);
    SLOGD("IsTopSessionPlaying002 end!");
}

/**
 * @tc.name: HandleMediaCardStateChangeEvent001
 * @tc.desc: Verifying the HandleMediaCardStateChangeEvent method with "APPEAR" state.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleMediaCardStateChangeEvent001, TestSize.Level0)
{
    SLOGD("HandleMediaCardStateChangeEvent001 begin!");
    std::string isAppear = "APPEAR";
    avservice_->HandleMediaCardStateChangeEvent(isAppear);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("HandleMediaCardStateChangeEvent001 end!");
}

/**
 * @tc.name: HandleMediaCardStateChangeEvent002
 * @tc.desc: Verifying the HandleMediaCardStateChangeEvent method with "DISAPPEAR" state.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleMediaCardStateChangeEvent002, TestSize.Level0)
{
    SLOGD("HandleMediaCardStateChangeEvent002 begin!");
    std::string isAppear = "DISAPPEAR";
    avservice_->HandleMediaCardStateChangeEvent(isAppear);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("HandleMediaCardStateChangeEvent002 end!");
}

/**
 * @tc.name: HandleMediaCardStateChangeEvent003
 * @tc.desc: Verifying the HandleMediaCardStateChangeEvent method with an invalid state.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, HandleMediaCardStateChangeEvent003, TestSize.Level0)
{
    SLOGD("HandleMediaCardStateChangeEvent003 begin!");
    std::string isAppear = "ISDISAPPEAR";
    avservice_->HandleMediaCardStateChangeEvent(isAppear);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("HandleMediaCardStateChangeEvent003 end!");
}

/**
 * @tc.name: OnAddSystemAbility001
 * @tc.desc: Verifying the OnAddSystemAbility method with valid system ability ID and device ID.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, OnAddSystemAbility001, TestSize.Level0)
{
    SLOGD("OnAddSystemAbility001 begin!");
    int32_t systemAbilityId = OHOS::XPOWER_MANAGER_SYSTEM_ABILITY_ID;
    const std::string deviceId = "AUDIO";
    avservice_->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("OnAddSystemAbility001 end!");
}

/**
 * @tc.name: UpdateTopSession001
 * @tc.desc: Verifying the UpdateTopSession method with a valid new top session.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, UpdateTopSession001, TestSize.Level0)
{
    SLOGD("UpdateTopSession001 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    const OHOS::sptr<AVSessionItem> newTopSession = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);
    avservice_->UpdateTopSession(newTopSession);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("UpdateTopSession001 end!");
}

/**
 * @tc.name: LowQualityCheck001
 * @tc.desc: Verifying the LowQualityCheck method with valid parameters.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, LowQualityCheck001, TestSize.Level0)
{
    SLOGD("LowQualityCheck001 begin!");
    int32_t uid = g_playOnCall;
    int32_t pid = g_pauseOnCall;
    StreamUsage streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
    RendererState rendererState = RendererState::RENDERER_PAUSED;
    avservice_->LowQualityCheck(uid, pid, streamUsage, rendererState);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("LowQualityCheck001 end!");
}

/**
 * @tc.name: PlayStateCheck001
 * @tc.desc: Verifying the PlayStateCheck method with valid parameters.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, PlayStateCheck001, TestSize.Level0)
{
    SLOGD("PlayStateCheck001 begin!");
    int32_t uid = AVSESSION_ERROR_BASE;
    StreamUsage streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
    RendererState rendererState = RendererState::RENDERER_PAUSED;
    avservice_->PlayStateCheck(uid, streamUsage, rendererState);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("PlayStateCheck001 end!");
}

/**
 * @tc.name: NotifyBackgroundReportCheck001
 * @tc.desc: Verifying NotifyBackgroundReportCheck with RENDERER_RUNNING state.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, NotifyBackgroundReportCheck001, TestSize.Level0)
{
    SLOGD("NotifyBackgroundReportCheck001 begin!");
    int32_t uid = g_playOnCall;
    int32_t pid = g_pauseOnCall;
    StreamUsage streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
    RendererState rendererState = RendererState::RENDERER_RUNNING;
    avservice_->NotifyBackgroundReportCheck(uid, pid, streamUsage, rendererState);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("NotifyBackgroundReportCheck001 end!");
}

/**
 * @tc.name: NotifyBackgroundReportCheck002
 * @tc.desc: Verifying NotifyBackgroundReportCheck with RENDERER_PAUSED state.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, NotifyBackgroundReportCheck002, TestSize.Level0)
{
    SLOGD("NotifyBackgroundReportCheck002 begin!");
    int32_t uid = g_playOnCall;
    int32_t pid = g_pauseOnCall;
    StreamUsage streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
    RendererState rendererState = RendererState::RENDERER_PAUSED;
    avservice_->NotifyBackgroundReportCheck(uid, pid, streamUsage, rendererState);
    EXPECT_NE(avservice_->topSession_, nullptr);
    SLOGD("NotifyBackgroundReportCheck002 end!");
}

/**
 * @tc.name: ServiceCallback001
 * @tc.desc: Verifying ServiceCallback with a null session item.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, ServiceCallback001, TestSize.Level0)
{
    SLOGD("ServiceCallback001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    auto sessionItem =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(sessionItem, nullptr);
    avservice_->ServiceCallback(sessionItem);
    SLOGD("ServiceCallback001 end!");
}

/**
 * @tc.name: IsParamInvalid001
 * @tc.desc: Verifying IsParamInvalid with an empty tag.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, IsParamInvalid001, TestSize.Level0)
{
    SLOGD("IsParamInvalid001 begin!");
    std::string tag = "";
    int32_t type = AVSession::SESSION_TYPE_AUDIO;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    bool result = avservice_->IsParamInvalid(tag, type, elementName);
    EXPECT_FALSE(result);
    SLOGD("IsParamInvalid001 end!");
}

/**
 * @tc.name: IsParamInvalid002
 * @tc.desc: Verifying IsParamInvalid with an invalid session type.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, IsParamInvalid002, TestSize.Level0)
{
    SLOGD("IsParamInvalid002 begin!");
    std::string tag = "testTag";
    int32_t type = AVSession::SESSION_TYPE_INVALID;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("com.example.bundle");
    elementName.SetAbilityName("com.example.ability");
    bool result = avservice_->IsParamInvalid(tag, type, elementName);
    EXPECT_FALSE(result);
    SLOGD("IsParamInvalid002 end!");
}

/**
 * @tc.name: IsParamInvalid003
 * @tc.desc: Verifying IsParamInvalid with an empty bundle name.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, IsParamInvalid003, TestSize.Level0)
{
    SLOGD("IsParamInvalid003 begin!");
    std::string tag = "testTag";
    int32_t type = AVSession::SESSION_TYPE_AUDIO;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("");
    elementName.SetAbilityName(g_testAnotherAbilityName);
    bool result = avservice_->IsParamInvalid(tag, type, elementName);
    EXPECT_FALSE(result);
    SLOGD("IsParamInvalid003 end!");
}

/**
 * @tc.name: IsParamInvalid004
 * @tc.desc: Verifying IsParamInvalid with an empty ability name.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, IsParamInvalid004, TestSize.Level0)
{
    SLOGD("IsParamInvalid004 begin!");
    std::string tag = "testTag";
    int32_t type = AVSession::SESSION_TYPE_AUDIO;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName("");
    bool result = avservice_->IsParamInvalid(tag, type, elementName);
    EXPECT_FALSE(result);
    SLOGD("IsParamInvalid004 end!");
}

/**
 * @tc.name: IsLocalDevice001
 * @tc.desc: Verifying IsLocalDevice with a valid local network ID.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, IsLocalDevice001, TestSize.Level0)
{
    SLOGD("IsLocalDevice001 begin!");
    const std::string networkId = "LocalDevice";
    bool result = avservice_->IsLocalDevice(networkId);
    EXPECT_TRUE(result);
    SLOGD("IsLocalDevice001 end!");
}

/**
 * @tc.name: GetDeviceInfo002
 * @tc.desc: Verifying GetDeviceInfo with a valid session item and descriptors.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, GetDeviceInfo002, TestSize.Level0)
{
    SLOGI("GetDeviceInfo002 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto avsessionHere = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    avservice_->SetDeviceInfo(descriptors, avsessionHere);
    avservice_->GetDeviceInfo(avsessionHere, descriptors, descriptors, descriptors);
    EXPECT_NE(avsessionHere, nullptr);
    SLOGI("GetDeviceInfo002 end!");
}

/**
 * @tc.name: CastAudioProcess001
 * @tc.desc: Verifying CastAudioProcess with a valid session item and descriptors.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CastAudioProcess001, TestSize.Level0)
{
    SLOGI("CastAudioProcess001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors;
    avservice_->GetDeviceInfo(avsessionHere, descriptors, descriptors, descriptors);
    const std::string  sourceSessionInfo = "123443";
    auto ret = avservice_->CastAudioProcess(descriptors, sourceSessionInfo, avsessionHere);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("CastAudioProcess001 end!");
}

/**
 * @tc.name: CastAudioProcess002
 * @tc.desc: Verifying CastAudioProcess with a valid session item and descriptors.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CastAudioProcess002, TestSize.Level0)
{
    SLOGI("CastAudioProcess002 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto avsessionHere = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    avservice_->SetDeviceInfo(descriptors, avsessionHere);
    avservice_->GetDeviceInfo(avsessionHere, descriptors, descriptors, descriptors);
    EXPECT_NE(avsessionHere, nullptr);
    const std::string  sourceSessionInfo = "123443";
    auto ret = avservice_->CastAudioProcess(descriptors, sourceSessionInfo, avsessionHere);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("CastAudioProcess002 end!");
}

/**
 * @tc.name: CastAudioInner001
 * @tc.desc: Verifying CastAudioInner with a valid session item and descriptors.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CastAudioInner001, TestSize.Level0)
{
    SLOGI("CastAudioInner001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto avsessionHere = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    const std::string  sourceSessionInfo = "123443";
    auto ret = avservice_->CastAudioInner(descriptors, sourceSessionInfo, avsessionHere);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("CastAudioInner001 end!");
}

/**
 * @tc.name: CancelCastAudioInner001
 * @tc.desc: Verifying CancelCastAudioInner with a valid session item and descriptors.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CancelCastAudioInner001, TestSize.Level0)
{
    SLOGI("CancelCastAudioInner001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
    avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    const std::string  sourceSessionInfo = "123443";
    auto ret = avservice_->CancelCastAudioInner(descriptors, sourceSessionInfo, avsessionHere);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("CancelCastAudioInner001 end!");
}

/**
 * @tc.name: CastAudioForAll001
 * @tc.desc: Verifying CastAudioForAll with valid descriptors.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CastAudioForAll001, TestSize.Level0)
{
    SLOGI("CastAudioForAll001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    auto ret = avservice_->CastAudioForAll(descriptors);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("CastAudioForAll001 end!");
}

/**
 * @tc.name: ClearControllerForClientDiedNoLock002
 * @tc.desc: Verifying ClearControllerForClientDiedNoLock with a valid PID.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, ClearControllerForClientDiedNoLock002, TestSize.Level0)
{
    SLOGI("ClearControllerForClientDiedNoLock002 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    pid_t pid = 1234;
    avservice_->ClearControllerForClientDiedNoLock(pid);
    EXPECT_TRUE(avservice_ != nullptr);
    SLOGI("ClearControllerForClientDiedNoLock002 end!");
}

/**
 * @tc.name: CheckAndCreateDir001
 * @tc.desc: Verifying CheckAndCreateDir with a valid file path.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, CheckAndCreateDir001, TestSize.Level0)
{
    SLOGI("CheckAndCreateDir001 begin!");
    EXPECT_TRUE(avservice_ != nullptr);
    const string filePath = "/data/path";
    bool ret = avservice_->CheckAndCreateDir(filePath);
    EXPECT_TRUE(ret);
    SLOGI("CheckAndCreateDir001 end!");
}

/**
 * @tc.name: SaveStringToFileEx001
 * @tc.desc: Verifying SaveStringToFileEx with a valid file path and content.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, SaveStringToFileEx001, TestSize.Level0)
{
    SLOGI("SaveStringToFileEx001 begin!");
    std::string filePath =  "uripath";
    std::string content = "123456";
    bool ret = avservice_->SaveStringToFileEx(filePath, content);
    EXPECT_EQ(ret, true);
    SLOGI("SaveStringToFileEx001 end!");
}

/**
 * @tc.name: SaveStringToFileEx002
 * @tc.desc: Verifying SaveStringToFileEx with an empty content.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, SaveStringToFileEx002, TestSize.Level0)
{
    SLOGI("SaveStringToFileEx002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string filePath = avservice_->GetAVSortDir();
    std::string content = "";
    bool ret = avservice_->SaveStringToFileEx(filePath, content);
    EXPECT_EQ(ret, false);
    SLOGI("SaveStringToFileEx002 end!");
}

/**
 * @tc.name: RemoveExpired001
 * @tc.desc: Verifying RemoveExpired with an expired time point.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, RemoveExpired001, TestSize.Level0)
{
    SLOGD("RemoveExpired001 begin!");
    std::list<std::chrono::system_clock::time_point> timeList;
    auto now = std::chrono::system_clock::now();
    int32_t timeThreshold = 5;
    timeList.push_back(now - std::chrono::seconds(10));
    avservice_->RemoveExpired(timeList, now, timeThreshold);

    EXPECT_TRUE(timeList.empty());
    SLOGD("RemoveExpired001 end!");
}

/**
 * @tc.name: RemoveExpired002
 * @tc.desc: Verifying RemoveExpired with a non-expired time point.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, RemoveExpired002, TestSize.Level0)
{
    SLOGD("RemoveExpired002 begin!");
    std::list<std::chrono::system_clock::time_point> timeList;
    auto now = std::chrono::system_clock::now();
    int32_t timeThreshold = 5;
    timeList.push_back(now - std::chrono::seconds(3));

    avservice_->RemoveExpired(timeList, now, timeThreshold);
    EXPECT_EQ(timeList.size(), 1);
    SLOGD("RemoveExpired002 end!");
}

/**
 * @tc.name: RemoveExpired003
 * @tc.desc: Verifying RemoveExpired with an empty time list.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, RemoveExpired003, TestSize.Level0)
{
    SLOGD("RemoveExpired003 begin!");
    std::list<std::chrono::system_clock::time_point> timeList;
    auto now = std::chrono::system_clock::now();
    int32_t timeThreshold = 5;
    avservice_->RemoveExpired(timeList, now, timeThreshold);
    EXPECT_TRUE(timeList.empty());
    SLOGD("RemoveExpired003 end!");
}

/**
 * @tc.name: NotifyFlowControl001
 * @tc.desc: Verifying NotifyFlowControl with a full flow control list.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, NotifyFlowControl001, TestSize.Level0)
{
    SLOGD("NotifyFlowControl001 begin!");
    avservice_->flowControlPublishTimestampList_.clear();
    const size_t count = 3;
    for (size_t i = 0; i < count; ++i) {
        avservice_->flowControlPublishTimestampList_.push_back(std::chrono::system_clock::now());
    }
    bool result = avservice_->NotifyFlowControl();
    EXPECT_TRUE(result);
    EXPECT_EQ(avservice_->flowControlPublishTimestampList_.size(), count);
    SLOGD("NotifyFlowControl001 end!");
}

/**
 * @tc.name: NotifyFlowControl002
 * @tc.desc: Verifying NotifyFlowControl with a non-full flow control list.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, NotifyFlowControl002, TestSize.Level0)
{
    SLOGD("NotifyFlowControl002 begin!");
    const size_t count = 3;
    avservice_->flowControlPublishTimestampList_.clear();
    for (size_t i = 0; i < count - 1; ++i) {
        avservice_->flowControlPublishTimestampList_.push_back(std::chrono::system_clock::now());
    }
    bool result = avservice_->NotifyFlowControl();
    EXPECT_FALSE(result);
    SLOGD("NotifyFlowControl002 end!");
}

/**
 * @tc.name: NotifyRemoteDistributedSessionControllersChanged001
 * @tc.desc: Verifying NotifyRemoteDistributedSessionControllersChanged with a valid session controller.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, NotifyRemoteDistributedSessionControllersChanged001, TestSize.Level0)
{
    SLOGD("NotifyRemoteDistributedSessionControllersChanged001 begin!");
    std::vector<OHOS::sptr<IRemoteObject>> sessionControllers;
    avservice_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
    OHOS::sptr<OHOS::ISystemAbilityManager> mgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(mgr != nullptr);
    OHOS::sptr<IRemoteObject> obj = mgr->GetSystemAbility(OHOS::AVSESSION_SERVICE_ID);
    sessionControllers.push_back(obj);
    avservice_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
    EXPECT_TRUE(avservice_ != nullptr);
    SLOGD("NotifyRemoteDistributedSessionControllersChanged001 end!");
}

/**
 * @tc.name: SuperLauncher001
 * @tc.desc: Verifying SuperLauncher with init state
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, SuperLauncher001, TestSize.Level0)
{
    SLOGD("SuperLauncher001 begin!");
    avservice_->SuperLauncher("adcdef", "SuperLauncher-Dual", "", "CONNECT_SUCC");
    EXPECT_EQ(avservice_->migrateAVSession_->supportCrossMediaPlay_, false);
    SLOGD("SuperLauncher001 end!");
}
 
/**
 * @tc.name: ReleaseSuperLauncher001
 * @tc.desc: Verifying ReleaseSuperLauncher with SupportCrossMediaPlay state
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, ReleaseSuperLauncher001, TestSize.Level0)
{
    SLOGD("ReleaseSuperLauncher001 begin!");
    avservice_->ReleaseSuperLauncher("SuperLauncher-Dual");
    EXPECT_EQ(avservice_->migrateAVSession_->supportCrossMediaPlay_, false);
    SLOGD("ReleaseSuperLauncher001 end!");
}
 
/**
 * @tc.name: ConnectSuperLauncher001
 * @tc.desc: Verifying ConnectSuperLauncher001 with init state
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, ConnectSuperLauncher001, TestSize.Level0)
{
    SLOGD("ConnectSuperLauncher001 begin!");
    avservice_->ConnectSuperLauncher("adcdef", "SuperLauncher-Dual");
    EXPECT_NE(avservice_->migrateAVSession_->servicePtr_, nullptr);
    SLOGD("ConnectSuperLauncher001 end!");
}
 
/**
 * @tc.name: SucceedSuperLauncher001
 * @tc.desc: Verifying SucceedSuperLauncher001 with init state
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTest, SucceedSuperLauncher001, TestSize.Level0)
{
    SLOGD("SucceedSuperLauncher001 begin!");
    avservice_->SucceedSuperLauncher("adcdef", "SuperLauncher-Dual");
    EXPECT_EQ(avservice_->migrateAVSession_->supportCrossMediaPlay_, false);
    SLOGD("SucceedSuperLauncher001 end!");
}

static HWTEST_F(AVSessionServiceTest, IsCapsuleNeeded001, TestSize.Level0)
{
    SLOGD("IsCapsuleNeeded001 begin!");
    avservice_->topSession_ = nullptr;
    bool result = avservice_->IsCapsuleNeeded();
    EXPECT_EQ(result, false);
    SLOGD("IsCapsuleNeeded001 end!");
}

static HWTEST_F(AVSessionServiceTest, SetForwardTime001, TestSize.Level0)
{
    SLOGD("SetForwardTime001 begin!");
    int64_t test = -1;
    int32_t ret = avcommand_->SetForwardTime(test);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGD("SetForwardTime001 end!");
}

static HWTEST_F(AVSessionServiceTest, SetRewindTime001, TestSize.Level0)
{
    SLOGD("SetRewindTime001 begin!");
    int64_t test = -1;
    int32_t ret = avcommand_->SetRewindTime(test);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGD("SetRewindTime001 end!");
}

static HWTEST_F(AVSessionServiceTest, SetSeekTime001, TestSize.Level0)
{
    SLOGD("SetSeekTime001 begin!");
    int64_t test = -1;
    int32_t ret = avcommand_->SetSeekTime(test);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGD("SetSeekTime001 end!");
}

static HWTEST_F(AVSessionServiceTest, SetPlayWithAssetId001, TestSize.Level0)
{
    SLOGD("SetPlayWithAssetId001 begin!");
    std::string test = "";
    auto avcommand_ = std::make_shared<AVControlCommand>();
    int32_t ret = avcommand_->SetPlayWithAssetId(test);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGD("SetPlayWithAssetId001 end!");
}

static HWTEST_F(AVSessionServiceTest, PlayParam001, TestSize.Level0)
{
    SLOGD("PlayParam001 begin!");
    std::string paramIn = "test";
    AVControlCommand cmd;
    int32_t ret = cmd.SetPlayParam(paramIn);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    std::string paramOut;
    ret = cmd.GetPlayParam(paramOut);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(paramIn, paramOut);
    SLOGD("PlayParam001 end!");
}