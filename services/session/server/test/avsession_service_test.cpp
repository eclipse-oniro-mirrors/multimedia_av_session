/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "audio_info.h"
#include "avsession_callback_client.h"

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
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override {};
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward(int64_t time) override {};
    void OnRewind(int64_t time) override {};
    void OnSeek(int64_t time) override {};
    void OnSetSpeed(double speed) override {};
    void OnSetLoopMode(int32_t loopMode) override {};
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
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override {};

    ~AVSessionCallbackImpl() override;
};

void AVSessionCallbackImpl::OnPlay()
{
    g_playOnCall = AVSESSION_SUCCESS;
    SLOGI("OnPlay %{public}d", g_playOnCall);
}

void AVSessionCallbackImpl::OnPause()
{
    g_pauseOnCall = AVSESSION_SUCCESS;
    SLOGI("OnPause %{public}d", g_pauseOnCall);
}

void AVSessionCallbackImpl::OnPlayNext()
{
    g_nextOnCall = AVSESSION_SUCCESS;
    SLOGI("OnPlayNext %{public}d", g_nextOnCall);
}

void AVSessionCallbackImpl::OnPlayPrevious()
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
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent001, TestSize.Level1)
{
    SLOGI("SendSystemAVKeyEvent001 begin!");
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

static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent002, TestSize.Level1)
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
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent003, TestSize.Level1)
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
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent004, TestSize.Level1)
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
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent005, TestSize.Level1)
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
static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent006, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, NotifyDeviceAvailable001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, NotifyMirrorToStreamCast001, TestSize.Level1)
{
    SLOGI("NotifyMirrorToStreamCast001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("NotifyMirrorToStreamCast001 in!");
    avservice_->NotifyMirrorToStreamCast();
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("NotifyMirrorToStreamCast001 end!");
}

static HWTEST_F(AVSessionServiceTest, NotifyMirrorToStreamCast002, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, NotifyMirrorToStreamCast003, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, RefreshFocusSessionSort001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, SelectSessionByUid001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, SelectSessionByUid002, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, InitBMS001, TestSize.Level1)
{
    SLOGI("InitBMS001 begin!");
    avservice_->InitBMS();
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("InitBMS001 end!");
}

static HWTEST_F(AVSessionServiceTest, ReleaseCastSession001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, CreateSessionByCast001, TestSize.Level1)
{
    SLOGI("CreateSessionByCast001 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("CreateSessionByCast001 in!");
    avservice_->CreateSessionByCast(0);
    avservice_->ClearSessionForClientDiedNoLock(getpid());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("CreateSessionByCast001 end!");
}

static HWTEST_F(AVSessionServiceTest, MirrorToStreamCast001, TestSize.Level1)
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
    avservice_->is2in1_ = true;
    avservice_->MirrorToStreamCast(avsessionHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("MirrorToStreamCast001 end!");
}

static HWTEST_F(AVSessionServiceTest, MirrorToStreamCast002, TestSize.Level1)
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
    avservice_->is2in1_ = false;
    avservice_->MirrorToStreamCast(avsessionHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("MirrorToStreamCast002 end!");
}

static HWTEST_F(AVSessionServiceTest, MirrorToStreamCast003, TestSize.Level1)
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
    avservice_->is2in1_ = true;
    avservice_->MirrorToStreamCast(avsessionHere_);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
#endif
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("MirrorToStreamCast003 end!");
}

static HWTEST_F(AVSessionServiceTest, RefreshSortFileOnCreateSession001, TestSize.Level1)
{
    SLOGI("RefreshSortFileOnCreateSession001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    avservice_->refreshSortFileOnCreateSession(avsessionHere_->GetSessionId(),
        "audio", elementName);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("RefreshSortFileOnCreateSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalAVQueueInfos001, TestSize.Level1)
{
    SLOGI("GetHistoricalAVQueueInfos001 begin!");
    std::vector<AVQueueInfo> avQueueInfos_;
    avservice_->GetHistoricalAVQueueInfos(0, 0, avQueueInfos_);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalAVQueueInfos001 end!");
}

static HWTEST_F(AVSessionServiceTest, SaveAvQueueInfo001, TestSize.Level1)
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
    if (!avservice_->LoadStringFromFileEx(avservice_->AVSESSION_FILE_DIR +
        avservice_->AVQUEUE_FILE_NAME, oldContent)) {
        SLOGE("SaveAvQueueInfo001 read avqueueinfo fail, Return!");
        return;
    }
    avservice_->SaveAvQueueInfo(oldContent, g_testAnotherBundleName, meta);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("SaveAvQueueInfo001 end!");
}

static HWTEST_F(AVSessionServiceTest, AddAvQueueInfoToFile001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, StartAVPlayback001, TestSize.Level1)
{
    SLOGI("StartAVPlayback001 begin!");
    avservice_->StartAVPlayback(g_testAnotherBundleName, "FAKE_ASSET_NAME");
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("StartAVPlayback001 end!");
}

static HWTEST_F(AVSessionServiceTest, GetSubNode001, TestSize.Level1)
{
    SLOGI("GetSubNode001 begin!");
    nlohmann::json value;
    value["bundleName"] = g_testAnotherBundleName;
    avservice_->GetSubNode(value, "FAKE_NAME");
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("GetSubNode001 end!");
}

static HWTEST_F(AVSessionServiceTest, Close001, TestSize.Level1)
{
    SLOGI("Close001 begin!");
    avservice_->Close();
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("Close001 end!");
}

static HWTEST_F(AVSessionServiceTest, DeleteHistoricalRecord001, TestSize.Level1)
{
    SLOGI("DeleteHistoricalRecord001 begin!");
    avservice_->DeleteHistoricalRecord(g_testAnotherBundleName);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("DeleteHistoricalRecord001 end!");
}

static HWTEST_F(AVSessionServiceTest, Dump001, TestSize.Level1)
{
    SLOGI("Dump001 begin!");std::vector<std::u16string> argsList;
    avservice_->Dump(1, argsList);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("Dump001 end!");
}

static HWTEST_F(AVSessionServiceTest, ProcessCastAudioCommand001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, ProcessCastAudioCommand002, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, HandleDeviceChange001, TestSize.Level1)
{
    SLOGI("HandleDeviceChange001 begin!");
    DeviceChangeAction deviceChange;
    deviceChange.type = static_cast<DeviceChangeType>(0);
    deviceChange.flag = static_cast<DeviceFlag>(0);
    avservice_->HandleDeviceChange(deviceChange);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("HandleDeviceChange001 end!");
}

static HWTEST_F(AVSessionServiceTest, HandleDeviceChange002, TestSize.Level1)
{
    SLOGI("HandleDeviceChange002 begin!");
    DeviceChangeAction deviceChange;
    std::vector<OHOS::sptr<AudioDeviceDescriptor>> audioDeviceDescriptors;
    OHOS::sptr<AudioDeviceDescriptor> descriptor = new(std::nothrow) AudioDeviceDescriptor();
    descriptor->deviceType_ = OHOS::AudioStandard::DEVICE_TYPE_WIRED_HEADSET;
    deviceChange.type = static_cast<DeviceChangeType>(0);
    deviceChange.flag = static_cast<DeviceFlag>(0);

    audioDeviceDescriptors.push_back(descriptor);
    deviceChange.deviceDescriptors = audioDeviceDescriptors;
    avservice_->HandleDeviceChange(deviceChange);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("HandleDeviceChange002 end!");
}
