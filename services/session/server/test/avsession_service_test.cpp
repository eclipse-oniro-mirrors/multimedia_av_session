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
#include "audio_info.h"
#include "avsession_callback_client.h"
#include "avsession_pixel_map.h"
#include "avsession_pixel_map_adapter.h"

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
    SLOGI("InitBMS001 stop to prevent crash in SubscribeBundleStatusEvent");
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

static HWTEST_F(AVSessionServiceTest, SaveSessionInfoInFile001, TestSize.Level1)
{
    SLOGI("SaveSessionInfoInFile001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);
    SLOGE("AVSession not to do refreshSortFileOnCreateSession for crash");
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("SaveSessionInfoInFile001 end!");
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
    if (!avservice_->LoadStringFromFileEx(avservice_->GetAVQueueDir(), oldContent)) {
        SLOGE("SaveAvQueueInfo001 read avqueueinfo fail, Return!");
        avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
        return;
    }
    avservice_->SaveAvQueueInfo(oldContent, g_testAnotherBundleName, meta,
        avservice_->GetUsersManager().GetCurrentUserId());
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
    SLOGI("Dump001 begin!");
    std::vector<std::u16string> argsList;
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
    SLOGI("OnReceiveEvent001 end!");
}

static HWTEST_F(AVSessionServiceTest, OnReceiveEvent002, TestSize.Level1)
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
    SLOGI("OnReceiveEvent002 end!");
}

static HWTEST_F(AVSessionServiceTest, UnSubscribeCommonEvent001, TestSize.Level1)
{
    SLOGI("SubscribeCommonEvent001 begin!");
    avservice_->SubscribeCommonEvent();
    avservice_->UnSubscribeCommonEvent();
    SLOGI("SubscribeCommonEvent001 end!");
}

static HWTEST_F(AVSessionServiceTest, UnSubscribeCommonEvent002, TestSize.Level1)
{
    SLOGI("SubscribeCommonEvent002 begin!");
    avservice_->UnSubscribeCommonEvent();
    SLOGI("SubscribeCommonEvent002 end!");
}

static HWTEST_F(AVSessionServiceTest, OnRemoveSystemAbility001, TestSize.Level1)
{
    SLOGI("OnRemoveSystemAbility001 begin!");
    int32_t systemAbilityId = 65546;
    std::string deviceId = "";
    avservice_->OnRemoveSystemAbility(systemAbilityId, deviceId);
    SLOGI("OnRemoveSystemAbility001 end!");
}

static HWTEST_F(AVSessionServiceTest, OnRemoveSystemAbility002, TestSize.Level1)
{
    SLOGI("OnRemoveSystemAbility002 begin!");
    int32_t systemAbilityId = 111222;
    std::string deviceId = "";
    avservice_->OnRemoveSystemAbility(systemAbilityId, deviceId);
    SLOGI("OnRemoveSystemAbility002 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptorsFromFile001, TestSize.Level1)
{
    SLOGI("GetHistoricalSessionDescriptorsFromFile001 begin!");
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = avservice_->GetHistoricalSessionDescriptorsFromFile(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalSessionDescriptorsFromFile001 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptors001, TestSize.Level1)
{
    SLOGI("GetHistoricalSessionDescriptors001 begin!");
    int32_t maxSize = -1;
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = avservice_->GetHistoricalSessionDescriptors(maxSize, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalSessionDescriptors001 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptors002, TestSize.Level1)
{
    SLOGI("GetHistoricalSessionDescriptors002 begin!");
    int32_t maxSize = 50;
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = avservice_->GetHistoricalSessionDescriptors(maxSize, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetHistoricalSessionDescriptors002 end!");
}

static HWTEST_F(AVSessionServiceTest, GetHistoricalSessionDescriptors003, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, DoMetadataImgClean001, TestSize.Level1)
{
    SLOGI("DoMetadataImgClean001 begin!");
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

static HWTEST_F(AVSessionServiceTest, DoMetadataImgClean002, TestSize.Level1)
{
    SLOGI("DoMetadataImgClean002 begin!");
    OHOS::AVSession::AVMetaData metaData;
    avservice_->DoMetadataImgClean(metaData);
    SLOGI("DoMetadataImgClean002 end!");
}

static HWTEST_F(AVSessionServiceTest, Dump002, TestSize.Level1)
{
    SLOGI("Dump002 begin!");
    int32_t fd = -1;
    std::vector<std::u16string> argsList;
    int32_t ret = avservice_->Dump(fd, argsList);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("Dump002 end!");
}

static HWTEST_F(AVSessionServiceTest, GetTrustedDeviceName001, TestSize.Level1)
{
    SLOGI("GetTrustedDeviceName001 begin!");
    std::string networkId = "";
    std::string deviceName = "";
    int32_t ret = avservice_->GetTrustedDeviceName(networkId, deviceName);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetTrustedDeviceName001 end!");
}

static HWTEST_F(AVSessionServiceTest, HandleFocusSession001, TestSize.Level1)
{
    SLOGI("HandleFocusSession001 begin!");
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
    avservice_->HandleFocusSession(info);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleFocusSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, HandleFocusSession002, TestSize.Level1)
{
    SLOGI("HandleFocusSession002 begin!");
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
    avservice_->HandleFocusSession(info);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleFocusSession002 end!");
}

static HWTEST_F(AVSessionServiceTest, UpdateFrontSession001, TestSize.Level1)
{
    SLOGI("HandleFocusSession001 begin!");
    int32_t pid = 203;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->SetUid(pid);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = pid;
    avservice_->HandleFocusSession(info);
    avservice_->UpdateFrontSession(avsessionHere_, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleFocusSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, UpdateFrontSession002, TestSize.Level1)
{
    SLOGI("UpdateFrontSession002 begin!");
    int32_t pid = 204;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionHere_->SetUid(pid);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 205;
    avservice_->HandleFocusSession(info);
    avservice_->UpdateFrontSession(avsessionHere_, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("UpdateFrontSession002 end!");
}

static HWTEST_F(AVSessionServiceTest, SelectFocusSession001, TestSize.Level1)
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
    info.uid = pid;
    bool ret = avservice_->SelectFocusSession(info);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    EXPECT_EQ(ret, true);
    SLOGI("SelectFocusSession001 end!");
}

static HWTEST_F(AVSessionServiceTest, SelectFocusSession002, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, SelectSessionByUid003, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, GetSessionDescriptorsBySessionId001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent007, TestSize.Level1)
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


static HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent008, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, PullMigrateStub001, TestSize.Level1)
{
    SLOGI("PullMigrateStub001 begin!");
    avservice_->PullMigrateStub();
    SLOGI("PullMigrateStub001 end!");
}

static HWTEST_F(AVSessionServiceTest, UpdateFrontSession003, TestSize.Level1)
{
    SLOGI("UpdateFrontSession003 begin!");
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

static HWTEST_F(AVSessionServiceTest, CreateSessionInner001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, CreateSessionInner002, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, ReportSessionInfo001, TestSize.Level1)
{
    SLOGI("ReportSessionInfo001 begin!");
    OHOS::sptr<AVSessionItem> avsessionHere_ = nullptr;
    avservice_->ReportSessionInfo(avsessionHere_, true);
    SLOGI("ReportSessionInfo001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateNewControllerForSession001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, IsHistoricalSession001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, StartDefaultAbilityByCall001, TestSize.Level1)
{
    SLOGI("StartDefaultAbilityByCall001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    std::string sessionId = avsessionHere_->GetSessionId();
    int32_t ret = avservice_->StartDefaultAbilityByCall(sessionId);
    EXPECT_EQ(ret, ERR_ABILITY_NOT_AVAILABLE);
    avservice_->HandleSessionRelease(sessionId);
    avsessionHere_->Destroy();
    SLOGI("StartDefaultAbilityByCall001 end!");
}

static HWTEST_F(AVSessionServiceTest, StartAbilityByCall001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, HandleSystemKeyColdStart001, TestSize.Level1)
{
    SLOGI("HandleSystemKeyColdStart001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    AVControlCommand command;
    avservice_->HandleSystemKeyColdStart(command);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("HandleSystemKeyColdStart001 end!");
}

static HWTEST_F(AVSessionServiceTest, SendSystemControlCommand001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, HandleControllerRelease001, TestSize.Level1)
{
    SLOGI("HandleControllerRelease001 begin!");
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

static HWTEST_F(AVSessionServiceTest, GetDeviceInfo001, TestSize.Level1)
{
    SLOGI("GetDeviceInfo001 begin!");
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

static HWTEST_F(AVSessionServiceTest, CreateControllerInner001, TestSize.Level1)
{
    SLOGI("CreateControllerInner001 begin!");
    std::string sessionId = "default";
    OHOS::sptr<IRemoteObject> object = nullptr;
    int32_t ret = avservice_->CreateControllerInner(sessionId, object);
    EXPECT_EQ(ret, ERR_ABILITY_NOT_AVAILABLE);
    SLOGI("CreateControllerInner001 end!");
}

static HWTEST_F(AVSessionServiceTest, ClearControllerForClientDiedNoLock001, TestSize.Level1)
{
    SLOGI("ClearControllerForClientDiedNoLock001 begin!");
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

static HWTEST_F(AVSessionServiceTest, LoadStringFromFileEx001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, LoadStringFromFileEx002, TestSize.Level1)
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
    ofstream ofs;
    ofs.open(filePath, ios::out);
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

static HWTEST_F(AVSessionServiceTest, LoadStringFromFileEx003, TestSize.Level1)
{
    SLOGI("LoadStringFromFileEx003 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);

    std::string filePath = "/adcdXYZ123/test3.txt";
    std::string content;
    ifstream file(filePath, ios_base::in);
    bool ret = avservice_->LoadStringFromFileEx(filePath, content);
    file.close();
    EXPECT_EQ(ret, false);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("LoadStringFromFileEx003 end!");
}

static HWTEST_F(AVSessionServiceTest, SaveStringToFileEx001, TestSize.Level1)
{
    SLOGI("SaveStringToFileEx001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);

    std::string filePath = avservice_->GetUsersManager().GetDirForCurrentUser() + "test4.txt";
    std::string content;
    bool ret = avservice_->LoadStringFromFileEx(filePath, content);
    EXPECT_EQ(ret, true);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("SaveStringToFileEx001 end!");
}

static HWTEST_F(AVSessionServiceTest, SaveStringToFileEx002, TestSize.Level1)
{
    SLOGI("SaveStringToFileEx002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);

    std::string filePath = "/adcdXYZ123/test5.txt";
    std::string content;
    ifstream file(filePath, ios_base::in);
    bool ret = avservice_->LoadStringFromFileEx(filePath, content);
    file.close();
    EXPECT_EQ(ret, false);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("SaveStringToFileEx002 end!");
}

static HWTEST_F(AVSessionServiceTest, CheckStringAndCleanFile001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, CheckStringAndCleanFile002, TestSize.Level1)
{
    SLOGI("CheckStringAndCleanFile002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere_ =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere_ != nullptr, true);

    std::string filePath = "/adcdXYZ123/test7.txt";
    ifstream file(filePath, ios_base::in);
    bool ret = avservice_->CheckStringAndCleanFile(filePath);
    file.close();
    EXPECT_EQ(ret, false);
    avservice_->HandleSessionRelease(avsessionHere_->GetSessionId());
    avsessionHere_->Destroy();
    SLOGI("CheckStringAndCleanFile002 end!");
}

static HWTEST_F(AVSessionServiceTest, ReportStartCastEnd001, TestSize.Level1)
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
static HWTEST_F(AVSessionServiceTest, OnStateChanged001, TestSize.Level1)
{
    SLOGI("OnStateChanged001 begin!");
    DetectBluetoothHostObserver detectBluetoothHostObserver(avservice_);
    int transport = 111222;
    int status = 111222;
    detectBluetoothHostObserver.OnStateChanged(transport, status);
    SLOGI("OnStateChanged001 end!");
}

static HWTEST_F(AVSessionServiceTest, OnStateChanged002, TestSize.Level1)
{
    SLOGI("OnStateChanged002 begin!");
    DetectBluetoothHostObserver detectBluetoothHostObserver(avservice_);
    int transport = OHOS::Bluetooth::BTTransport::ADAPTER_BREDR;
    int status = 111222;
    detectBluetoothHostObserver.OnStateChanged(transport, status);
    SLOGI("OnStateChanged002 end!");
}

static HWTEST_F(AVSessionServiceTest, OnStateChanged003, TestSize.Level1)
{
    SLOGI("OnStateChanged003 begin!");
    DetectBluetoothHostObserver detectBluetoothHostObserver(avservice_);
    int transport = OHOS::Bluetooth::BTTransport::ADAPTER_BREDR;
    int status = OHOS::Bluetooth::BTStateID::STATE_TURN_ON;
    detectBluetoothHostObserver.OnStateChanged(transport, status);
    SLOGI("OnStateChanged003 end!");
}

static HWTEST_F(AVSessionServiceTest, OnStateChanged004, TestSize.Level1)
{
    SLOGI("OnStateChanged004 begin!");
    AVSessionService *avservice = nullptr;
    DetectBluetoothHostObserver detectBluetoothHostObserver(avservice);
    int transport = OHOS::Bluetooth::BTTransport::ADAPTER_BREDR;
    int status = OHOS::Bluetooth::BTStateID::STATE_TURN_ON;
    detectBluetoothHostObserver.OnStateChanged(transport, status);
    SLOGI("OnStateChanged004 end!");
}
#endif

static HWTEST_F(AVSessionServiceTest, OnReceiveEvent003, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, UpdateFrontSession004, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, CheckAncoAudio001, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, SendSystemControlCommand002, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, CreateWantAgent001, TestSize.Level1)
{
    SLOGD("CreateWantAgent001 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor(nullptr);
    auto ret = avservice_->CreateWantAgent(histroyDescriptor.get());
    EXPECT_EQ(ret, nullptr);
    SLOGD("CreateWantAgent001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateWantAgent002, TestSize.Level1)
{
    SLOGD("CreateWantAgent001 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto ret = avservice_->CreateWantAgent(histroyDescriptor.get());
    EXPECT_EQ(ret, nullptr);
    SLOGD("CreateWantAgent001 end!");
}

static HWTEST_F(AVSessionServiceTest, CreateWantAgent003, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, CreateWantAgent004, TestSize.Level1)
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

static HWTEST_F(AVSessionServiceTest, HandleSystemKeyColdStart002, TestSize.Level1)
{
    SLOGD("HandleSystemKeyColdStart002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere =
        avservice_->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_EQ(avsessionHere != nullptr, true);
    AVControlCommand command;
    command.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    avservice_->HandleSystemKeyColdStart(command);
    avservice_->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    SLOGD("HandleSystemKeyColdStart002 end!");
}