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

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;


static AVMetaData g_metaData;
static AVPlaybackState g_playbackState;
static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";
static int32_t g_playOnCall = AVSESSION_ERROR;
static int32_t g_pauseOnCall = AVSESSION_ERROR;
static int32_t g_nextOnCall = AVSESSION_ERROR;
static int32_t g_previousOnCall = AVSESSION_ERROR;

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
}

void AVSessionServiceTest::TearDownTestCase()
{
}

void AVSessionServiceTest::SetUp()
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    avsession_ = AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO,
                                                               elementName);
    ASSERT_NE(avsession_, nullptr);
    avsession_->Activate();
}

void AVSessionServiceTest::TearDown()
{
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
    void OnFastForward() override {};
    void OnRewind() override {};
    void OnSeek(int64_t time) override {};
    void OnSetSpeed(double speed) override {};
    void OnSetLoopMode(int32_t loopMode) override {};
    void OnToggleFavorite(const std::string& mediaId) override {};
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override {};
    void OnOutputDeviceChange(const int32_t connectionState,
        const OHOS::AVSession::OutputDeviceInfo& outputDeviceInfo) override {};
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override {};
    void OnSkipToQueueItem(int32_t itemId) override {};

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
HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent001, TestSize.Level1)
{
    SLOGI("SendSystemAVKeyEvent001 begin!");

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
    avsession_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsession_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);

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
    SLOGI("SendSystemAVKeyEvent001 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent002
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/

HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent002, TestSize.Level1)
{
    SLOGI("SendSystemAVKeyEvent002 begin!");

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
    avsession_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PAUSE);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsession_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);

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
    SLOGI("SendSystemAVKeyEvent002 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent003
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent003, TestSize.Level1)
{
    SLOGI("SendSystemAVKeyEvent003 begin!");

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
    avsession_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsession_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);

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
    SLOGI("SendSystemAVKeyEvent003 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent004
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent004, TestSize.Level1)
{
    SLOGI("SendSystemAVKeyEvent004 begin!");

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
    avsession_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsession_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);

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
    SLOGI("SendSystemAVKeyEvent004 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent005
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent005, TestSize.Level1)
{
    SLOGI("SendSystemAVKeyEvent005 begin!");

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
    avsession_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsession_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);

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
    SLOGI("SendSystemAVKeyEvent005 end!");
}

/**
* @tc.name: SendSystemAVKeyEvent006
* @tc.desc: verifying send system keyEvent
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVSessionServiceTest, SendSystemAVKeyEvent006, TestSize.Level1)
{
    SLOGI("SendSystemAVKeyEvent006 begin!");

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
    avsession_->SetAVMetaData(g_metaData);

    g_playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    avsession_->SetAVPlaybackState(g_playbackState);

    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);

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
    SLOGI("SendSystemAVKeyEvent006 end!");
}