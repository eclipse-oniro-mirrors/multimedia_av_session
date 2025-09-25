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

#include "avsession_manager.h"
#include "avsession_errors.h"
#include "avsession_callback_client.h"
#include "want_agent.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avcall_state.h"
#include "avcall_meta_data.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avsession_log.h"
#include "avcontrol_command.h"

#include "accesstoken_kit.h"
#include "bool_wrapper.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AVSession {
static int32_t g_onCall = AVSESSION_ERROR;
static int32_t g_sessionId = AVSESSION_ERROR;
static AVMetaData g_metaData;
static AVCallMetaData g_avCallMetaData;
static AVCallState g_avCallState;
static AVPlaybackState g_playbackState;
static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";
static uint64_t g_selfTokenId = 0;

static HapInfoParams g_info = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demo",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demo",
    .isSystemApp = true
};

static HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .bundleName = "ohos.permission_test.demo",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

class AvsessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AVSession> avsession_ = nullptr;
    std::shared_ptr<AVSessionController> controller_ = nullptr;

    static constexpr int SESSION_LEN = 64;
};

void AvsessionTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AvsessionTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AvsessionTest::SetUp()
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    avsession_ = AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO,
                                                               elementName);
    ASSERT_NE(avsession_, nullptr);
    g_sessionId++;
    auto ret = AVSessionManager::GetInstance().CreateController(avsession_->GetSessionId(), controller_);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    ASSERT_NE(controller_, nullptr);
}

void AvsessionTest::TearDown()
{
    [[maybe_unused]] int32_t ret = AVSESSION_ERROR;
    if (avsession_ != nullptr) {
        ret = avsession_->Destroy();
        avsession_ = nullptr;
    }
    if (controller_ != nullptr) {
        ret = controller_->Destroy();
        controller_ = nullptr;
    }
    g_onCall = AVSESSION_ERROR;
}

class AVSessionDemo : public AVSession {
public:
    std::string GetSessionId() override;
    std::string GetSessionType() override;
    int32_t GetAVMetaData(AVMetaData& meta) override;
    int32_t SetAVMetaData(const AVMetaData& meta) override;
    int32_t SetAVCallMetaData(const AVCallMetaData& meta) override;
    int32_t SetAVCallState(const AVCallState& avCallState) override;
    int32_t GetAVPlaybackState(AVPlaybackState& state) override;
    int32_t SetAVPlaybackState(const AVPlaybackState& state) override;
    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;
    int32_t SetAVQueueItems(const std::vector<AVQueueItem>& items) override;
    int32_t GetAVQueueTitle(std::string& title) override;
    int32_t SetAVQueueTitle(const std::string& title) override;
    int32_t SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability) override;
    int32_t GetExtras(AAFwk::WantParams& extras) override;
    int32_t SetExtras(const AAFwk::WantParams& extras) override;
    std::shared_ptr<AVSessionController> GetController() override;
    int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback) override;
    int32_t Activate() override;
    int32_t Deactivate() override;
    bool IsActive() override;
    int32_t Destroy() override;
    int32_t AddSupportCommand(const int32_t cmd) override;
    int32_t DeleteSupportCommand(const int32_t cmd) override;
    int32_t SetSessionEvent(const std::string& event, const AAFwk::WantParams& args) override;
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> GetAVCastController() override;
    int32_t ReleaseCast(bool continuePlay = false) override;
    int32_t StartCastDisplayListener() override;
    int32_t StopCastDisplayListener() override;
    int32_t GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays) override;
#endif
};

std::string AVSessionDemo::GetSessionId()
{
    return "";
}

std::string AVSessionDemo::GetSessionType()
{
    return "";
}

int32_t AVSessionDemo::GetAVMetaData(AVMetaData& meta)
{
    return 0;
}

int32_t AVSessionDemo::SetAVMetaData(const AVMetaData& meta)
{
    return 0;
}

int32_t AVSessionDemo::SetAVCallMetaData(const AVCallMetaData& meta)
{
    return 0;
}

int32_t AVSessionDemo::SetAVCallState(const AVCallState& avCallState)
{
    return 0;
}

int32_t AVSessionDemo::GetAVPlaybackState(AVPlaybackState& state)
{
    return 0;
}

int32_t AVSessionDemo::SetAVPlaybackState(const AVPlaybackState& state)
{
    return 0;
}

int32_t AVSessionDemo::GetAVQueueItems(std::vector<AVQueueItem>& items)
{
    return 0;
}

int32_t AVSessionDemo::SetAVQueueItems(const std::vector<AVQueueItem>& items)
{
    return 0;
}

int32_t AVSessionDemo::GetAVQueueTitle(std::string& title)
{
    return 0;
}

int32_t AVSessionDemo::SetAVQueueTitle(const std::string& title)
{
    return 0;
}

int32_t AVSessionDemo::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    return 0;
}

int32_t AVSessionDemo::GetExtras(AAFwk::WantParams& extras)
{
    return 0;
}

int32_t AVSessionDemo::SetExtras(const AAFwk::WantParams& extras)
{
    return 0;
}

std::shared_ptr<AVSessionController> AVSessionDemo::GetController()
{
    return nullptr;
}

int32_t AVSessionDemo::RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback)
{
    return 0;
}

int32_t AVSessionDemo::Activate()
{
    return 0;
}

int32_t AVSessionDemo::Deactivate()
{
    return 0;
}

bool AVSessionDemo::IsActive()
{
    return false;
}

int32_t AVSessionDemo::Destroy()
{
    return 0;
}

int32_t AVSessionDemo::AddSupportCommand(const int32_t cmd)
{
    return 0;
}

int32_t AVSessionDemo::DeleteSupportCommand(const int32_t cmd)
{
    return 0;
}

int32_t AVSessionDemo::SetSessionEvent(const std::string& event, const AAFwk::WantParams& args)
{
    return 0;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
std::shared_ptr<AVCastController> AVSessionDemo::GetAVCastController()
{
    return nullptr;
}

int32_t AVSessionDemo::ReleaseCast(bool continuePlay = false)
{
    return 0;
}

int32_t AVSessionDemo::StartCastDisplayListener()
{
    return 0;
}

int32_t AVSessionDemo::StopCastDisplayListener()
{
    return 0;
}

int32_t AVSessionDemo::GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays)
{
    return 0;
}
#endif

class AVSessionCallbackImpl : public AVSessionCallback {
public:
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward(int64_t time) override;
    void OnRewind(int64_t time) override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnSetTargetLoopMode(int32_t targetLoopMode) override;
    void OnToggleFavorite(const std::string& mediaId) override;
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override;
    void OnOutputDeviceChange(const int32_t connectionState,
        const OHOS::AVSession::OutputDeviceInfo& outputDeviceInfo) override {};
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override;
    void OnSkipToQueueItem(int32_t itemId) override {};
    void OnAVCallAnswer() override {};
    void OnAVCallHangUp() override {};
    void OnAVCallToggleCallMute() override {};
    void OnPlayFromAssetId(int64_t assetId) override;
    void OnPlayWithAssetId(const std::string& assetId) override;
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override;

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

void AVSessionCallbackImpl::OnFastForward(int64_t time)
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnFastForward %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnRewind(int64_t time)
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnRewind %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnSeek(int64_t time)
{
    SLOGE("OnSeek %{public}" PRId64, time);
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

void AVSessionCallbackImpl::OnSetTargetLoopMode(int32_t targetLoopMode)
{
    SLOGE("OnSetTargetLoopMode %{public}d", targetLoopMode);
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnSetTargetLoopMode %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnToggleFavorite(const std::string& mediaId)
{
    SLOGE("OnToggleFavorite %{public}s", mediaId.c_str());
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnToggleFavorite %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent)
{
    SLOGE("OnMediaKeyEvent");
    g_onCall = AVSESSION_SUCCESS;
}

void AVSessionCallbackImpl::OnCommonCommand(const std::string& commonCommand,
    const OHOS::AAFwk::WantParams& commandArgs)
{
    SLOGI("OnCommonCommand");
    g_onCall = AVSESSION_SUCCESS;
}

void AVSessionCallbackImpl::OnPlayFromAssetId(int64_t assetId)
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPlayFromAssetId %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnPlayWithAssetId(const std::string& assetId)
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPlayWithAssetId %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo)
{
    SLOGE("OnCastDisplayChange");
    g_onCall = AVSESSION_SUCCESS;
}

AVSessionCallbackImpl::~AVSessionCallbackImpl()
{
}

/**
 * @tc.name: SetAVCallMetaData001
 * @tc.desc: Return the result of set avcall meta data
 * @tc.type: FUNC
 */
HWTEST_F(AvsessionTest, SetAVCallMetaData001, TestSize.Level1)
{
    SLOGE("SetAVCallMetaData001 Begin");
    g_avCallMetaData.Reset();
    g_avCallMetaData.SetName("");
    g_avCallMetaData.SetPhoneNumber("123456789");

    EXPECT_EQ(avsession_->SetAVCallMetaData(g_avCallMetaData), AVSESSION_SUCCESS);
    SLOGE("SetAVCallMetaData001 enable optional params End");
}

/**
 * @tc.name: SetAVCallMetaData002
 * @tc.desc: Return the result of set avcall meta data
 * @tc.type: FUNC
 */
HWTEST_F(AvsessionTest, SetAVCallMetaData002, TestSize.Level1)
{
    SLOGE("SetAVCallMetaData002 Begin");
    g_avCallMetaData.Reset();
    g_avCallMetaData.SetName("xiaoming");
    g_avCallMetaData.SetPhoneNumber("123456789");

    EXPECT_EQ(avsession_->SetAVCallMetaData(g_avCallMetaData), AVSESSION_SUCCESS);
    SLOGE("SetAVCallMetaData002 End");
}

/**
 * @tc.name: SetAVCallState001
 * @tc.desc: Return the result of set avcall meta data
 * @tc.type: FUNC
 */
HWTEST_F(AvsessionTest, SetAVCallState001, TestSize.Level1)
{
    SLOGE("SetAVCallState001 Begin");
    g_avCallState.SetAVCallState(2);
    g_avCallState.SetAVCallMuted(false);

    EXPECT_EQ(avsession_->SetAVCallState(g_avCallState), AVSESSION_SUCCESS);
    SLOGE("SetAVCallState001 End");
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
    auto sessionId = avsession_->GetSessionId();
    EXPECT_EQ(sessionId.length() == SESSION_LEN, true);
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
    g_metaData.SetAssetId("");
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
    EXPECT_EQ(avsession_->SetAVMetaData(g_metaData), AVSESSION_ERROR);
    SLOGE("SetAVMetaData001 End");
}

/**
* @tc.name: SetAVMetaData002
* @tc.desc: Return the result of set av meta data
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVMetaData002, TestSize.Level1)
{
    SLOGE("SetAVMetaData002 Begin");
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
    EXPECT_EQ(avsession_->SetAVMetaData(g_metaData), AVSESSION_SUCCESS);
    SLOGE("SetAVMetaData002 End");
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
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState001 End");
}

/**
* @tc.name: SetAVPlaybackState002
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState002, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState002 Begin");
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(700000);
    g_playbackState.SetLoopMode(1);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState002 End");
}

/**
* @tc.name: SetAVPlaybackState003
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState003, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState003 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(2000000);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(17000);
    g_playbackState.SetLoopMode(1);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState003 End");
}

/**
* @tc.name: SetAVPlaybackState004
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState004, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState004 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(2000000);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({10000, 0});
    g_playbackState.SetBufferedTime(17000);
    g_playbackState.SetLoopMode(1);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState004 End");
}


/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test001, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test001 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test001 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test002, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test002 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test002 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test003, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test003 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test003 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test004, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test004 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test004 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test005, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test005 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test005 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test006, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test006 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test006 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test007, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test007 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test007 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test008, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test008 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test008 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test009, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test009 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test009 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test010, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test010 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test010 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test011, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test011 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test011 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test012, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test012 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test012 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test013, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test013 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test013 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test014, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test014 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test014 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test015, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test015 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test015 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test016, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test016 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test016 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test017, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test017 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetPosition({40000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test017 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test018, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test018 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetBufferedTime(30000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test018 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test019, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test019 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test019 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test020, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test020 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test020 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test021, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test021 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test021 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test022, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test022 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test022 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test023, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test023 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test023 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test024, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test024 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetFavorite(false);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test024 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test025, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test025 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test025 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test026, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test026 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test026 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test027, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test027 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test027 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test028, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test028 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test028 End");
}


/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test029, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test029 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test029 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test030, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test030 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test030 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test031, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test031 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test031 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test032, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test032 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test032 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test033, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test033 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test033 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test034, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test034 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test034 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test035, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test035 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test035 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test036, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test036 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test036 End");
}


/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test037, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test037 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test037 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test038, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test038 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test038 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test039, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test039 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test039 End");
}


/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test040, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test040 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test040 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test041, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test041 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test041 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test042, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test042 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test042 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test043, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test043 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test043 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test044, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test044 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test044 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test045, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test045 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test045 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test046, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test046 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test046 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test047, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test047 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test047 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test048, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test048 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({50000, 0});
    g_playbackState.SetFavorite(false);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test048 End");
}


/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test049, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test049 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({50000, 0});
    g_playbackState.SetFavorite(false);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test049 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test050, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test050 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({50000, 0});
    g_playbackState.SetFavorite(false);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test050 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test051, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test051 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({50000, 0});
    g_playbackState.SetFavorite(false);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test051 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test052, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test052 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test052 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test053, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test053 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test053 End");
}

/**
* @tc.name: SetAVPlaybackState_sequence_test
* @tc.desc: Return the result of set av playback state
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test054, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test054 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test054 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test055, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test055 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test055 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test056, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test056 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test056 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test057, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test057 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test057 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test058, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test058 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test058 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test059, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test059 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test059 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test060, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test060 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test060 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test061, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test061 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test061 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test062, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test062 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test062 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test063, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test063 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test063 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test064, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test064 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test064 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test065, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test065 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test065 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test066, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test066 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test066 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test067, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test067 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test067 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test068, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test068 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test068 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test069, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test069 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test069 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test070, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test070 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test070 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test071, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test071 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test071 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test072, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test072 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test072 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test073, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test073 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(2);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test073 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test074, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test074 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    g_playbackState.SetSpeed(0.5);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test074 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test075, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test075 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    g_playbackState.SetSpeed(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test075 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test076, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test076 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test076 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test077, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test077 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test077 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test078, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test078 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test078 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test079, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test079 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test079 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test080, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test080 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test080 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test081, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test081 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test081 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test082, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test082 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test082 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test083, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test083 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test083 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test084, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test084 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test084 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test085, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test085 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test085 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test086, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test086 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test086 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test087, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test087 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test087 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test088, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test088 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test088 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test089, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test089 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test089 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test090, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test090 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test090 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test91, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test91 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test91 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test92, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test92 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test92 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test093, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test093 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test093 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test094, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test094 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test094 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test095, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test095 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test095 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test096, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test096 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test096 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test097, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test097 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test097 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test098, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test098 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test098 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test099, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test099 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test099 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test100, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test100 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test100 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test101, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test101 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test101 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test102, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test102 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test102 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test103, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test103 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test103 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test104, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test104 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test104 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test105, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test105 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test105 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test106, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test106 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test106 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test107, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test107 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test107 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test108, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test108 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test108 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test109, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test109 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test109 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test110, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test110 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test110 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test111, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test111 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test111 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test112, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test112 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(8);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test112 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test113, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test113 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test113 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test114, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test114 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test114 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test115, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test115 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(9);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test115 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test116, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test116 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test116 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test117, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test117 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test117 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test118, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test118 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(10);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test118 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test119, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test119 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test119 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test120, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test120 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test120 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test121, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test121 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(11);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({20000, 0});
    g_playbackState.SetBufferedTime(40000);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test121 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test122, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test122 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test122 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test123, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test123 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test123 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test124, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test124 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test124 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test125, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test125 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test125 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test126, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test126 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test126 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test127, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test127 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test127 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test128, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test128 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test128 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test129, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test129 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test129 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test130, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test130 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test130 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test131, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test131 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test131 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test132, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test132 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test132 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test133, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test133 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(2);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test133 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test134, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test134 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test134 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test135, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test135 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test135 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test136, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test136 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test136 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test137, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test137 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test137 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test138, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test138 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test138 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test139, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test139 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test139 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test140, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test140 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test140 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test141, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test141 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test141 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test142, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test142 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test142 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test143, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test143 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test143 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test144, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test144 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test144 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test145, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test145 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(3);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test145 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test146, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test146 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test146 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test147, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test147 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test147 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test148, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test148 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test148 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test149, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test149 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test149 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test150, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test150 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test150 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test151, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test151 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test151 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test152, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test152 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test152 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test153, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test153 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test153 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test154, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test154 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test154 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test155, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test155 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test155 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test156, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test156 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test156 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test157, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test157 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(4);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test157 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test158, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test158 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test158 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test159, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test159 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test159 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test160, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test160 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test160 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test161, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test161 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test161 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test162, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test162 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test162 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test163, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test163 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test163 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test164, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test164 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test164 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test165, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test165 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test165 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test166, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test166 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test166 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test167, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test167 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test167 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test168, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test168 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test168 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test169, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test169 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(5);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test169 End");
}


/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test170, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test170 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test170 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test171, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test171 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test171 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test172, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test172 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test172 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test173, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test173 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test173 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test174, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test174 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test174 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test175, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test175 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test175 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test176, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test176 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test176 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test177, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test177 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test177 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test178, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test178 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test178 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test179, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test179 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(1);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test179 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test180, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test180 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(4);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test180 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test181, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test181 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(6);
    g_playbackState.SetSpeed(2);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(3);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test181 End");
}

/**
 * @tc.name: SetAVPlaybackState_sequence_test
 * @tc.desc: Return the result of set av playback state
 * @tc.type: FUNC
 * @tc.require: AR000H31JF
 */
HWTEST_F(AvsessionTest, SetAVPlaybackState_sequence_test182, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState_sequence_test182 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(20);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1.5);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(60000);
    g_playbackState.SetLoopMode(2);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    g_playbackState.SetState(7);
    g_playbackState.SetSpeed(0.5);
    g_playbackState.SetPosition({30000, 0});
    g_playbackState.SetBufferedTime(50000);
    g_playbackState.SetLoopMode(0);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState_sequence_test182 End");
}

/**
* @tc.name: SetSessionEventTest001
* @tc.desc: Set session event
* @tc.type: FUNC
* @tc.require: I6C6IN
*/
HWTEST_F(AvsessionTest, SetSessionEventTest001, TestSize.Level1)
{
    SLOGE("SetSessionEventTest001 Begin");
    std::string event = "eventName";
    OHOS::AAFwk::WantParams args;
    EXPECT_EQ(avsession_->SetSessionEvent(event, args), AVSESSION_SUCCESS);
    SLOGE("SetSessionEventTest001 End");
}

/**
* @tc.name: SetSessionEventTest002
* @tc.desc: Set session event - large number of calls
* @tc.type: FUNC
* @tc.require: I6C6IN
*/
HWTEST_F(AvsessionTest, SetSessionEventTest002, TestSize.Level2)
{
    SLOGE("SetSessionEventTest002 Begin");
    std::string event = "eventName";
    OHOS::AAFwk::WantParams args;

    // Test the interface through 500 calls
    for (int i = 0; i < 500; i++) {
        EXPECT_EQ(avsession_->SetSessionEvent(event, args), AVSESSION_SUCCESS);
    }
    SLOGE("SetSessionEventTest002 End");
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
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(2000000);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    g_playbackState.SetState(1);
    g_playbackState.SetSpeed(1);
    g_playbackState.SetPosition({80000, 0});
    g_playbackState.SetBufferedTime(87000);
    g_playbackState.SetLoopMode(1);
    g_playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(g_playbackState), AVSESSION_SUCCESS);
    AVPlaybackState state;
    EXPECT_EQ(avsession_->GetAVPlaybackState(state), AVSESSION_SUCCESS);
    EXPECT_EQ(state.GetState(), g_playbackState.GetState());
    EXPECT_EQ(state.GetSpeed(), g_playbackState.GetSpeed());
    EXPECT_EQ(state.GetPosition().elapsedTime_, g_playbackState.GetPosition().elapsedTime_);
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
* @tc.name: GetController002
* @tc.desc: Return shared_ptr of controller
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, GetController002, TestSize.Level1)
{
    SLOGE("GetController002 Begin");
    auto controller = avsession_->GetController();
    auto controller1 = avsession_->GetController();
    EXPECT_NE(controller, nullptr);
    EXPECT_NE(controller1, nullptr);
    EXPECT_EQ(controller->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller1->Destroy(), ERR_CONTROLLER_NOT_EXIST);
    SLOGE("GetController002 End");
}

/**
* @tc.name: SetAVQueueItems
* @tc.desc: Set queue items of current application
* @tc.type: FUNC
* @tc.require: I6RJST
*/
HWTEST_F(AvsessionTest, SetAVQueueItems, TestSize.Level1)
{
    SLOGE("SetAVQueueItems Begin");
    std::vector<AVQueueItem> items;
    AVQueueItem queueItem;
    queueItem.SetItemId(1);
    AVMediaDescription description;
    description.SetMediaId("id");
    queueItem.SetDescription(std::make_shared<AVMediaDescription>(description));
    items.push_back(queueItem);
    EXPECT_EQ(avsession_->SetAVQueueItems(items), AVSESSION_SUCCESS);
    SLOGE("SetAVQueueItems End");
}

/**
* @tc.name: SetAVQueueTitle
* @tc.desc: Set queue title of current application
* @tc.type: FUNC
* @tc.require: I6RJST
*/
HWTEST_F(AvsessionTest, SetAVQueueTitle, TestSize.Level1)
{
    SLOGE("SetAVQueueTitle Begin");
    std::string title = "AVQueueTitle";
    EXPECT_EQ(avsession_->SetAVQueueTitle(title), AVSESSION_SUCCESS);
    SLOGE("SetAVQueueTitle End");
}

/**
* @tc.name: SetExtrasTest001
* @tc.desc: Set custom media packets
* @tc.type: FUNC
* @tc.require: I6TD43
*/
HWTEST_F(AvsessionTest, SetExtrasTest001, TestSize.Level1)
{
    SLOGI("SetExtrasTest001 Begin");
    std::shared_ptr<OHOS::AAFwk::WantParams> wantParamsIn = nullptr;
    wantParamsIn = std::make_shared<OHOS::AAFwk::WantParams>();
    std::string keyStr = "1234567";
    bool valueBool = true;
    wantParamsIn->SetParam(keyStr, OHOS::AAFwk::Boolean::Box(valueBool));

    EXPECT_EQ(avsession_->SetExtras(*wantParamsIn), AVSESSION_SUCCESS);
    SLOGI("SetExtrasTest001 End");
}

/**
* @tc.name: SetExtrasTest002
* @tc.desc: Set custom media packets - large number of calls
* @tc.type: FUNC
* @tc.require: I6TD43
*/
HWTEST_F(AvsessionTest, SetExtrasTest002, TestSize.Level2)
{
    SLOGI("SetExtrasTest002 Begin");
    std::shared_ptr<OHOS::AAFwk::WantParams> wantParamsIn = nullptr;
    wantParamsIn = std::make_shared<OHOS::AAFwk::WantParams>();
    std::string keyStr = "1234567";
    bool valueBool = true;
    wantParamsIn->SetParam(keyStr, OHOS::AAFwk::Boolean::Box(valueBool));

    // Test the interface through 500 calls
    for (int i = 0; i < 500; i++) {
        EXPECT_EQ(avsession_->SetExtras(*wantParamsIn), AVSESSION_SUCCESS);
    }
    SLOGI("SetExtrasTest002 End");
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
    for (int32_t cmd = AVControlCommand::SESSION_CMD_PLAY; cmd < AVControlCommand::SESSION_CMD_MAX; cmd++) {
        if (cmd == AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT) {
            continue;
        }
        AVControlCommand controlCommand;
        EXPECT_EQ(avsession_->AddSupportCommand(cmd), AVSESSION_SUCCESS);
        EXPECT_EQ(controlCommand.SetCommand(cmd), AVSESSION_SUCCESS);
        switch (cmd) {
            case AVControlCommand::SESSION_CMD_SEEK : controlCommand.SetSeekTime(100000);
                break;
            case AVControlCommand::SESSION_CMD_SET_SPEED : controlCommand.SetSpeed(1.5);
                break;
            case AVControlCommand::SESSION_CMD_SET_LOOP_MODE : controlCommand.SetLoopMode(2);
                break;
            case AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE : controlCommand.SetTargetLoopMode(2);
                break;
            case AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE : controlCommand.SetAssetId("callback");
                break;
            case AVControlCommand::SESSION_CMD_FAST_FORWARD : controlCommand.SetForwardTime(10);
                break;
            case AVControlCommand::SESSION_CMD_REWIND : controlCommand.SetRewindTime(10);
                break;
            case AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID: controlCommand.SetPlayFromAssetId(0);
                break;
            case AVControlCommand::SESSION_CMD_PLAY_WITH_ASSETID: controlCommand.SetPlayWithAssetId("0");
                break;
            default:
                break;
        }
        bool isActive = false;
        controller_->IsSessionActive(isActive);
        if (!isActive) {
            avsession_->Activate();
        }
        EXPECT_EQ(controller_->SendControlCommand(controlCommand), AVSESSION_SUCCESS);
        sleep(1);
        EXPECT_EQ(g_onCall, AVSESSION_SUCCESS);
        g_onCall = false;
    }
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
HWTEST_F(AvsessionTest, Activate001, TestSize.Level1)
{
    SLOGE("Activate001 Begin");
    bool isActive = false;
    EXPECT_EQ(avsession_->Activate(), AVSESSION_SUCCESS);
    isActive = avsession_->IsActive();
    EXPECT_EQ(isActive, true);
    SLOGE("Activate001 End");
}

/**
* @tc.name: Disactive001
* @tc.desc: Return is Session Actived
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, Deactivate001, TestSize.Level1)
{
    SLOGE("Deactivate001 Begin");
    bool isActive = true;
    EXPECT_EQ(avsession_->Deactivate(), AVSESSION_SUCCESS);
    isActive = avsession_->IsActive();
    EXPECT_EQ(isActive, false);
    SLOGE("Deactivate001 End");
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
* @tc.name: AddSupportCommand003
* @tc.desc: add supported commands
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, AddSupportCommand003, TestSize.Level1)
{
    SLOGE("AddSupportCommand003 Begin");
    for (int32_t cmd = AVControlCommand::SESSION_CMD_PLAY; cmd < AVControlCommand::SESSION_CMD_MAX; cmd++) {
        EXPECT_EQ(avsession_->AddSupportCommand(cmd), AVSESSION_SUCCESS);
    }
    std::vector<int32_t> cmds;
    EXPECT_EQ(controller_->GetValidCommands(cmds), AVSESSION_SUCCESS);
    EXPECT_EQ(cmds.size(), (AVControlCommand::SESSION_CMD_MAX - 1));
    for (int32_t index = 0; index < cmds.size(); index++) {
        EXPECT_EQ(cmds[index] > AVControlCommand::SESSION_CMD_INVALID, true);
        EXPECT_EQ(cmds[index] < AVControlCommand::SESSION_CMD_MAX, true);
        if (index >= AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT) {
            EXPECT_EQ(cmds[index], index + 1);
        } else {
            EXPECT_EQ(cmds[index], index);
        }
    }
    SLOGE("AddSupportCommand003 End");
}

/**
* @tc.name: deleteSupportCommand001
* @tc.desc: delete supported commands
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, deleteSupportCommand001, TestSize.Level1)
{
    SLOGE("deleteSupportCommand001 Begin");
    for (int32_t cmd = AVControlCommand::SESSION_CMD_PLAY; cmd < AVControlCommand::SESSION_CMD_MAX; cmd++) {
        EXPECT_EQ(avsession_->AddSupportCommand(cmd), AVSESSION_SUCCESS);
    }
    std::vector<int32_t> cmds;
    EXPECT_EQ(controller_->GetValidCommands(cmds), AVSESSION_SUCCESS);
    EXPECT_EQ(cmds.size(), (AVControlCommand::SESSION_CMD_MAX - 1));
    for (int32_t cmd = AVControlCommand::SESSION_CMD_PLAY; cmd < AVControlCommand::SESSION_CMD_MAX; cmd++) {
        EXPECT_EQ(avsession_->DeleteSupportCommand(cmd), AVSESSION_SUCCESS);
    }
    cmds.clear();
    EXPECT_EQ(controller_->GetValidCommands(cmds), AVSESSION_SUCCESS);
    EXPECT_EQ(cmds.size(), 0);
    SLOGE("deleteSupportCommand001 End");
}

/**
* @tc.name: deleteSupportCommand002
* @tc.desc: delete supported commands
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, deleteSupportCommand002, TestSize.Level1)
{
    SLOGE("deleteSupportCommand002 Begin");
    for (int32_t cmd = AVControlCommand::SESSION_CMD_PLAY; cmd < AVControlCommand::SESSION_CMD_MAX; cmd++) {
        EXPECT_EQ(avsession_->DeleteSupportCommand(cmd), AVSESSION_SUCCESS);
    }
    SLOGE("deleteSupportCommand002 End");
}

/**
* @tc.name: deleteSupportCommand003
* @tc.desc: delete supported commands
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, deleteSupportCommand003, TestSize.Level1)
{
    SLOGE("deleteSupportCommand003 Begin");
    for (int32_t cmd = AVControlCommand::SESSION_CMD_PLAY; cmd < AVControlCommand::SESSION_CMD_MAX; cmd++) {
        EXPECT_EQ(avsession_->AddSupportCommand(cmd), AVSESSION_SUCCESS);
    }
    std::vector<int32_t> cmds;
    EXPECT_EQ(controller_->GetValidCommands(cmds), AVSESSION_SUCCESS);
    EXPECT_EQ(cmds.size(), (AVControlCommand::SESSION_CMD_MAX - 1));
    EXPECT_EQ(avsession_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_INVALID), AVSESSION_ERROR);
    EXPECT_EQ(avsession_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_MAX), AVSESSION_ERROR);
    SLOGE("deleteSupportCommand003 End");
}

/**
* @tc.name: Destroy001
* @tc.desc: Return is Session destroyed result
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, Destroy001, TestSize.Level1)
{
    SLOGE("Destroy001 Begin");
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    avsession_ = nullptr;
    SLOGE("Destroy001 End");
}

/**
* @tc.name: Destroy002
* @tc.desc: Return is Session destroyed result
* @tc.type: FUNC
* @tc.require: AR000H31JF
*/
HWTEST_F(AvsessionTest, Destroy002, TestSize.Level1)
{
    SLOGE("Destroy002 Begin");
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(avsession_->Destroy(), ERR_SESSION_NOT_EXIST);
    avsession_ = nullptr;
    SLOGE("Destroy002 End");
}

/**
* @tc.name: GetSessionType001
* @tc.desc: GetSessionType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AvsessionTest, GetSessionType001, TestSize.Level1)
{
    SLOGD("GetSessionType001 Begin");
    EXPECT_EQ(avsession_->GetSessionType(), "audio");
    SLOGD("GetSessionType001 End");
}

/**
* @tc.name: GetAVQueueItems001
* @tc.desc: get que items
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AvsessionTest, GetAVQueueItems001, TestSize.Level1)
{
    SLOGD("GetAVQueueItems001 Begin");
    std::vector<AVQueueItem> items;
    EXPECT_EQ(avsession_->GetAVQueueItems(items), AVSESSION_SUCCESS);
    SLOGD("GetAVQueueItems001 End");
}

/**
* @tc.name: GetAVQueueTitle001
* @tc.desc: get av que title
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AvsessionTest, GetAVQueueTitle001, TestSize.Level1)
{
    SLOGD("GetAVQueueTitle001 Begin");
    std::string title1 = "AVQueueTitle";
    std::string title2;
    EXPECT_EQ(avsession_->SetAVQueueTitle(title1), AVSESSION_SUCCESS);
    EXPECT_EQ(avsession_->GetAVQueueTitle(title2), AVSESSION_SUCCESS);
    SLOGD("GetAVQueueTitle001 End");
}

/**
* @tc.name: GetExtras001
* @tc.desc: get extras
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AvsessionTest, GetExtras001, TestSize.Level1)
{
    SLOGD("GetExtras001 Begin");
    std::shared_ptr<OHOS::AAFwk::WantParams> wantParamsIn = nullptr;
    wantParamsIn = std::make_shared<OHOS::AAFwk::WantParams>();
    std::string keyStr = "1234567";
    bool valueBool = true;
    wantParamsIn->SetParam(keyStr, OHOS::AAFwk::Boolean::Box(valueBool));
    OHOS::AAFwk::WantParams wantParamsOut;
    EXPECT_EQ(avsession_->SetExtras(*wantParamsIn), AVSESSION_SUCCESS);
    EXPECT_EQ(avsession_->GetExtras(wantParamsOut), AVSESSION_SUCCESS);
    SLOGD("GetExtras001 End");
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
/**
* @tc.name: GetAllCastDisplays001
* @tc.desc: get all cast displays
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AvsessionTest, GetAllCastDisplays001, TestSize.Level1)
{
    SLOGD("GetAllCastDisplays001 Begin");
    std::vector<CastDisplayInfo> castDisplays;
    EXPECT_EQ(avsession_->GetAllCastDisplays(castDisplays), AVSESSION_SUCCESS);
    SLOGD("GetAllCastDisplays001 End");
}
#endif

/**
* @tc.name: UpdateAVQueueInfo001
* @tc.desc: update avqueue info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AvsessionTest, UpdateAVQueueInfo001, TestSize.Level1)
{
    SLOGD("UpdateAVQueueInfo001 Begin");
    AVQueueInfo info = AVQueueInfo();
    EXPECT_EQ(avsession_->UpdateAVQueueInfo(info), AVSESSION_SUCCESS);
    SLOGD("UpdateAVQueueInfo001 End");
}

/**
* @tc.name: AVSessionDemoUpdateAVQueueInfo001
* @tc.desc: create AVSessionDemo and UpdateAVQueueInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AvsessionTest, AVSessionDemoUpdateAVQueueInfo001, TestSize.Level1)
{
    SLOGE("AVSessionDemoUpdateAVQueueInfo001 Begin");
    AVSessionDemo avsessionDemo = AVSessionDemo();
    AVQueueInfo info = AVQueueInfo();
    EXPECT_EQ(avsessionDemo.UpdateAVQueueInfo(info), AVSESSION_SUCCESS);
    SLOGE("AVSessionDemoUpdateAVQueueInfo001 End");
}
} // namespace AVSession
} // namespace OHOS
