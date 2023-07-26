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

#include "avsession_manager.h"
#include "avsession_errors.h"
#include "want_agent.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avsession_log.h"
#include "avcontrol_command.h"
#include "avcast_control_command.h"
#include "iavcast_controller.h"
#include "avcast_controller_item.h"
#include "hw_cast_stream_player.h"

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

class AVCastControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AVSession> avsession_ = nullptr;
    std::shared_ptr<AVSessionController> controller_ = nullptr;
    std::shared_ptr<AVCastControllerItem> castController_ = std::make_shared<AVCastControllerItem>();

    static constexpr int SESSION_LEN = 64;
};

void AVCastControllerTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVCastControllerTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVCastControllerTest::SetUp()
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

    std::shared_ptr<HwCastStreamPlayer> HwCastStreamPlayer_ = std::make_shared<HwCastStreamPlayer>(nullptr);
    castController_->Init(HwCastStreamPlayer_);
}

void AVCastControllerTest::TearDown()
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

class AVCastControllerCallbackImpl : public AVCastControllerCallback {
public:
    void OnCastPlaybackStateChange(const AVPlaybackState& state) override;

    void OnMediaItemChange(const AVQueueItem& avQueueItem) override;

    void OnPlayNext() override;

    void OnPlayPrevious() override;

    void OnSeekDone(const int32_t seekNumber) override;

    void OnVideoSizeChange(const int32_t width, const int32_t height) override;

    void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) override;

    ~AVCastControllerCallbackImpl() override;

    AVPlaybackState state_;
    AVQueueItem avQueueItem_;
    int32_t seekNumber_;
    int32_t width_;
    int32_t height_;
    int32_t errorCode_;
    std::string errorMsg_;
};

AVCastControllerCallbackImpl::~AVCastControllerCallbackImpl()
{
}

void AVCastControllerCallbackImpl::OnCastPlaybackStateChange(const AVPlaybackState& state)
{
    state_ = state;
}

void AVCastControllerCallbackImpl::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    avQueueItem_ = avQueueItem;
}

void AVCastControllerCallbackImpl::OnPlayNext()
{
}

void AVCastControllerCallbackImpl::OnPlayPrevious()
{
}

void AVCastControllerCallbackImpl::OnSeekDone(const int32_t seekNumber)
{
    seekNumber_ = seekNumber;
}

void AVCastControllerCallbackImpl::OnVideoSizeChange(const int32_t width, const int32_t height)
{
    width_ = width;
    height_ = height;
}

void AVCastControllerCallbackImpl::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{
    errorCode_ = errorCode;
    errorMsg_ = errorMsg;
}

/**
* @tc.name: SendControlCommand001
* @tc.desc: send command, check if AVCastControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand001, TestSize.Level1)
{
    AVCastControlCommand command;
    EXPECT_EQ(command.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_INVALID), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_MAX), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetForwardTime(0), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetRewindTime(-1), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetSeekTime(-1), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetSpeed(-1), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetLoopMode(-1), ERR_INVALID_PARAM);
}

/**
* @tc.name: SendControlCommand002
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand002, TestSize.Level1)
{
    AVCastControlCommand command;
    int32_t mode = -1;
    OHOS::Parcel parcel;
    EXPECT_EQ(command.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetLoopMode(AVPlaybackState::LOOP_MODE_SEQUENCE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.Marshalling(parcel), true);
    AVCastControlCommand *ret = AVCastControlCommand::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->GetCommand(), AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE);
    EXPECT_EQ(ret->GetLoopMode(mode), AVSESSION_SUCCESS);
    EXPECT_EQ(mode, AVPlaybackState::LOOP_MODE_SEQUENCE);
    delete ret;
}

/**
* @tc.name: SendControlCommand003
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand003, TestSize.Level1)
{
    AVCastControlCommand command;
    int32_t speed = -1;
    OHOS::Parcel parcel;
    EXPECT_EQ(command.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetSpeed(1), AVSESSION_SUCCESS);
    EXPECT_EQ(command.Marshalling(parcel), true);
    AVCastControlCommand *ret = AVCastControlCommand::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->GetCommand(), AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED);
    EXPECT_EQ(ret->GetSpeed(speed), AVSESSION_SUCCESS);
    EXPECT_EQ(speed, 1);
    delete ret;
}

/**
* @tc.name: SendControlCommand004
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand004, TestSize.Level1)
{
    AVCastControlCommand command;
    int32_t volumn = -1;
    OHOS::Parcel parcel;
    EXPECT_EQ(command.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetVolume(1), AVSESSION_SUCCESS);
    EXPECT_EQ(command.Marshalling(parcel), true);
    AVCastControlCommand *ret = AVCastControlCommand::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->GetCommand(), AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME);
    EXPECT_EQ(ret->GetVolume(volumn), AVSESSION_SUCCESS);
    EXPECT_EQ(volumn, 1);
    delete ret;
}

/**
* @tc.name: SendControlCommand005
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand005, TestSize.Level1)
{
    AVCastControlCommand command;
    int32_t seek = -1;
    OHOS::Parcel parcel;
    EXPECT_EQ(command.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_SEEK), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetSeekTime(1), AVSESSION_SUCCESS);
    EXPECT_EQ(command.Marshalling(parcel), true);
    AVCastControlCommand *ret = AVCastControlCommand::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->GetCommand(), AVCastControlCommand::CAST_CONTROL_CMD_SEEK);
    EXPECT_EQ(ret->GetSeekTime(seek), AVSESSION_SUCCESS);
    EXPECT_EQ(seek, 1);
    delete ret;
}

/**
* @tc.name: SendControlCommand006
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand006, TestSize.Level1)
{
    AVCastControlCommand command;
    int32_t rewind = -1;
    OHOS::Parcel parcel;
    EXPECT_EQ(command.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_REWIND), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetRewindTime(1), AVSESSION_SUCCESS);
    EXPECT_EQ(command.Marshalling(parcel), true);
    AVCastControlCommand *ret = AVCastControlCommand::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->GetCommand(), AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
    EXPECT_EQ(ret->GetRewindTime(rewind), AVSESSION_SUCCESS);
    EXPECT_EQ(rewind, 1);
    delete ret;
}

/**
* @tc.name: SendControlCommand007
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand007, TestSize.Level1)
{
    AVCastControlCommand command;
    int32_t forward = -1;
    OHOS::Parcel parcel;
    EXPECT_EQ(command.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetForwardTime(1), AVSESSION_SUCCESS);
    EXPECT_EQ(command.Marshalling(parcel), true);
    AVCastControlCommand *ret = AVCastControlCommand::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->GetCommand(), AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
    EXPECT_EQ(ret->GetForwardTime(forward), AVSESSION_SUCCESS);
    EXPECT_EQ(forward, 1);
    delete ret;
}

/**
* @tc.name: SendControlCommand008
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand008, TestSize.Level1)
{
    AVCastControlCommand command;
    EXPECT_EQ(castController_->SendControlCommand(command), AVSESSION_SUCCESS);
}
} // namespace AVSession
} // namespace OHOS