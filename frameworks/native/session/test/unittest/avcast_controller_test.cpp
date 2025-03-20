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

#include "accesstoken_kit.h"
#include "bool_wrapper.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "want_agent.h"
#include "avcast_control_command.h"
#include "avcast_controller_item.h"
#include "avmedia_description.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avqueue_item.h"
#include "avsession_manager.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "hw_cast_stream_player.h"
#include "iavcast_controller.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#define private public
#include "hw_cast_provider.h"
#undef private

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
static std::string g_errLog;
sptr<AVCastControllerCallbackProxy> g_AVCastControllerCallbackProxy {nullptr};

void MyLogCallback(const LogType type, const LogLevel level,
    const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}

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
    std::vector<int32_t> supportedCastCmd_;

    static constexpr int SESSION_LEN = 64;
};

void AVCastControllerTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);

    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGI("failed to get sa mgr");
        return;
    }
    auto object = mgr->GetSystemAbility(OHOS::AVSESSION_SERVICE_ID);
    if (object == nullptr) {
        SLOGI("failed to get service");
        return;
    }
    g_AVCastControllerCallbackProxy = iface_cast<AVCastControllerCallbackProxy>(object);
    ASSERT_TRUE(g_AVCastControllerCallbackProxy != nullptr);
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
    auto validCallback = [this](int32_t cmd, std::vector<int32_t>& supportedCastCmds) {
        SLOGI("add cast valid command %{public}d", cmd);
        supportedCastCmds = supportedCastCmd_;
        return;
    };
    auto preparecallback = []() {
        SLOGI("prepare callback");
    };
    castController_->Init(HwCastStreamPlayer_, validCallback, preparecallback);
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
    
    void OnCastValidCommandChanged(const std::vector<int32_t> &cmds) override;

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

void AVCastControllerCallbackImpl::OnCastValidCommandChanged(const std::vector<int32_t> &cmds)
{
}

class AVCastControllerProxyMock : public IAVCastControllerProxy {
public:
    void Release() {};
    int32_t RegisterControllerListener(const std::shared_ptr<IAVCastControllerProxyListener>
        iAVCastControllerProxyListener) {return 0;}
    int32_t UnRegisterControllerListener(const std::shared_ptr<IAVCastControllerProxyListener>
        iAVCastControllerProxyListener) {return 0;}
    AVQueueItem GetCurrentItem() {return AVQueueItem();}
    int32_t Start(const AVQueueItem& avQueueItem) {return 0;}
    int32_t Prepare(const AVQueueItem& avQueueItem) {return 0;}
    void SendControlCommand(const AVCastControlCommand cmd) {}
    int32_t GetDuration(int32_t& duration) {return 0;}
    int32_t GetCastAVPlaybackState(AVPlaybackState& avPlaybackState) {return 0;}
    int32_t SetValidAbility(const std::vector<int32_t>& validAbilityList) {return 0;}
    int32_t GetValidAbility(std::vector<int32_t> &validAbilityList) {return 0;}
    int32_t SetDisplaySurface(std::string& surfaceId) {return 0;}
    int32_t ProcessMediaKeyResponse(const std::string& assetId, const std::vector<uint8_t>& response) {return 0;}
    int32_t GetSupportedDecoders(std::vector<std::string>& decoderTypes) {return 0;}
    int32_t GetRecommendedResolutionLevel(std::string& decoderType, ResolutionLevel& resolutionLevel) {return 0;}
    int32_t GetSupportedHdrCapabilities(std::vector<HDRFormat>& hdrFormats) {return 0;}
    int32_t GetSupportedPlaySpeeds(std::vector<float>& playSpeeds) {return 0;}
};

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
* @tc.desc: send command, check if AVCastControlCommand is invalid
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
    ret = nullptr;
}

/**
* @tc.name: SendControlCommand003
* @tc.desc: send command, check if AVCastControlCommand is invalid
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
    ret = nullptr;
}

/**
* @tc.name: SendControlCommand004
* @tc.desc: send command, check if AVCastControlCommand is invalid
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
    ret = nullptr;
}

/**
* @tc.name: SendControlCommand005
* @tc.desc: send command, check if AVCastControlCommand is invalid
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
    ret = nullptr;
}

/**
* @tc.name: SendControlCommand006
* @tc.desc: send command, check if AVCastControlCommand is invalid
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
    ret = nullptr;
}

/**
* @tc.name: SendControlCommand007
* @tc.desc: send command, check if AVCastControlCommand is invalid
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
    ret = nullptr;
}

/**
* @tc.name: SendControlCommand008
* @tc.desc: send command, check if AVCastControlCommand is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SendControlCommand008, TestSize.Level1)
{
    AVCastControlCommand command;
    EXPECT_EQ(castController_->SendControlCommand(command), AVSESSION_SUCCESS);
}

/**
* @tc.name: Start001
* @tc.desc: Start
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, Start001, TestSize.Level1)
{
    AVQueueItem avQueueItem;
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("Subtitle");
    description->SetDescription("This is music description");
    description->SetIcon(nullptr);
    description->SetIconUri("xxxxx");
    description->SetExtras(nullptr);
    description->SetMediaUri("Media url");
    avQueueItem.SetDescription(description);
    EXPECT_EQ(castController_->Start(avQueueItem), AVSESSION_SUCCESS);
}

/**
* @tc.name: Prepare001
* @tc.desc: Prepare
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, Prepare001, TestSize.Level1)
{
    AVQueueItem avQueueItem;
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("Subtitle");
    description->SetDescription("This is music description");
    description->SetIcon(nullptr);
    description->SetIconUri("xxxxx");
    description->SetExtras(nullptr);
    description->SetMediaUri("Media url");
    avQueueItem.SetDescription(description);
    EXPECT_EQ(castController_->Prepare(avQueueItem), AVSESSION_SUCCESS);
}

/**
* @tc.name: GetDuration001
* @tc.desc: GetDuration
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, GetDuration001, TestSize.Level1)
{
    int32_t duration;
    EXPECT_EQ(castController_->GetDuration(duration), AVSESSION_ERROR);
}

/**
* @tc.name: GetCastAVPlaybackState001
* @tc.desc: GetCastAVPlaybackState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, GetCastAVPlaybackState001, TestSize.Level1)
{
    AVPlaybackState avPlaybackState;
    EXPECT_EQ(castController_->GetCastAVPlaybackState(avPlaybackState), AVSESSION_ERROR);
}

/**
* @tc.name: GetCurrentItem001
* @tc.desc: GetCurrentItem
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, GetCurrentItem001, TestSize.Level1)
{
    AVQueueItem currentItem;
    EXPECT_EQ(castController_->GetCurrentItem(currentItem), AVSESSION_SUCCESS);
}

/**
* @tc.name: GetValidCommands001
* @tc.desc: GetValidCommands
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, GetValidCommands001, TestSize.Level1)
{
    std::vector<int32_t> cmds;
    EXPECT_EQ(castController_->GetValidCommands(cmds), AVSESSION_SUCCESS);
}

/**
* @tc.name: SetDisplaySurface001
* @tc.desc: SetDisplaySurface
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SetDisplaySurface001, TestSize.Level1)
{
    std::string surfaceId = "surfaceId";
    EXPECT_EQ(castController_->SetDisplaySurface(surfaceId), AVSESSION_ERROR);
}

/**
* @tc.name: ProcessMediaKeyResponse001
* @tc.desc: ProcessMediaKeyResponse
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, ProcessMediaKeyResponse001, TestSize.Level1)
{
    std::string assetId = "assetId";
    std::vector<uint8_t> response;
    EXPECT_EQ(castController_->ProcessMediaKeyResponse(assetId, response), AVSESSION_ERROR);
}

/**
* @tc.name: SetCastPlaybackFilter001
* @tc.desc: SetCastPlaybackFilter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SetCastPlaybackFilter001, TestSize.Level1)
{
    AVPlaybackState::PlaybackStateMaskType filter;
    EXPECT_EQ(castController_->SetCastPlaybackFilter(filter), AVSESSION_SUCCESS);
}

/**
* @tc.name: AddAvailableCommand001
* @tc.desc: AddAvailableCommand
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, AddAvailableCommand001, TestSize.Level1)
{
    EXPECT_EQ(castController_->AddAvailableCommand(0), AVSESSION_SUCCESS);
}

/**
* @tc.name: RemoveAvailableCommand001
* @tc.desc: RemoveAvailableCommand
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, RemoveAvailableCommand001, TestSize.Level1)
{
    EXPECT_EQ(castController_->AddAvailableCommand(0), AVSESSION_SUCCESS);
    EXPECT_EQ(castController_->RemoveAvailableCommand(0), AVSESSION_SUCCESS);
}

/**
* @tc.name: RegisterControllerListener001
* @tc.desc: RegisterControllerListener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, RegisterControllerListener001, TestSize.Level1)
{
    std::shared_ptr<IAVCastControllerProxy> castControllerProxy = nullptr;
    EXPECT_EQ(castController_->RegisterControllerListener(castControllerProxy), true);
}

/**
* @tc.name: Destroy001
* @tc.desc: Destroy
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, Destroy001, TestSize.Level1)
{
    EXPECT_EQ(castController_->Destroy(), AVSESSION_SUCCESS);
}

/**
* @tc.name: OnCastPlaybackStateChange001
* @tc.desc: OnCastPlaybackStateChange, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnCastPlaybackStateChange001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    AVPlaybackState state;
    castController_->OnCastPlaybackStateChange(state);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
* @tc.name: OnMediaItemChange001
* @tc.desc: OnMediaItemChange, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnMediaItemChange001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    AVQueueItem avQueueItem;
    castController_->OnMediaItemChange(avQueueItem);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
* @tc.name: OnPlayNext001
* @tc.desc: OnPlayNext, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnPlayNext001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->OnPlayNext();
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
* @tc.name: OnPlayPrevious001
* @tc.desc: OnPlayPrevious, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnPlayPrevious001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->OnPlayPrevious();
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
* @tc.name: OnSeekDone001
* @tc.desc: OnSeekDone, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnSeekDone001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    int32_t seekNumber = 0;
    castController_->OnSeekDone(seekNumber);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
* @tc.name: OnVideoSizeChange001
* @tc.desc: OnVideoSizeChange, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnVideoSizeChange001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    int32_t width = 0;
    int32_t height = 0;
    castController_->OnVideoSizeChange(width, height);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
* @tc.name: OnPlayerError001
* @tc.desc: OnPlayerError, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnPlayerError001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    int32_t errorCode = 0;
    std::string errorMsg = "errorMsg";
    castController_->OnPlayerError(errorCode, errorMsg);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
* @tc.name: StartCastDiscovery001
* @tc.desc: StartCastDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, StartCastDiscovery001, TestSize.Level1)
{
    EXPECT_EQ(AVSessionManager::GetInstance().StartCastDiscovery(1, {}), AVSESSION_SUCCESS);
}

/**
* @tc.name: StopCastDiscovery001
* @tc.desc: StopCastDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, StopCastDiscovery001, TestSize.Level1)
{
    EXPECT_EQ(AVSessionManager::GetInstance().StopCastDiscovery(), AVSESSION_SUCCESS);
}

/**
* @tc.name: SetDiscoverable001
* @tc.desc: SetDiscoverable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SetDiscoverable001, TestSize.Level1)
{
    EXPECT_EQ(AVSessionManager::GetInstance().SetDiscoverable(true), AVSESSION_SUCCESS);
}

/**
* @tc.name: StartCast001
* @tc.desc: StartCast
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, StartCast001, TestSize.Level1)
{
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "deviceId";
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    EXPECT_EQ(AVSessionManager::GetInstance().StartCast(sessionToken, outputDeviceInfo), -1007);
}

/**
* @tc.name: StopCast001
* @tc.desc: StopCast
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, StopCast001, TestSize.Level1)
{
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    EXPECT_EQ(AVSessionManager::GetInstance().StopCast(sessionToken), AVSESSION_SUCCESS);
}

HWTEST_F(AVCastControllerTest, StartDiscovery001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;
    std::vector<std::string> drmSchemes;
    EXPECT_EQ(hwCastProvider.StartDiscovery(2, drmSchemes), true);
}

HWTEST_F(AVCastControllerTest, StopDiscovery001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;
    hwCastProvider.StopDiscovery();
    EXPECT_TRUE(true);
}

HWTEST_F(AVCastControllerTest, Release001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;
    hwCastProvider.Release();
    EXPECT_TRUE(true);
}

HWTEST_F(AVCastControllerTest, StartCastSession001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;
    // StartCastSession may fail with -1003
    int32_t ret = hwCastProvider.StartCastSession();
    SLOGI("StartCastSession001 with ret %{public}d", ret);
    EXPECT_TRUE(ret != AVSESSION_SUCCESS);
}

HWTEST_F(AVCastControllerTest, StopCastSession001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;
    hwCastProvider.StopCastSession(2);
    EXPECT_TRUE(true);
}

HWTEST_F(AVCastControllerTest, AddCastDevice001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;

    DeviceInfo deviceInfo1;
    deviceInfo1.castCategory_ = 1;
    deviceInfo1.deviceId_ = "deviceid1";
    deviceInfo1.deviceName_ = "devicename1";
    deviceInfo1.deviceType_ = 1;
    deviceInfo1.ipAddress_ = "ipAddress1";
    deviceInfo1.providerId_ = 1;
    deviceInfo1.supportedProtocols_ = 3;
    deviceInfo1.authenticationStatus_ = 1;
    std::vector<std::string> supportedDrmCapabilities;
    supportedDrmCapabilities.emplace_back("");
    deviceInfo1.supportedDrmCapabilities_ = supportedDrmCapabilities;
    deviceInfo1.isLegacy_ = false;
    deviceInfo1.mediumTypes_ = 2;

    EXPECT_EQ(hwCastProvider.AddCastDevice(1, deviceInfo1), false);
}

HWTEST_F(AVCastControllerTest, RemoveCastDevice001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;

    DeviceInfo deviceInfo1;
    deviceInfo1.castCategory_ = 1;
    deviceInfo1.deviceId_ = "deviceid1";
    deviceInfo1.deviceName_ = "devicename1";
    deviceInfo1.deviceType_ = 1;
    deviceInfo1.ipAddress_ = "ipAddress1";
    deviceInfo1.providerId_ = 1;
    deviceInfo1.supportedProtocols_ = 1;
    deviceInfo1.authenticationStatus_ = 0;
    std::vector<std::string> supportedDrmCapabilities;
    supportedDrmCapabilities.emplace_back("");
    deviceInfo1.supportedDrmCapabilities_ = supportedDrmCapabilities;
    deviceInfo1.isLegacy_ = false;
    deviceInfo1.mediumTypes_ = 2;

    EXPECT_EQ(hwCastProvider.RemoveCastDevice(1, deviceInfo1), false);
}

HWTEST_F(AVCastControllerTest, RegisterCastStateListener001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;

    EXPECT_EQ(hwCastProvider.RegisterCastStateListener(nullptr), false);
}

HWTEST_F(AVCastControllerTest, UnRegisterCastStateListener001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;

    EXPECT_EQ(hwCastProvider.UnRegisterCastStateListener(nullptr), false);
}

HWTEST_F(AVCastControllerTest, RegisterCastSessionStateListener001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;

    EXPECT_EQ(hwCastProvider.RegisterCastSessionStateListener(2, nullptr), false);
}

HWTEST_F(AVCastControllerTest, UnRegisterCastSessionStateListener001, TestSize.Level1)
{
    HwCastProvider hwCastProvider;

    EXPECT_EQ(hwCastProvider.UnRegisterCastSessionStateListener(2, nullptr), false);
}

/**
* @tc.name: OnCastPlaybackStateChange002
* @tc.desc: OnCastPlaybackStateChange, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnCastPlaybackStateChange002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PREPARE);
    castController_->OnCastPlaybackStateChange(state);
    EXPECT_EQ(castController_->isPlayingState_, false);
}

/**
* @tc.name: OnCastPlaybackStateChange003
* @tc.desc: OnCastPlaybackStateChange, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnCastPlaybackStateChange003, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    castController_->castControllerProxy_ = std::make_shared<AVCastControllerProxyMock>();
    
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    castController_->OnCastPlaybackStateChange(state);
    EXPECT_EQ(castController_->isPlayingState_, true);
}

/**
* @tc.name: OnCastPlaybackStateChange003
* @tc.desc: OnCastPlaybackStateChange, have reigstered callback and session callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnCastPlaybackStateChange004, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    castController_->castControllerProxy_ = std::make_shared<AVCastControllerProxyMock>();
    castController_->sessionCallbackForCastNtf_ = [](std::string&, bool, bool)->void {};
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    castController_->OnCastPlaybackStateChange(state);
    EXPECT_EQ(castController_->isPlayingState_, true);
}

/**
* @tc.name: OnMediaItemChange002
* @tc.desc: OnMediaItemChange, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnMediaItemChange002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    AVQueueItem avQueueItem;
    castController_->OnMediaItemChange(avQueueItem);
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnPlayNext002
* @tc.desc: OnPlayNext, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnPlayNext002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    castController_->OnPlayNext();
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnPlayPrevious002
* @tc.desc: OnPlayPrevious, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnPlayPrevious002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    castController_->OnPlayPrevious();
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnSeekDone002
* @tc.desc: OnSeekDone, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnSeekDone002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    int32_t seekNumber = 0;
    castController_->OnSeekDone(seekNumber);
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnVideoSizeChange002
* @tc.desc: OnVideoSizeChange, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnVideoSizeChange002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    int32_t width = 0;
    int32_t height = 0;
    castController_->OnVideoSizeChange(width, height);
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnPlayerError002
* @tc.desc: OnPlayerError, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnPlayerError002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    int32_t errorCode = 0;
    std::string errorMsg = "errorMsg";
    castController_->OnPlayerError(errorCode, errorMsg);
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnEndOfStream001
* @tc.desc: OnEndOfStream, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnEndOfStream001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = nullptr;
    int32_t isLooping = true;
    castController_->OnEndOfStream(isLooping);
    EXPECT_TRUE(castController_->callback_ == nullptr);
}

/**
* @tc.name: OnEndOfStream002
* @tc.desc: OnEndOfStream, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnEndOfStream002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    int32_t isLooping = true;
    castController_->OnEndOfStream(isLooping);
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnPlayRequest001
* @tc.desc: OnPlayRequest, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnPlayRequest001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = nullptr;
    AVQueueItem avQueueItem;
    castController_->OnPlayRequest(avQueueItem);
    EXPECT_TRUE(castController_->callback_ == nullptr);
}

/**
* @tc.name: OnPlayRequest002
* @tc.desc: OnPlayRequest, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnPlayRequest002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    AVQueueItem avQueueItem;
    castController_->OnPlayRequest(avQueueItem);
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnKeyRequest001
* @tc.desc: OnKeyRequest, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnKeyRequest001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = nullptr;
    std::string assetId = "test";
    std::vector<uint8_t> keyRequestData {};
    castController_->OnKeyRequest(assetId, keyRequestData);
    EXPECT_TRUE(castController_->callback_ == nullptr);
}

/**
* @tc.name: OnKeyRequest002
* @tc.desc: OnKeyRequest, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnKeyRequest002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    std::string assetId = "test";
    std::vector<uint8_t> keyRequestData {};
    castController_->OnKeyRequest(assetId, keyRequestData);
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: onDataSrcRead001
* @tc.desc: onDataSrcRead, no callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, onDataSrcRead001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = nullptr;
    std::shared_ptr<AVSharedMemory> mem = nullptr;
    uint32_t length = 0;
    int64_t pos = 0;
    castController_->onDataSrcRead(mem, length, pos);
    EXPECT_TRUE(castController_->callback_ == nullptr);
}

/**
* @tc.name: onDataSrcRead002
* @tc.desc: onDataSrcRead, have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, onDataSrcRead002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    std::shared_ptr<AVSharedMemory> mem = nullptr;
    uint32_t length = 0;
    int64_t pos = 0;
    castController_->onDataSrcRead(mem, length, pos);
    EXPECT_TRUE(castController_->callback_ != nullptr);
}

/**
* @tc.name: OnCastPlaybackStateChange005
* @tc.desc: success to copy and no registrered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnCastPlaybackStateChange005, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::string bits = std::string(14ULL, '1');
    castController_->castPlaybackMask_ = std::bitset<14ULL>(bits);
    castController_->callback_ = nullptr;
    castController_->currentState_ = AVPlaybackState::PLAYBACK_STATE_INITIAL;
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PAUSE);
    castController_->OnCastPlaybackStateChange(state);
    EXPECT_TRUE(state.GetState() != AVPlaybackState::PLAYBACK_STATE_PLAY);
}

/**
* @tc.name: OnCastPlaybackStateChange006
* @tc.desc: have no reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnCastPlaybackStateChange006, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::string bits = std::string(14ULL, '1');
    castController_->castPlaybackMask_ = std::bitset<14ULL>(bits);
    castController_->callback_ = nullptr;
    castController_->currentState_ = AVPlaybackState::PLAYBACK_STATE_INITIAL;
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    castController_->OnCastPlaybackStateChange(state);
    EXPECT_TRUE(castController_->isPlayingState_);
    EXPECT_TRUE(state.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAY);
}

/**
* @tc.name: OnCastPlaybackStateChange007
* @tc.desc: success to CopyToByMask and have no reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnCastPlaybackStateChange007, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::string bits = std::string(14ULL, '1');
    castController_->castPlaybackMask_ = std::bitset<14ULL>(bits);
    castController_->callback_ = nullptr;
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    castController_->currentState_ = state.GetState();
    castController_->OnCastPlaybackStateChange(state);
    AVPlaybackState stateOut;
    EXPECT_TRUE(state.CopyToByMask(castController_->castPlaybackMask_, stateOut));
}


/**
* @tc.name: OnCastPlaybackStateChange008
* @tc.desc: success to CopyToByMask and have reigstered callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, OnCastPlaybackStateChange008, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::string bits = std::string(14ULL, '1');
    castController_->castPlaybackMask_ = std::bitset<14ULL>(bits);
    castController_->callback_ = g_AVCastControllerCallbackProxy;
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    castController_->currentState_ = state.GetState();
    castController_->OnCastPlaybackStateChange(state);
    AVPlaybackState stateOut;
    EXPECT_TRUE(state.CopyToByMask(castController_->castPlaybackMask_, stateOut));
}
/**
* @tc.name: Prepare002
* @tc.desc: GetIcon is not nullptr but GetIconUri is failed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, Prepare002, TestSize.Level1)
{
    AVQueueItem avQueueItem;
    std::shared_ptr<AVSessionPixelMap> icon = std::make_shared<AVSessionPixelMap>();
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("Subtitle");
    description->SetDescription("This is music description");
    description->SetIcon(icon);
    description->SetIconUri("test");
    description->SetExtras(nullptr);
    description->SetMediaUri("Media url");
    avQueueItem.SetDescription(description);
    EXPECT_EQ(castController_->Prepare(avQueueItem), AVSESSION_SUCCESS);
}

/**
* @tc.name: Prepare003
* @tc.desc: GetIcon is not nullptr and GetIconUri is successed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, Prepare003, TestSize.Level1)
{
    AVQueueItem avQueueItem;
    std::shared_ptr<AVSessionPixelMap> icon = std::make_shared<AVSessionPixelMap>();
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("Subtitle");
    description->SetDescription("This is music description");
    description->SetIcon(icon);
    description->SetIconUri("URI_CACHE");
    description->SetExtras(nullptr);
    description->SetMediaUri("Media url");
    avQueueItem.SetDescription(description);
    EXPECT_EQ(castController_->Prepare(avQueueItem), AVSESSION_SUCCESS);
}

/**
* @tc.name: Prepare004
* @tc.desc: callback is registered and isPlayingState is false
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, Prepare004, TestSize.Level1)
{
    AVQueueItem avQueueItem;
    std::shared_ptr<AVSessionPixelMap> icon = std::make_shared<AVSessionPixelMap>();
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("Subtitle");
    description->SetDescription("This is music description");
    description->SetIcon(icon);
    description->SetIconUri("URI_CACHE");
    description->SetExtras(nullptr);
    description->SetMediaUri("Media url");
    avQueueItem.SetDescription(description);
    castController_->sessionCallbackForCastNtf_ = [](std::string&, bool, bool) -> void {};
    castController_->isPlayingState_ = false;
    EXPECT_EQ(castController_->Prepare(avQueueItem), AVSESSION_SUCCESS);
}

/**
* @tc.name: Prepare005
* @tc.desc: callback is registered and isPlayingState is true
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, Prepare005, TestSize.Level1)
{
    AVQueueItem avQueueItem;
    std::shared_ptr<AVSessionPixelMap> icon = std::make_shared<AVSessionPixelMap>();
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("Subtitle");
    description->SetDescription("This is music description");
    description->SetIcon(icon);
    description->SetIconUri("URI_CACHE");
    description->SetExtras(nullptr);
    description->SetMediaUri("Media url");
    avQueueItem.SetDescription(description);
    castController_->sessionCallbackForCastNtf_ = [](std::string&, bool, bool) -> void {};
    castController_->isPlayingState_ = true;
    EXPECT_EQ(castController_->Prepare(avQueueItem), AVSESSION_SUCCESS);
}

/**
* @tc.name: SetQueueItemDataSrc001
* @tc.desc: callback is registered and isPlayingState is true
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, SetQueueItemDataSrc001, TestSize.Level1)
{
    AVDataSrcDescriptor dataSrc;
    dataSrc.hasCallback = true;
    dataSrc.callback_ = [](void*, uint32_t, int64_t) -> int32_t { return 0; };
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetDataSrc(dataSrc);
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    castController_->sessionCallbackForCastNtf_ = [](std::string&, bool, bool) -> void {};
    castController_->isPlayingState_ = true;
    castController_->SetQueueItemDataSrc(avQueueItem);
    EXPECT_EQ(avQueueItem.GetDescription()->GetDataSrc().hasCallback, true);
}

/**
* @tc.name: CheckIfCancelCastCapsule001
* @tc.desc: state is avaiable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerTest, CheckIfCancelCastCapsule001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    castController_->currentState_ =  AVPlaybackState::PLAYBACK_STATE_PAUSE;
    castController_->castControllerProxy_ = std::make_shared<AVCastControllerProxyMock>();
    castController_->CheckIfCancelCastCapsule();
    EXPECT_EQ(castController_->IsStopState(castController_->currentState_), true);
}

} // namespace AVSession
} // namespace OHOS