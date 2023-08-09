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
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "cast_session_manager.h"
#include "avcast_controller_item.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "hw_cast_provider.h"
#include "hw_cast_stream_player.h"

using namespace testing::ext;
using namespace OHOS::CastEngine::CastEngineClient;
using namespace OHOS::CastEngine;

namespace OHOS {
namespace AVSession {
class HwCastStreamPlayerTest : public testing::TestWithParam<int> {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<HwCastProviderSession> hwCastProviderSession = nullptr;
    std::shared_ptr<HwCastStreamPlayer> hwCastStreamPlayer = nullptr;
};

class TestCastSessionManagerListener : public ICastSessionManagerListener {
public:
    void OnDeviceFound(const std::vector<CastRemoteDevice> &deviceList) override
    {
        static_cast<void>(deviceList);
    }
    void OnSessionCreated(const std::shared_ptr<ICastSession> &castSession) override
    {
        static_cast<void>(castSession);
    }
    void OnServiceDied() override {}
    void OnDeviceOffline(const std::string &deviceId) override
    {
        static_cast<void>(deviceId);
    }
};

std::shared_ptr<ICastSession> CreateSession()
{
    std::shared_ptr<ICastSession> session;
    auto listener = std::make_shared<TestCastSessionManagerListener>();
    CastSessionManager::GetInstance().RegisterListener(listener);
    CastSessionProperty property = {CastEngine::ProtocolType::CAST_PLUS_STREAM, CastEngine::EndType::CAST_SOURCE};
    CastSessionManager::GetInstance().CreateCastSession(property, session);
    return session;
}

std::shared_ptr<AVMediaDescription> CreateAVMediaDescription()
{
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->Reset();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("SubTitle");
    description->SetDescription("This is music description");
    description->SetIcon(nullptr);
    description->SetIconUri("xxxxx");
    description->SetExtras(nullptr);
    return description;
}

void HwCastStreamPlayerTest::SetUpTestCase()
{}

void HwCastStreamPlayerTest::TearDownTestCase()
{}

void HwCastStreamPlayerTest::SetUp()
{
    constexpr int castPermissionNum = 2;
    const char *perms[castPermissionNum] = {
        "ohos.permission.ACCESS_CAST_ENGINE_MIRROR",
        "ohos.permission.ACCESS_CAST_ENGINE_STREAM",
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,  // Indicates the capsbility list of the sa.
        .permsNum = castPermissionNum,
        .aclsNum = 0,   // acls is the list of rights that can be escalated.
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "hw_cast_stream_player_test",
        .aplStr = "system_basic",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    std::shared_ptr<ICastSession> castSession = CreateSession();
    hwCastProviderSession = std::make_shared<HwCastProviderSession>(castSession);
    if (hwCastProviderSession) {
        hwCastProviderSession->Init();
    }
    std::shared_ptr<IStreamPlayer> streamPlayer = hwCastProviderSession->CreateStreamPlayer();
    hwCastStreamPlayer = std::make_shared<HwCastStreamPlayer>(streamPlayer);
    if (hwCastStreamPlayer) {
        hwCastStreamPlayer->Init();
    }
}

void HwCastStreamPlayerTest::TearDown()
{
    if (hwCastProviderSession) {
        hwCastProviderSession->Release();
    }
    if (hwCastStreamPlayer) {
        hwCastStreamPlayer->Release();
    }
}

INSTANTIATE_TEST_CASE_P(SendControlCommand, HwCastStreamPlayerTest, testing::Values(
    AVCastControlCommand::CAST_CONTROL_CMD_INVALID,
    AVCastControlCommand::CAST_CONTROL_CMD_PLAY,
    AVCastControlCommand::CAST_CONTROL_CMD_PAUSE,
    AVCastControlCommand::CAST_CONTROL_CMD_STOP,
    AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT,
    AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS,
    AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD,
    AVCastControlCommand::CAST_CONTROL_CMD_REWIND,
    AVCastControlCommand::CAST_CONTROL_CMD_SEEK,
    AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME,
    AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED,
    AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE,
    AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_FAVORITE,
    AVCastControlCommand::CAST_CONTROL_CMD_MAX
));

/**
 * @tc.name: SendControlCommand001
 * @tc.desc: SendControlCommand all test
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_P(HwCastStreamPlayerTest, SendControlCommand001, TestSize.Level1)
{
    SLOGI("SendControlCommand001 begin!");
    AVCastControlCommand command;
    int32_t cmd = GetParam();
    if (cmd == AVCastControlCommand::CAST_CONTROL_CMD_INVALID || cmd == AVCastControlCommand::CAST_CONTROL_CMD_MAX) {
        ASSERT_EQ(command.SetCommand(cmd), ERR_INVALID_PARAM);
    } else {
        ASSERT_EQ(command.SetCommand(cmd), AVSESSION_SUCCESS);
    }
    hwCastStreamPlayer->SendControlCommand(command);
    SLOGI("SendControlCommand001 end!");
}

/**
 * @tc.name: Start001
 * @tc.desc: start no media id and fd src
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Start001, TestSize.Level1)
{
    SLOGI("Start001 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("Start001 end!");
}

/**
 * @tc.name: Start002
 * @tc.desc: start with fd src
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Start002, TestSize.Level1)
{
    SLOGI("Start002 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    AVFileDescriptor avFileDescriptor;
    avFileDescriptor.fd_ = 100;
    description->SetFdSrc(avFileDescriptor);
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_ERROR);
    SLOGI("Start002 end!");
}

/**
 * @tc.name: Start003
 * @tc.desc: start same media
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Start003, TestSize.Level1)
{
    SLOGI("Start003 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("Media url");
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    hwCastStreamPlayer->Start(avQueueItem);
    SLOGI("Start003 end!");
}

/**
 * @tc.name: Prepare001
 * @tc.desc: prepare no media id and fd src
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Prepare001, TestSize.Level1)
{
    SLOGI("Prepare001 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    ret = hwCastStreamPlayer->Prepare(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("Prepare001 end!");
}

/**
 * @tc.name: Prepare002
 * @tc.desc: prepare with fd src
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Prepare002, TestSize.Level1)
{
    SLOGI("Prepare002 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    AVFileDescriptor avFileDescriptor;
    avFileDescriptor.fd_ = 100;
    description->SetFdSrc(avFileDescriptor);
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_ERROR);
    ret = hwCastStreamPlayer->Prepare(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_ERROR);
    SLOGI("Prepare002 end!");
}

/**
 * @tc.name: GetDuration001
 * @tc.desc: GetDuration
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, GetDuration001, TestSize.Level1)
{
    SLOGI("GetDuration001 begin!");
    int32_t duration = 40000;
    ASSERT_EQ(hwCastStreamPlayer->GetDuration(duration), AVSESSION_SUCCESS);
    SLOGI("GetDuration001 end!");
}

/**
 * @tc.name: GetCastAVPlaybackState001
 * @tc.desc: GetCastAVPlaybackState
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, GetCastAVPlaybackState001, TestSize.Level1)
{
    SLOGI("GetCastAVPlaybackState001 begin!");
    AVPlaybackState state;
    ASSERT_EQ(hwCastStreamPlayer->GetCastAVPlaybackState(state), AVSESSION_SUCCESS);
    SLOGI("GetCastAVPlaybackState001 end!");
}

/**
 * @tc.name: SetDisplaySurface001
 * @tc.desc: SetDisplaySurface
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, SetDisplaySurface001, TestSize.Level1)
{
    SLOGI("SetDisplaySurface001 begin!");
    std::string surfaceId = "surfaceId";
    ASSERT_EQ(hwCastStreamPlayer->SetDisplaySurface(surfaceId), AVSESSION_SUCCESS);
    SLOGI("SetDisplaySurface001 end!");
}

/**
 * @tc.name: RegisterControllerListener001
 * @tc.desc: RegisterControllerListener invalid listener
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, RegisterControllerListener001, TestSize.Level1)
{
    SLOGI("RegisterControllerListener001 begin!");
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(nullptr), AVSESSION_ERROR);
    SLOGI("RegisterControllerListener001 end!");
}

/**
 * @tc.name: RegisterControllerListener002
 * @tc.desc: RegisterControllerListener repeat
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, RegisterControllerListener002, TestSize.Level1)
{
    SLOGI("RegisterControllerListener002 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_ERROR);
    SLOGI("RegisterControllerListener002 end!");
}

/**
 * @tc.name: UnRegisterControllerListener001
 * @tc.desc: UnRegisterControllerListener invalid listener
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, UnRegisterControllerListener001, TestSize.Level1)
{
    SLOGI("UnRegisterControllerListener001 begin!");
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(nullptr), AVSESSION_ERROR);
    SLOGI("UnRegisterControllerListener001 end!");
}

/**
 * @tc.name: UnRegisterControllerListener002
 * @tc.desc: UnRegisterControllerListener success
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, UnRegisterControllerListener002, TestSize.Level1)
{
    SLOGI("UnRegisterControllerListener002 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("UnRegisterControllerListener002 end!");
}

/**
 * @tc.name: UnRegisterControllerListener003
 * @tc.desc: UnRegisterControllerListener failed
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, UnRegisterControllerListener003, TestSize.Level1)
{
    SLOGI("UnRegisterControllerListener003 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem1 = std::make_shared<AVCastControllerItem>();
    std::shared_ptr<AVCastControllerItem> avCastControllerItem2 = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem1), AVSESSION_SUCCESS);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem2), AVSESSION_ERROR);
    SLOGI("UnRegisterControllerListener003 end!");
}

/**
 * @tc.name: OnStateChanged001
 * @tc.desc: OnStateChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnStateChanged001, TestSize.Level1)
{
    SLOGI("OnStateChanged001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnStateChanged(CastEngine::PlayerStates::PLAYER_INITIALIZED, true);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnStateChanged001 end!");
}

/**
 * @tc.name: OnPositionChanged001
 * @tc.desc: OnPositionChanged invalid
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPositionChanged001, TestSize.Level1)
{
    SLOGI("OnPositionChanged001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnPositionChanged(-1, -1, -1);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnPositionChanged001 end!");
}

/**
 * @tc.name: OnPositionChanged002
 * @tc.desc: OnPositionChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPositionChanged002, TestSize.Level1)
{
    SLOGI("OnPositionChanged002 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnPositionChanged(0, 0, 10);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnPositionChanged002 end!");
}

/**
 * @tc.name: OnMediaItemChanged001
 * @tc.desc: OnMediaItemChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnMediaItemChanged001, TestSize.Level1)
{
    SLOGI("OnMediaItemChanged001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    CastEngine::MediaInfo mediaInfo;
    hwCastStreamPlayer->OnMediaItemChanged(mediaInfo);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnMediaItemChanged001 end!");
}

/**
 * @tc.name: OnNextRequest001
 * @tc.desc: OnNextRequest
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnNextRequest001, TestSize.Level1)
{
    SLOGI("OnNextRequest001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnNextRequest();
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnNextRequest001 end!");
}

/**
 * @tc.name: OnPreviousRequest001
 * @tc.desc: OnPreviousRequest
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPreviousRequest001, TestSize.Level1)
{
    SLOGI("OnPreviousRequest001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnPreviousRequest();
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnPreviousRequest001 end!");
}

/**
 * @tc.name: OnVolumeChanged001
 * @tc.desc: OnVolumeChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnVolumeChanged001, TestSize.Level1)
{
    SLOGI("OnVolumeChanged001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnVolumeChanged(5, 15);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnVolumeChanged001 end!");
}

/**
 * @tc.name: OnLoopModeChanged001
 * @tc.desc: OnLoopModeChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnLoopModeChanged001, TestSize.Level1)
{
    SLOGI("OnLoopModeChanged001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnLoopModeChanged(CastEngine::LoopMode::LOOP_MODE_SINGLE);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnLoopModeChanged001 end!");
}

/**
 * @tc.name: OnPlaySpeedChanged001
 * @tc.desc: OnPlaySpeedChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPlaySpeedChanged001, TestSize.Level1)
{
    SLOGI("OnPlaySpeedChanged001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnPlaySpeedChanged(CastEngine::PlaybackSpeed::SPEED_FORWARD_2_00_X);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnPlaySpeedChanged001 end!");
}

/**
 * @tc.name: OnPlayerError001
 * @tc.desc: OnPlayerError
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPlayerError001, TestSize.Level1)
{
    SLOGI("OnPlayerError001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnPlayerError(10003, "PLAYER_ERROR");
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnPlayerError001 end!");
}

/**
 * @tc.name: OnSeekDone001
 * @tc.desc: OnSeekDone
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnSeekDone001, TestSize.Level1)
{
    SLOGI("OnSeekDone001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    int32_t seekNumber = 0;
    hwCastStreamPlayer->OnSeekDone(seekNumber);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnSeekDone001 end!");
}

/**
 * @tc.name: OnVideoSizeChanged001
 * @tc.desc: OnVideoSizeChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnVideoSizeChanged001, TestSize.Level1)
{
    SLOGI("OnVideoSizeChanged001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnVideoSizeChanged(0, 0);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnVideoSizeChanged001 end!");
}

/**
 * @tc.name: OnEndOfStream001
 * @tc.desc: OnEndOfStream
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnEndOfStream001, TestSize.Level1)
{
    SLOGI("OnEndOfStream001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    hwCastStreamPlayer->OnEndOfStream(0);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnEndOfStream001 end!");
}
} // namespace AVSession
} // namespace OHOS
