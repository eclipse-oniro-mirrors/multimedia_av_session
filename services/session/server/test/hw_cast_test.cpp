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
#include <memory>
#include "avsession_errors.h"
#include "avsession_log.h"
#include "hw_cast_stream_player.h"
#include "hw_cast_provider.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class IAVCastSessionStateListenerTest : public IAVCastSessionStateListener {
public:
    IAVCastSessionStateListenerTest() = default;
    virtual ~IAVCastSessionStateListenerTest() = default;
    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo) override {};
    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg) override {};
};

class HwCastTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HwCastTest::SetUpTestCase()
{}

void HwCastTest::TearDownTestCase()
{}

void HwCastTest::SetUp()
{}

void HwCastTest::TearDown()
{}

/**
 * @tc.name: HwCastStreamPlayerInit001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerInit001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerInit001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    SLOGI("HwCastStreamPlayerInit001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerRelease001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerRelease001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerRelease001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Release();
    SLOGI("HwCastStreamPlayerRelease001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommand001
 * @tc.desc: cmd : CAST_CONTROL_CMD_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommand001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommand001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_INVALID);
    streamplayer->SendControlCommand(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommand001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommand002
 * @tc.desc: cmd : CAST_CONTROL_CMD_PLAY
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommand002, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommand002 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
    streamplayer->SendControlCommand(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommand002 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommand003
 * @tc.desc: cmd : CAST_CONTROL_CMD_PAUSE
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommand003, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommand003 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PAUSE);
    streamplayer->SendControlCommand(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommand003 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommand004
 * @tc.desc: cmd : CAST_CONTROL_CMD_STOP
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommand004, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommand004 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_STOP);
    streamplayer->SendControlCommand(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommand004 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommand005
 * @tc.desc: cmd : CAST_CONTROL_CMD_PLAY_NEXT
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommand005, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommand005 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
    streamplayer->SendControlCommand(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommand005 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommand006
 * @tc.desc: cmd : CAST_CONTROL_CMD_PLAY_PREVIOUS
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommand006, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommand006 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS);
    streamplayer->SendControlCommand(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommand006 end!");
}

/**
 * @tc.name: HwCastStreamPlayerGetCurrentItem001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerGetCurrentItem001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerGetCurrentItem001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVQueueItem item = streamplayer->GetCurrentItem();
    SLOGI("HwCastStreamPlayerGetCurrentItem001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerStart001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerStart001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerStart001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVQueueItem item;
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("Subtitle");
    description->SetDescription("This is music description");
    description->SetIcon(nullptr);
    description->SetIconUri("xxxxx");
    description->SetExtras(nullptr);
    description->SetMediaUri("Media url");
    item.SetDescription(description);
    int32_t ret = streamplayer->Start(item);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("HwCastStreamPlayerStart001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerPrepare001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerPrepare001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerPrepare001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVQueueItem item;
    std::shared_ptr<AVMediaDescription> description = std::make_shared<AVMediaDescription>();
    description->SetMediaId("123");
    description->SetTitle("Title");
    description->SetSubtitle("Subtitle");
    description->SetDescription("This is music description");
    description->SetIcon(nullptr);
    description->SetIconUri("xxxxx");
    description->SetExtras(nullptr);
    description->SetMediaUri("Media url");
    item.SetDescription(description);
    int32_t ret = streamplayer->Prepare(item);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("HwCastStreamPlayerPrepare001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerGetDuration001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerGetDuration001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerGetDuration001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int32_t duration;
    int32_t ret = streamplayer->GetDuration(duration);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("HwCastStreamPlayerGetDuration001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerGetCastAVPlaybackState001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerGetCastAVPlaybackState001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerGetCastAVPlaybackState001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVPlaybackState avPlaybackState;
    int32_t ret = streamplayer->GetCastAVPlaybackState(avPlaybackState);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("HwCastStreamPlayerGetCastAVPlaybackState001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSetDisplaySurface001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSetDisplaySurface001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSetDisplaySurface001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    std::string surfaceId = "surfaceId";
    int32_t ret = streamplayer->SetDisplaySurface(surfaceId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("HwCastStreamPlayerSetDisplaySurface001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerRegisterControllerListener001
 * @tc.desc: Listener is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerRegisterControllerListener001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerRegisterControllerListener001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int32_t ret = streamplayer->RegisterControllerListener(nullptr);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("HwCastStreamPlayerRegisterControllerListener001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerUnRegisterControllerListener001
 * @tc.desc: Listener is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerUnRegisterControllerListener001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerUnRegisterControllerListener001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int32_t ret = streamplayer->UnRegisterControllerListener(nullptr);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("HwCastStreamPlayerUnRegisterControllerListener001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnStateChanged001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnStateChanged001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnStateChanged001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    OHOS::CastEngine::PlayerStates playbackState = OHOS::CastEngine::PlayerStates::PLAYER_STATE_ERROR;
    streamplayer->OnStateChanged(playbackState, true);
    SLOGI("HwCastStreamPlayerOnStateChanged001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnPositionChanged001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnPositionChanged001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnPositionChanged001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int position = 0;
    int bufferPosition = 0;
    int duration = 0;
    streamplayer->OnPositionChanged(position, bufferPosition, duration);
    SLOGI("HwCastStreamPlayerOnPositionChanged001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnPositionChanged002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnPositionChanged002, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnPositionChanged002 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int position = -1;
    int bufferPosition = 0;
    int duration = 0;
    streamplayer->OnPositionChanged(position, bufferPosition, duration);
    SLOGI("HwCastStreamPlayerOnPositionChanged002 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnPositionChanged003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnPositionChanged003, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnPositionChanged003 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int position = 0;
    int bufferPosition = -1;
    int duration = 0;
    streamplayer->OnPositionChanged(position, bufferPosition, duration);
    SLOGI("HwCastStreamPlayerOnPositionChanged003 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnPositionChanged004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnPositionChanged004, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnPositionChanged004 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int position = -1;
    int bufferPosition = -1;
    int duration = 0;
    streamplayer->OnPositionChanged(position, bufferPosition, duration);
    SLOGI("HwCastStreamPlayerOnPositionChanged004 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnMediaItemChanged001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnMediaItemChanged001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnMediaItemChanged001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    OHOS::CastEngine::MediaInfo mediaInfo;
    streamplayer->OnMediaItemChanged(mediaInfo);
    SLOGI("HwCastStreamPlayerOnMediaItemChanged001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnVolumeChanged001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnVolumeChanged001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnVolumeChanged001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int volume = 0;
    int maxVolume = 0;
    streamplayer->OnVolumeChanged(volume, maxVolume);
    SLOGI("HwCastStreamPlayerOnVolumeChanged001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnLoopModeChanged001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnLoopModeChanged001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnLoopModeChanged001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    OHOS::CastEngine::LoopMode loopMode = OHOS::CastEngine::LoopMode::LOOP_MODE_SINGLE;
    streamplayer->OnLoopModeChanged(loopMode);
    SLOGI("HwCastStreamPlayerOnLoopModeChanged001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnNextRequest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnNextRequest001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnNextRequest001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    streamplayer->OnNextRequest();
    SLOGI("HwCastStreamPlayerOnNextRequest001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnPreviousRequest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnPreviousRequest001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnPreviousRequest001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    streamplayer->OnPreviousRequest();
    SLOGI("HwCastStreamPlayerOnPreviousRequest001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnPlaySpeedChanged001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnPlaySpeedChanged001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnPlaySpeedChanged001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    OHOS::CastEngine::PlaybackSpeed speed = OHOS::CastEngine::PlaybackSpeed::SPEED_FORWARD_1_00_X;
    streamplayer->OnPlaySpeedChanged(speed);
    SLOGI("HwCastStreamPlayerOnPlaySpeedChanged001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnPlayerError001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnPlayerError001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnPlayerError001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int errorCode = 0;
    std::string errorMsg = "errorMsg";
    streamplayer->OnPlayerError(errorCode, errorMsg);
    SLOGI("HwCastStreamPlayerOnPlayerError001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnSeekDone001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnSeekDone001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnSeekDone001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int32_t seekDone = 0;
    streamplayer->OnSeekDone(seekDone);
    SLOGI("HwCastStreamPlayerOnSeekDone001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnVideoSizeChanged001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnVideoSizeChanged001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnVideoSizeChanged001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int32_t width = 0;
    int32_t height = 0;
    streamplayer->OnVideoSizeChanged(width, height);
    SLOGI("HwCastStreamPlayerOnVideoSizeChanged001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnEndOfStream001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnEndOfStream001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnEndOfStream001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    int32_t isLooping = 0;
    streamplayer->OnEndOfStream(isLooping);
    SLOGI("HwCastStreamPlayerOnEndOfStream001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnPlayRequest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnPlayRequest001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnPlayRequest001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    OHOS::CastEngine::MediaInfo mediaInfo;
    streamplayer->OnPlayRequest(mediaInfo);
    SLOGI("HwCastStreamPlayerOnPlayRequest001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerOnKeyRequest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerOnKeyRequest001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerOnKeyRequest001 begin!");
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(nullptr);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    std::string assetId = "assetId";
    std::vector<uint8_t> keyRequestData;
    streamplayer->OnKeyRequest(assetId, keyRequestData);
    SLOGI("HwCastStreamPlayerOnKeyRequest001 end!");
}

class StreamPlayerImpl : public OHOS::CastEngine::IStreamPlayer {
public:
    int GetPosition(int32_t& currentPosition) override
    {
        return 0;
    };

    int Seek(int32_t position) override
    {
        return 0;
    };

    int SetSpeed(const OHOS::CastEngine::PlaybackSpeed speed) override
    {
        return 0;
    };

    int FastForward(const int32_t delta) override
    {
        return 0;
    };

    int FastRewind(const int32_t delta) override
    {
        return 0;
    };

    int SetVolume(const int32_t volume) override
    {
        return 0;
    };

    int SetMute(bool mute) override
    {
        return 0;
    };

    int ProvideKeyResponse(const std::string &mediaId, const std::vector<uint8_t> &response) override
    {
        return 0;
    };

    int SetLoopMode(const OHOS::CastEngine::LoopMode loopMode) override
    {
        return 0;
    };

    int RegisterListener(std::shared_ptr<OHOS::CastEngine::IStreamPlayerListener> listener) override
    {
        return 0;
    };

    int UnregisterListener() override
    {
        return 0;
    };

    int SetSurface(const std::string &surfaceInfo) override
    {
        return 0;
    };

    int Load(const OHOS::CastEngine::MediaInfo &media) override
    {
        return 0;
    };

    int Play() override
    {
        return 0;
    };

    int Play(const OHOS::CastEngine::MediaInfo &media) override
    {
        return 0;
    };

    int Play(int index) override
    {
        return 0;
    };

    int Pause() override
    {
        return 0;
    };
    int Stop() override
    {
        return 0;
    };
    int Next() override
    {
        return 0;
    };

    int Previous() override
    {
        return 0;
    };

    int GetPlayerStatus(OHOS::CastEngine::PlayerStates &status) override
    {
        return 0;
    };

    int GetDuration(int &duration) override
    {
        return 0;
    };

    int GetVolume(int32_t &volume, int32_t &maxVolume) override
    {
        return 0;
    };

    int GetMute(bool &mute) override
    {
        return 0;
    };

    int GetLoopMode(OHOS::CastEngine::LoopMode &loopMode) override
    {
        return 0;
    };

    int GetMediaCapabilities(std::string &jsonCapabilities) override
    {
        return 0;
    };

    int GetPlaySpeed(OHOS::CastEngine::PlaybackSpeed &speed) override
    {
        return 0;
    };

    int GetMediaInfoHolder(OHOS::CastEngine::MediaInfoHolder &hold) override
    {
        return 0;
    };

    int SetAvailableCapability(const OHOS::CastEngine::StreamCapability &streamCapability) override
    {
        return 0;
    }

    int GetAvailableCapability(OHOS::CastEngine::StreamCapability &streamCapability) override
    {
        return 0;
    }

    int Release() override
    {
        return 0;
    };
};

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams001
 * @tc.desc: cmd : CAST_CONTROL_CMD_FAST_FORWARD
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams001, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams001 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams001 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams002
 * @tc.desc: cmd : CAST_CONTROL_CMD_REWIND
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams002, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams002 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams002 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams003
 * @tc.desc: cmd : CAST_CONTROL_CMD_SEEK
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams003, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams003 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_SEEK);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams003 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams004
 * @tc.desc: cmd : CAST_CONTROL_CMD_SET_VOLUME
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams004, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams004 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams004 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams005
 * @tc.desc: cmd : CAST_CONTROL_CMD_SET_SPEED
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams005, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams005 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams005 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams006
 * @tc.desc: cmd : CAST_CONTROL_CMD_SET_LOOP_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams006, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams006 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams006 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams007
 * @tc.desc: cmd : CAST_CONTROL_CMD_TOGGLE_FAVORITE
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams007, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams007 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_FAVORITE);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams007 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams008
 * @tc.desc: cmd : CAST_CONTROL_CMD_TOGGLE_MUTE
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams008, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams008 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_MUTE);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams008 end!");
}

/**
 * @tc.name: HwCastStreamPlayerSendControlCommandWithParams009
 * @tc.desc: cmd : CAST_CONTROL_CMD_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastStreamPlayerSendControlCommandWithParams009, TestSize.Level1)
{
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams009 begin!");
    std::shared_ptr<StreamPlayerImpl> player = std::make_shared<StreamPlayerImpl>();
    std::shared_ptr<HwCastStreamPlayer> streamplayer = std::make_shared<HwCastStreamPlayer>(player);
    EXPECT_EQ(streamplayer != nullptr, true);
    streamplayer->Init();
    AVCastControlCommand cmd;
    cmd.SetCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_INVALID);
    streamplayer->SendControlCommandWithParams(cmd);
    SLOGI("HwCastStreamPlayerSendControlCommandWithParams009 end!");
}

/**
 * @tc.name: HwCastProviderInit001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderInit001, TestSize.Level1)
{
    SLOGI("HwCastProviderInit001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    SLOGI("HwCastProviderInit001 end!");
}

/**
 * @tc.name: HwCastProviderStartDiscovery001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderStartDiscovery001, TestSize.Level1)
{
    SLOGI("HwCastProviderStartDiscovery001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    int castCapability = 0;
    std::vector<std::string> drmSchemes;
    EXPECT_EQ(hwCastProvider->StartDiscovery(castCapability, drmSchemes), true);
    SLOGI("HwCastProviderStartDiscovery001 end!");
}

/**
 * @tc.name: HwCastProviderStopDiscovery001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderStopDiscovery001, TestSize.Level1)
{
    SLOGI("HwCastProviderStopDiscovery001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    hwCastProvider->StopDiscovery();
    SLOGI("HwCastProviderStopDiscovery001 end!");
}

/**
 * @tc.name: HwCastProviderSetDiscoverable001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSetDiscoverable001, TestSize.Level1)
{
    SLOGI("HwCastProviderSetDiscoverable001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    bool enable = true;
    EXPECT_EQ(hwCastProvider->SetDiscoverable(enable), AVSESSION_SUCCESS);
    SLOGI("HwCastProviderSetDiscoverable001 end!");
}

/**
 * @tc.name: HwCastProviderRelease001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderRelease001, TestSize.Level1)
{
    SLOGI("HwCastProviderRelease001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    hwCastProvider->Release();
    SLOGI("HwCastProviderRelease001 end!");
}

/**
 * @tc.name: HwCastProviderStartCastSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderStartCastSession001, TestSize.Level1)
{
    SLOGI("HwCastProviderStartCastSession001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    // Init may fail with -1, StartCastSession may fail with -1003
    int32_t retForInit = hwCastProvider->Init();
    int32_t retForStart = hwCastProvider->StartCastSession();
    SLOGI("HwCastProviderStartCastSession001 end with ret %{public}d | %{public}d", retForInit, retForStart);
}

/**
 * @tc.name: HwCastProviderStopCastSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderStopCastSession001, TestSize.Level1)
{
    SLOGI("HwCastProviderStopCastSession001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    int castId = 0;
    hwCastProvider->StopCastSession(castId);
    SLOGI("HwCastProviderStopCastSession001 end!");
}

/**
 * @tc.name: HwCastProviderAddCastDevice001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderAddCastDevice001, TestSize.Level1)
{
    SLOGI("HwCastProviderAddCastDevice001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    int castId = 0;
    DeviceInfo deviceInfo;
    EXPECT_EQ(hwCastProvider->AddCastDevice(castId, deviceInfo), false);
    SLOGI("HwCastProviderAddCastDevice001 end!");
}

/**
 * @tc.name: HwCastProviderRemoveCastDevice001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderRemoveCastDevice001, TestSize.Level1)
{
    SLOGI("HwCastProviderRemoveCastDevice001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    int castId = 0;
    DeviceInfo deviceInfo;
    EXPECT_EQ(hwCastProvider->RemoveCastDevice(castId, deviceInfo), false);
    SLOGI("HwCastProviderRemoveCastDevice001 end!");
}

/**
 * @tc.name: HwCastProviderGetRemoteController001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderGetRemoteController001, TestSize.Level1)
{
    SLOGI("HwCastProviderGetRemoteController001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    int castId = 0;
    EXPECT_EQ(hwCastProvider->GetRemoteController(castId), nullptr);
    SLOGI("HwCastProviderGetRemoteController001 end!");
}

/**
 * @tc.name: HwCastProviderRegisterCastStateListener001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderRegisterCastStateListener001, TestSize.Level1)
{
    SLOGI("HwCastProviderRegisterCastStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    EXPECT_EQ(hwCastProvider->RegisterCastStateListener(nullptr), false);
    SLOGI("HwCastProviderRegisterCastStateListener001 end!");
}

/**
 * @tc.name: HwCastProviderUnregisterCastStateListener001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderUnregisterCastStateListener001, TestSize.Level1)
{
    SLOGI("HwCastProviderUnregisterCastStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    EXPECT_EQ(hwCastProvider->UnRegisterCastStateListener(nullptr), false);
    SLOGI("HwCastProviderUnregisterCastStateListener001 end!");
}

/**
 * @tc.name: HwCastProviderRegisterCastSessionStateListener001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderRegisterCastSessionStateListener001, TestSize.Level1)
{
    SLOGI("HwCastProviderRegisterCastSessionStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    int castId = 0;
    EXPECT_EQ(hwCastProvider->RegisterCastSessionStateListener(castId, nullptr), false);
    SLOGI("HwCastProviderRegisterCastSessionStateListener001 end!");
}

/**
 * @tc.name: HwCastProviderUnregisterCastSessionStateListener001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderUnregisterCastSessionStateListener001, TestSize.Level1)
{
    SLOGI("HwCastProviderUnregisterCastSessionStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    int castId = 0;
    EXPECT_EQ(hwCastProvider->RegisterCastSessionStateListener(castId, nullptr), false);
    SLOGI("HwCastProviderUnregisterCastSessionStateListener001 end!");
}

/**
 * @tc.name: HwCastProviderOnDeviceFound001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderOnDeviceFound001, TestSize.Level1)
{
    SLOGI("HwCastProviderOnDeviceFound001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    std::vector<OHOS::CastEngine::CastRemoteDevice> device;
    hwCastProvider->OnDeviceFound(device);
    SLOGI("HwCastProviderOnDeviceFound001 end!");
}

/**
 * @tc.name: HwCastProviderOnSessionCreated001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderOnSessionCreated001, TestSize.Level1)
{
    SLOGI("HwCastProviderOnSessionCreated001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    hwCastProvider->OnSessionCreated(nullptr);
    SLOGI("HwCastProviderOnSessionCreated001 end!");
}

/**
 * @tc.name: HwCastProviderOnServiceDied001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderOnServiceDied001, TestSize.Level1)
{
    SLOGI("HwCastProviderOnServiceDied001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    hwCastProvider->OnServiceDied();
    SLOGI("HwCastProviderOnServiceDied001 end!");
}

/**
 * @tc.name: HwCastProviderSessionInit001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSessionInit001, TestSize.Level1)
{
    SLOGI("HwCastProviderSessionInit001 begin!");
    std::shared_ptr<HwCastProviderSession> provideSession = std::make_shared<HwCastProviderSession>(nullptr);
    EXPECT_EQ(provideSession != nullptr, true);
    provideSession->Init();
    SLOGI("HwCastProviderSessionInit001 end!");
}

/**
 * @tc.name: HwCastProviderSessionRelease001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSessionRelease001, TestSize.Level1)
{
    SLOGI("HwCastProviderSessionRelease001 begin!");
    std::shared_ptr<HwCastProviderSession> provideSession = std::make_shared<HwCastProviderSession>(nullptr);
    EXPECT_EQ(provideSession != nullptr, true);
    provideSession->Init();
    provideSession->Release();
    SLOGI("HwCastProviderSessionRelease001 end!");
}

/**
 * @tc.name: HwCastProviderSessionOnDeviceState001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSessionOnDeviceState001, TestSize.Level1)
{
    SLOGI("HwCastProviderSessionOnDeviceState001 begin!");
    std::shared_ptr<HwCastProviderSession> provideSession = std::make_shared<HwCastProviderSession>(nullptr);
    EXPECT_EQ(provideSession != nullptr, true);
    provideSession->Init();
    OHOS::CastEngine::DeviceStateInfo stateInfo;
    stateInfo.deviceId = "testDeviceId";
    provideSession->OnDeviceState(stateInfo);
    SLOGI("HwCastProviderSessionOnDeviceState001 end!");
}

/**
 * @tc.name: HwCastProviderSessionAddDevice001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSessionAddDevice001, TestSize.Level1)
{
    SLOGI("HwCastProviderSessionAddDevice001 begin!");
    std::shared_ptr<HwCastProviderSession> provideSession = std::make_shared<HwCastProviderSession>(nullptr);
    EXPECT_EQ(provideSession != nullptr, true);
    provideSession->Init();
    std::string deviceId = "deviceId";
    EXPECT_EQ(provideSession->AddDevice(deviceId), false);
    SLOGI("HwCastProviderSessionAddDevice001 end!");
}

/**
 * @tc.name: HwCastProviderSessionRemoveDevice001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSessionRemoveDevice001, TestSize.Level1)
{
    SLOGI("HwCastProviderSessionRemoveDevice001 begin!");
    std::shared_ptr<HwCastProviderSession> provideSession = std::make_shared<HwCastProviderSession>(nullptr);
    EXPECT_EQ(provideSession != nullptr, true);
    provideSession->Init();
    std::string deviceId = "deviceId";
    EXPECT_EQ(provideSession->RemoveDevice(deviceId), false);
    SLOGI("HwCastProviderSessionRemoveDevice001 end!");
}

/**
 * @tc.name: HwCastProviderSessionCreateStreamPlayer001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSessionCreateStreamPlayer001, TestSize.Level1)
{
    SLOGI("HwCastProviderSessionCreateStreamPlayer001 begin!");
    std::shared_ptr<HwCastProviderSession> provideSession = std::make_shared<HwCastProviderSession>(nullptr);
    EXPECT_EQ(provideSession != nullptr, true);
    provideSession->Init();
    EXPECT_EQ(provideSession->CreateStreamPlayer(), nullptr);
    SLOGI("HwCastProviderSessionCreateStreamPlayer001 end!");
}

/**
 * @tc.name: HwCastProviderSessionRegisterCastSessionStateListener001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSessionRegisterCastSessionStateListener001, TestSize.Level1)
{
    SLOGI("HwCastProviderSessionRegisterCastSessionStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();
    EXPECT_EQ(hwCastProvider->RegisterCastSessionStateListener(0, nullptr), false);
    SLOGI("HwCastProviderSessionRegisterCastSessionStateListener001 end!");
}

/**
 * @tc.name: HwCastProviderSessionUnregisterCastSessionStateListener001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastTest, HwCastProviderSessionUnregisterCastSessionStateListener001, TestSize.Level1)
{
    SLOGI("HwCastProviderSessionUnregisterCastSessionStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    std::shared_ptr<IAVCastSessionStateListener> listener = std::make_shared<IAVCastSessionStateListenerTest>();
    hwCastProvider->RegisterCastSessionStateListener(0, listener);
    EXPECT_EQ(hwCastProvider->UnRegisterCastSessionStateListener(0, listener), false);
    SLOGI("HwCastProviderSessionUnregisterCastSessionStateListener001 end!");
}
