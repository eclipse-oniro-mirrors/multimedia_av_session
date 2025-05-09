/*
* Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "hw_cast_provider_session.h"
#include "hw_cast_stream_player.h"
#include "image_type.h"

using namespace testing::ext;
using namespace OHOS::CastEngine::CastEngineClient;
using namespace OHOS::CastEngine;

namespace OHOS {
namespace AVSession {

const static int32_t INVAILD_STATE_CODE = 1000;

class HwCastStreamPlayerTest : public testing::TestWithParam<int> {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<OHOS::Media::PixelMap> CreatePixelMap();

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

class StreamPlayerIMock : public OHOS::CastEngine::IStreamPlayer {
public:
    explicit StreamPlayerIMock(int state = 0) : state_(state) {}

    int GetPosition(int32_t& currentPosition) override { return 0; }

    int Seek(int32_t position) override { return 0; }

    int SetSpeed(const OHOS::CastEngine::PlaybackSpeed speed) override { return 0; }

    int FastForward(const int32_t delta) override { return 0; }

    int FastRewind(const int32_t delta) override { return 0; }

    int SetVolume(const int32_t volume) override { return 0; }

    int SetMute(bool mute) override { return 0; }

    int ProvideKeyResponse(const std::string &mediaId, const std::vector<uint8_t> &response) override { return 0; }

    int SetLoopMode(const OHOS::CastEngine::LoopMode loopMode) override { return 0; }

    int RegisterListener(std::shared_ptr<OHOS::CastEngine::IStreamPlayerListener> listener) override { return 0; }

    int UnregisterListener() override { return 0; }

    int SetSurface(const std::string &surfaceInfo) override { return 0; }

    int Load(const OHOS::CastEngine::MediaInfo &media) override
    {
        if (state_ == 0) {
            return 0;
        } else {
            return 1;
        }
    }

    int Play() override { return 0; }

    int Play(const OHOS::CastEngine::MediaInfo &media) override { return 0; }

    int Play(int index) override { return 0; }

    int Pause() override { return 0; }

    int Stop() override { return 0; }

    int Next() override { return 0; }

    int Previous() override { return 0; }

    int GetPlayerStatus(OHOS::CastEngine::PlayerStates &status) override
    {
        if (state_ == 0) {
            status = OHOS::CastEngine::PlayerStates::PLAYER_STATE_ERROR;
        } else {
            status = static_cast<OHOS::CastEngine::PlayerStates>(INVAILD_STATE_CODE);
        }
        return 0;
    }

    int GetDuration(int &duration) override { return 0; }

    int GetVolume(int32_t &volume, int32_t &maxVolume) override { return 0; }

    int GetMute(bool &mute) override { return 0; }

    int GetLoopMode(OHOS::CastEngine::LoopMode &loopMode) override
    {
        if (state_ == 0) {
            loopMode = OHOS::CastEngine::LoopMode::LOOP_MODE_SINGLE;
        } else {
            loopMode = static_cast<OHOS::CastEngine::LoopMode>(INVAILD_STATE_CODE);
        }
        return 0;
    }

    int GetMediaCapabilities(std::string &jsonCapabilities) override { return 0; }

    int GetPlaySpeed(OHOS::CastEngine::PlaybackSpeed &speed) override
    {
        if (state_ == 0) {
            speed = OHOS::CastEngine::PlaybackSpeed::SPEED_FORWARD_1_00_X;
        } else {
            speed = static_cast<OHOS::CastEngine::PlaybackSpeed>(INVAILD_STATE_CODE);
        }
        return 0;
    }

    int GetMediaInfoHolder(OHOS::CastEngine::MediaInfoHolder &hold) override { return 0; }

    int SetAvailableCapability(const OHOS::CastEngine::StreamCapability &streamCapability) override { return 0; }

    int GetAvailableCapability(OHOS::CastEngine::StreamCapability &streamCapability) override { return 0; }

    int Release() override { return 0; }

private:
    int state_ = 0;
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
        hwCastStreamPlayer->streamPlayer_ = std::make_shared<StreamPlayerIMock>();
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

std::shared_ptr<OHOS::Media::PixelMap> HwCastStreamPlayerTest::CreatePixelMap()
{
    int32_t pixelMapWidth = 4;
    int32_t pixelMapHeight = 3;
    const std::shared_ptr<OHOS::Media::PixelMap>& pixelMap = std::make_shared<OHOS::Media::PixelMap>();
    Media::ImageInfo info;
    info.size.width = pixelMapWidth;
    info.size.height = pixelMapHeight;
    info.pixelFormat = Media::PixelFormat::RGB_888;
    info.colorSpace = Media::ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);
    int32_t rowDataSize = pixelMapWidth;
    uint32_t bufferSize = rowDataSize * pixelMapHeight;
    if (bufferSize <= 0) {
        return pixelMap;
    }

    std::vector<std::uint8_t> buffer(bufferSize, 0x03);
    pixelMap->SetPixelsAddr(buffer.data(), nullptr, bufferSize, Media::AllocatorType::CUSTOM_ALLOC, nullptr);

    return pixelMap;
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
    AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_MUTE,
    AVCastControlCommand::CAST_CONTROL_CMD_MAX
));

static const int32_t DURATION_TIME = 40000;
static OHOS::AVSession::AVMetaData GetAVMetaData()
{
    OHOS::AVSession::AVMetaData g_metaData;
    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(DURATION_TIME);
    g_metaData.SetMediaImageUri("xxxxx");
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("xxxxx");
    return g_metaData;
}

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
 * @tc.name: SendControlCommand002
 * @tc.desc: test all AVCastControlCommand for SendControlCommand
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_P(HwCastStreamPlayerTest, SendControlCommand002, TestSize.Level1)
{
    SLOGI("SendControlCommand002 begin!");
    std::vector<int32_t> commands = {
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
        AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_MUTE,
        AVCastControlCommand::CAST_CONTROL_CMD_MAX
    };
    ASSERT_TRUE(hwCastStreamPlayer->streamPlayer_ != nullptr);
    for (int32_t cmd : commands) {
        AVCastControlCommand avCastControlCommand;
        avCastControlCommand.SetCommand(cmd);
        hwCastStreamPlayer->SendControlCommand(avCastControlCommand);
    }
    SLOGI("SendControlCommand002 end!");
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
    // do not use fd of descriptor which cause crash
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
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
 * @tc.name: Start004
 * @tc.desc: set callback for data source
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Start004, TestSize.Level1)
{
    SLOGI("Start004 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("Media url");
    AVDataSrcDescriptor dataSrcDescriptor;
    dataSrcDescriptor.hasCallback = true;
    dataSrcDescriptor.callback_ = [](void*, uint32_t, int64_t) -> int32_t { return 0; };
    description->SetDataSrc(dataSrcDescriptor);
    
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    hwCastStreamPlayer->Start(avQueueItem);
    SLOGI("Start004 end!");
}

/**
 * @tc.name: Start005
 * @tc.desc: set callback for data source but callback is null
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Start005, TestSize.Level1)
{
    SLOGI("Start005 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("Media url");
    AVDataSrcDescriptor dataSrcDescriptor;
    dataSrcDescriptor.hasCallback = true;
    dataSrcDescriptor.callback_ = nullptr;
    description->SetDataSrc(dataSrcDescriptor);

    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    hwCastStreamPlayer->Start(avQueueItem);
    SLOGI("Start005 end!");
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
    // do not use fd of descriptor which cause crash
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    ret = hwCastStreamPlayer->Prepare(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("Prepare002 end!");
}

/**
 * @tc.name: Prepare003
 * @tc.desc: RepeatPrepare is true
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Prepare003, TestSize.Level1)
{
    SLOGI("Prepare003 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    description->SetIconUri("URI_CACHE");
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    ret = hwCastStreamPlayer->Prepare(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("Prepare003 end!");
}

/**
 * @tc.name: Prepare004
 * @tc.desc: set callback for dataSrcDescriptor
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Prepare004, TestSize.Level1)
{
    SLOGI("Prepare004 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    description->SetIconUri("");
    AVDataSrcDescriptor dataSrcDescriptor;
    dataSrcDescriptor.hasCallback = true;
    dataSrcDescriptor.callback_ = [](void*, uint32_t, int64_t) -> int32_t { return 0; };
    description->SetDataSrc(dataSrcDescriptor);

    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    ret = hwCastStreamPlayer->Prepare(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("Prepare004 end!");
}

/**
 * @tc.name: Prepare005
 * @tc.desc: set callback for dataSrcDescriptor but callback is null
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Prepare005, TestSize.Level1)
{
    SLOGI("Prepare005 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    description->SetIconUri("");
    AVDataSrcDescriptor dataSrcDescriptor;
    dataSrcDescriptor.hasCallback = true;
    dataSrcDescriptor.callback_ = nullptr;
    description->SetDataSrc(dataSrcDescriptor);

    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    ret = hwCastStreamPlayer->Prepare(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("Prepare005 end!");
}

/**
 * @tc.name: Prepare006
 * @tc.desc: streamPlayer_ is nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Prepare006, TestSize.Level1)
{
    SLOGI("Prepare006 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    description->SetIconUri("");
    AVDataSrcDescriptor dataSrcDescriptor;
    dataSrcDescriptor.hasCallback = true;
    dataSrcDescriptor.callback_ = nullptr;
    description->SetDataSrc(dataSrcDescriptor);

    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    hwCastStreamPlayer->streamPlayer_ = nullptr;
    ret = hwCastStreamPlayer->Prepare(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_ERROR);
    SLOGI("Prepare006 end!");
}

/**
 * @tc.name: Prepare007
 * @tc.desc: streamPlayer_->Load is not AVSESSION_SUCCESS
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, Prepare007, TestSize.Level1)
{
    SLOGI("Prepare007 begin!");
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    description->SetMediaUri("");
    description->SetIconUri("");
    AVDataSrcDescriptor dataSrcDescriptor;
    dataSrcDescriptor.hasCallback = true;
    dataSrcDescriptor.callback_ = nullptr;
    description->SetDataSrc(dataSrcDescriptor);

    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    auto ret = hwCastStreamPlayer->Start(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    hwCastStreamPlayer->streamPlayer_ = std::make_shared<StreamPlayerIMock>(1);
    ret = hwCastStreamPlayer->Prepare(avQueueItem);
    ASSERT_EQ(ret, AVSESSION_ERROR);
    SLOGI("Prepare007 end!");
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
 * @tc.name: GetCastAVPlaybackState002
 * @tc.desc: failed to data from map
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, GetCastAVPlaybackState002, TestSize.Level1)
{
    SLOGI("GetCastAVPlaybackState002 begin!");
    AVPlaybackState state;
    hwCastStreamPlayer->streamPlayer_ = std::make_shared<StreamPlayerIMock>(1);
    ASSERT_EQ(hwCastStreamPlayer->GetCastAVPlaybackState(state), AVSESSION_SUCCESS);
    SLOGI("GetCastAVPlaybackState002 end!");
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
 * @tc.name: ProcessMediaKeyResponse001
 * @tc.desc: ProcessMediaKeyResponse
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, ProcessMediaKeyResponse001, TestSize.Level1)
{
    SLOGI("ProcessMediaKeyResponse001 begin!");
    std::string assetId = "assetId";
    std::vector<uint8_t> response;
    ASSERT_EQ(hwCastStreamPlayer->ProcessMediaKeyResponse(assetId, response), AVSESSION_SUCCESS);
    SLOGI("ProcessMediaKeyResponse001 end!");
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
 * @tc.name: OnStateChanged002
 * @tc.desc: push listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnStateChanged002, TestSize.Level1)
{
    SLOGI("OnStateChanged002 begin!");
    auto state = static_cast<OHOS::CastEngine::PlayerStates>(1000);
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    hwCastStreamPlayer->OnStateChanged(state, true);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnStateChanged002 end!");
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
 * @tc.name: OnPositionChanged003
 * @tc.desc: push listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPositionChanged003, TestSize.Level1)
{
    SLOGI("OnPositionChanged003 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    hwCastStreamPlayer->OnPositionChanged(1, 1, 1);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnPositionChanged003 end!");
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
 * @tc.name: OnMediaItemChanged002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnMediaItemChanged002, TestSize.Level1)
{
    SLOGI("OnMediaItemChanged002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    CastEngine::MediaInfo mediaInfo;
    hwCastStreamPlayer->OnMediaItemChanged(mediaInfo);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnMediaItemChanged002 end!");
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
 * @tc.name: OnNextRequest002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnNextRequest002, TestSize.Level1)
{
    SLOGI("OnNextRequest002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    hwCastStreamPlayer->OnNextRequest();
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnNextRequest002 end!");
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
 * @tc.name: OnVolumeChanged002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnVolumeChanged002, TestSize.Level1)
{
    SLOGI("OnVolumeChanged002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    hwCastStreamPlayer->OnVolumeChanged(5, 15);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnVolumeChanged002 end!");
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
 * @tc.name: OnLoopModeChanged002
 * @tc.desc: send error code
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnLoopModeChanged002, TestSize.Level1)
{
    SLOGI("OnLoopModeChanged002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    auto loopMode = static_cast<OHOS::CastEngine::LoopMode>(1000);
    hwCastStreamPlayer->OnLoopModeChanged(loopMode);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnLoopModeChanged002 end!");
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
 * @tc.name: OnPlaySpeedChanged002
 * @tc.desc: send error code
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPlaySpeedChanged002, TestSize.Level1)
{
    SLOGI("OnPlaySpeedChanged002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    auto playSpeed = static_cast<OHOS::CastEngine::PlaybackSpeed>(1000);
    hwCastStreamPlayer->OnPlaySpeedChanged(playSpeed);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnPlaySpeedChanged002 end!");
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
 * @tc.name: OnPlayerError002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPlayerError002, TestSize.Level1)
{
    SLOGI("OnPlayerError002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    hwCastStreamPlayer->OnPlayerError(10003, "PLAYER_ERROR");
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnPlayerError002 end!");
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
 * @tc.name: OnSeekDone002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnSeekDone002, TestSize.Level1)
{
    SLOGI("OnSeekDone002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    int32_t seekNumber = 0;
    hwCastStreamPlayer->OnSeekDone(seekNumber);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnSeekDone002 end!");
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
 * @tc.name: OnVideoSizeChanged002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnVideoSizeChanged002, TestSize.Level1)
{
    SLOGI("OnVideoSizeChanged002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    hwCastStreamPlayer->OnVideoSizeChanged(0, 0);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnVideoSizeChanged002 end!");
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

/**
 * @tc.name: OnEndOfStream002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnEndOfStream002, TestSize.Level1)
{
    SLOGI("OnEndOfStream002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    hwCastStreamPlayer->OnEndOfStream(0);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnEndOfStream002 end!");
}

/**
 * @tc.name: OnPlayRequest001
 * @tc.desc: OnPlayRequest
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPlayRequest001, TestSize.Level1)
{
    SLOGI("OnPlayRequest001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    CastEngine::MediaInfo mediaInfo;
    hwCastStreamPlayer->OnPlayRequest(mediaInfo);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnPlayRequest001 end!");
}

/**
 * @tc.name: OnPlayRequest002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnPlayRequest002, TestSize.Level1)
{
    SLOGI("OnPlayRequest002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    CastEngine::MediaInfo mediaInfo;
    hwCastStreamPlayer->OnPlayRequest(mediaInfo);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnPlayRequest002 end!");
}

/**
 * @tc.name: OnKeyRequest001
 * @tc.desc: OnKeyRequest
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnKeyRequest001, TestSize.Level1)
{
    SLOGI("OnKeyRequest001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    std::string assetId = "assetId";
    std::vector<uint8_t> keyRequestData;
    hwCastStreamPlayer->OnKeyRequest(assetId, keyRequestData);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnKeyRequest001 end!");
}

/**
 * @tc.name: OnKeyRequest002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnKeyRequest002, TestSize.Level1)
{
    SLOGI("OnKeyRequest002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    std::string assetId = "assetId";
    std::vector<uint8_t> keyRequestData;
    hwCastStreamPlayer->OnKeyRequest(assetId, keyRequestData);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnKeyRequest002 end!");
}

/**
 * @tc.name: SetValidAbility001
 * @tc.desc: SetValidAbility to cast
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, SetValidAbility001, TestSize.Level1)
{
    SLOGI("SetValidAbility001 begin!");
    std::vector<int32_t> validAbilityList;
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PAUSE);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_STOP);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
    ASSERT_EQ(hwCastStreamPlayer->SetValidAbility(validAbilityList), AVSESSION_SUCCESS);
    SLOGI("SetValidAbility001 end!");
}

/**
 * @tc.name: GetValidAbility001
 * @tc.desc: GetValidAbility from cast
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, GetValidAbility001, TestSize.Level1)
{
    SLOGI("GetValidAbility001 begin!");
    std::vector<int32_t> validAbilityList;
    ASSERT_EQ(hwCastStreamPlayer->GetValidAbility(validAbilityList), AVSESSION_SUCCESS);
    SLOGI("GetValidAbility001 end!");
}

/**
 * @tc.name: GetValidAbility002
 * @tc.desc: streamPlayer_ is nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, GetValidAbility002, TestSize.Level1)
{
    SLOGI("GetValidAbility002 begin!");
    std::vector<int32_t> validAbilityList;
    hwCastStreamPlayer->streamPlayer_ = nullptr;
    ASSERT_EQ(hwCastStreamPlayer->GetValidAbility(validAbilityList), AVSESSION_ERROR);
    SLOGI("GetValidAbility002 end!");
}

/**
 * @tc.name: OnAvailableCapabilityChanged001
 * @tc.desc: OnAvailableCapabilityChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnAvailableCapabilityChanged001, TestSize.Level1)
{
    SLOGI("OnAvailableCapabilityChanged001 begin!");
    std::shared_ptr<AVCastControllerItem> avCastControllerItem = std::make_shared<AVCastControllerItem>();
    ASSERT_EQ(hwCastStreamPlayer->RegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    CastEngine::StreamCapability streamCapability;
    streamCapability.isPlaySupported = true;
    streamCapability.isPauseSupported = true;
    streamCapability.isStopSupported = true;
    streamCapability.isNextSupported = true;
    streamCapability.isPreviousSupported = true;
    streamCapability.isSeekSupported = true;
    hwCastStreamPlayer->OnAvailableCapabilityChanged(streamCapability);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(avCastControllerItem), AVSESSION_SUCCESS);
    SLOGI("OnAvailableCapabilityChanged001 end!");
}

/**
 * @tc.name: OnAvailableCapabilityChanged002
 * @tc.desc: add listener to streamPlayerListenerList_
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnAvailableCapabilityChanged002, TestSize.Level1)
{
    SLOGI("OnAvailableCapabilityChanged002 begin!");
    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);
    CastEngine::StreamCapability streamCapability;
    streamCapability.isPlaySupported = true;
    streamCapability.isPauseSupported = true;
    streamCapability.isStopSupported = true;
    streamCapability.isNextSupported = true;
    streamCapability.isPreviousSupported = true;
    streamCapability.isSeekSupported = true;
    streamCapability.isFastForwardSupported = true;
    streamCapability.isFastRewindSupported = true;
    streamCapability.isLoopModeSupported = true;
    streamCapability.isSetVolumeSupported = true;

    hwCastStreamPlayer->OnAvailableCapabilityChanged(streamCapability);
    ASSERT_EQ(hwCastStreamPlayer->UnRegisterControllerListener(controller), AVSESSION_SUCCESS);
    SLOGI("OnAvailableCapabilityChanged002 end!");
}

/**
 * @tc.name: CheckCastTime001
 * @tc.desc: CheckCastTime
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, CheckCastTime001, TestSize.Level1)
{
    SLOGI("CheckCastTime001 begin!");
    int32_t castTime = 1001;
    int32_t ret = hwCastStreamPlayer->CheckCastTime(castTime);
    EXPECT_EQ(ret, castTime);
    SLOGI("CheckCastTime001 end!");
}

/**
 * @tc.name: CheckCastTime002
 * @tc.desc: castTime is less than 1000
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, CheckCastTime002, TestSize.Level1)
{
    SLOGI("CheckCastTime002 begin!");
    int32_t castTime = 1;
    int32_t ret = hwCastStreamPlayer->CheckCastTime(castTime);
    EXPECT_EQ(ret, 1000);
    SLOGI("CheckCastTime002 end!");
}

/**
 * @tc.name: RepeatPrepare001
 * @tc.desc: test RepeatPrepare
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, RepeatPrepare001, TestSize.Level1)
{
    SLOGI("RepeatPrepare001 begin!");
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 0, 0, 0, 1};
    mediaPixelMap->SetInnerImgBuffer(imgBuffer);

    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    hwCastStreamPlayer->RefreshCurrentAVQueueItem(avQueueItem);
    description->SetIconUri("URI_CACHE");
    description->SetIcon(mediaPixelMap);
    auto ret = hwCastStreamPlayer->RepeatPrepare(description);
    EXPECT_EQ(ret, true);
    SLOGI("RepeatPrepare001 end!");
}

/**
 * @tc.name: SetValidAbility002
 * @tc.desc: test SetValidAbility
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, SetValidAbility002, TestSize.Level1)
{
    SLOGI("SetValidAbility002 begin!");
    std::vector<int32_t> validAbilityList;
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PAUSE);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_STOP);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
    hwCastStreamPlayer->streamPlayer_ = nullptr;
    auto ret = hwCastStreamPlayer->SetValidAbility(validAbilityList);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetValidAbility002 end!");
}

/**
 * @tc.name: SetValidAbility003
 * @tc.desc: test all cmds in SetValidAbility
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, SetValidAbility003, TestSize.Level1)
{
    SLOGI("SetValidAbility003 begin!");
    std::vector<int32_t> validAbilityList;
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PAUSE);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_STOP);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SEEK);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE);
    validAbilityList.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME);
    validAbilityList.push_back(INVAILD_STATE_CODE);
    auto ret = hwCastStreamPlayer->SetValidAbility(validAbilityList);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetValidAbility003 end!");
}

/**
 * @tc.name: OnAlbumCoverChanged001
 * @tc.desc: test OnAlbumCoverChanged
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnAlbumCoverChanged001, TestSize.Level1)
{
    SLOGI("OnAlbumCoverChanged001 begin!");
    OHOS::AVSession::AVMetaData metaData = GetAVMetaData();
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = metaData.GetMediaImage();
    std::shared_ptr<Media::PixelMap> pixelMap = AVSessionPixelMapAdapter::ConvertFromInner(mediaPixelMap);
    hwCastStreamPlayer->OnAlbumCoverChanged(pixelMap);
    SLOGI("OnAlbumCoverChanged001 end!");
}

/**
 * @tc.name: OnAlbumCoverChanged002
 * @tc.desc: pixelMap is not nullptr but innerPixelMap is nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnAlbumCoverChanged002, TestSize.Level1)
{
    SLOGI("OnAlbumCoverChanged002 begin!");
    auto pixelMap = std::make_shared<OHOS::Media::PixelMap>();
    hwCastStreamPlayer->OnAlbumCoverChanged(pixelMap);
    std::shared_ptr<AVSessionPixelMap> innerPixelMap =
        AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    EXPECT_TRUE(innerPixelMap == nullptr);
    SLOGI("OnAlbumCoverChanged002 end!");
}

/**
 * @tc.name: OnAlbumCoverChanged003
 * @tc.desc: pixelMap is not nullptr but innerPixelMap and nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnAlbumCoverChanged003, TestSize.Level1)
{
    SLOGI("OnAlbumCoverChanged003 begin!");
    auto pixelMap = CreatePixelMap();
    hwCastStreamPlayer->OnAlbumCoverChanged(pixelMap);
    std::shared_ptr<AVSessionPixelMap> innerPixelMap =
        AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    EXPECT_TRUE(innerPixelMap != nullptr);
    SLOGI("OnAlbumCoverChanged003 end!");
}

/**
 * @tc.name: OnAlbumCoverChanged004
 * @tc.desc: pixelMap is not nullptr but innerPixelMap and nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnAlbumCoverChanged004, TestSize.Level1)
{
    SLOGI("OnAlbumCoverChanged004 begin!");
    auto pixelMap = CreatePixelMap();
    hwCastStreamPlayer->OnAlbumCoverChanged(pixelMap);
    auto innerPixelMap = AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    EXPECT_TRUE(innerPixelMap != nullptr);
    SLOGI("OnAlbumCoverChanged004 end!");
}

/**
 * @tc.name: OnAlbumCoverChanged005
 * @tc.desc: pixelMap is not nullptr but innerPixelMap and nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(HwCastStreamPlayerTest, OnAlbumCoverChanged005, TestSize.Level1)
{
    SLOGI("OnAlbumCoverChanged005 begin!");
    auto pixelMap = CreatePixelMap();
    std::shared_ptr<AVMediaDescription> description = CreateAVMediaDescription();
    AVQueueItem avQueueItem;
    avQueueItem.SetDescription(description);
    hwCastStreamPlayer->RefreshCurrentAVQueueItem(avQueueItem);

    auto controller = std::make_shared<AVCastControllerItem>();
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(controller);
    hwCastStreamPlayer->streamPlayerListenerList_.push_back(nullptr);

    hwCastStreamPlayer->OnAlbumCoverChanged(pixelMap);
    auto innerPixelMap = AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    EXPECT_TRUE(innerPixelMap != nullptr);
    SLOGI("OnAlbumCoverChanged005 end!");
}

/**
* @tc.name: GetMediaCapabilitiesOfVideo001
* @tc.desc: json contains needed data
* @tc.type: FUNC
* @tc.require: NA
*/
HWTEST_F(HwCastStreamPlayerTest, GetMediaCapabilitiesOfVideo001, TestSize.Level1)
{
    string capabilities = R"(
    {
        "decoderType": ["H264", "H265"],
        "decoderSupportResolution": {"video/hevc": 0, "video/avc": 1},
        "HDRFormat": 1,
        "speed": 1
    })";
    nlohmann::json value = nlohmann::json::parse(capabilities);
    EXPECT_NE(value.empty(), true);
    hwCastStreamPlayer->GetMediaCapabilitiesOfVideo(value);
    auto vec = hwCastStreamPlayer->jsonCapabilitiesSptr_->decoderTypes_;
    EXPECT_NE(std::find(vec.begin(), vec.end(), "H264"), vec.end());

    string resolution = "H264";
    ResolutionLevel level;
    auto ret = hwCastStreamPlayer->GetRecommendedResolutionLevel(resolution, level);
    EXPECT_EQ(ret, AVSESSION_ERROR);

    std::vector<HDRFormat> hdrFormats;
    ret = hwCastStreamPlayer->GetSupportedHdrCapabilities(hdrFormats);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::vector<float> playSpeeds;
    hwCastStreamPlayer->jsonCapabilitiesSptr_->playSpeeds_.push_back(1.0f);
    ret = hwCastStreamPlayer->GetSupportedPlaySpeeds(playSpeeds);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: GetMediaCapabilitiesOfVideo002
* @tc.desc: json not contains needed data
* @tc.type: FUNC
* @tc.require: NA
*/
HWTEST_F(HwCastStreamPlayerTest, GetMediaCapabilitiesOfVideo002, TestSize.Level1)
{
    string capabilities = R"(
    {
        "decoderType_NA": ["H264", "H265"],
        "decoderSupportResolution_NA": {"video/hevc": 0, "video/avc": 1},
        "HDRFormat_NA": 1
    })";
    nlohmann::json value = nlohmann::json::parse(capabilities);
    EXPECT_NE(value.empty(), true);
    hwCastStreamPlayer->GetMediaCapabilitiesOfVideo(value);
    auto vec = hwCastStreamPlayer->jsonCapabilitiesSptr_->decoderTypes_;
    EXPECT_EQ(std::find(vec.begin(), vec.end(), "H264"), vec.end());
}

/**
* @tc.name: GetMediaCapabilitiesOfAudio001
* @tc.desc: json contains needed data
* @tc.type: FUNC
* @tc.require: NA
*/
HWTEST_F(HwCastStreamPlayerTest, GetMediaCapabilitiesOfAudio001, TestSize.Level1)
{
    string capabilities = R"(
    {
        "decoderType": "mp3"
    })";
    nlohmann::json value = nlohmann::json::parse(capabilities);
    EXPECT_NE(value.empty(), true);
    hwCastStreamPlayer->GetMediaCapabilitiesOfAudio(value);
    auto vec = hwCastStreamPlayer->jsonCapabilitiesSptr_->decoderTypes_;
    EXPECT_NE(std::find(vec.begin(), vec.end(), "mp3"), vec.end());

    std::vector<std::string> decoderTypes;
    auto ret = hwCastStreamPlayer->GetSupportedDecoders(decoderTypes);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: GetMediaCapabilitiesOfAudio002
* @tc.desc: json not contains needed data
* @tc.type: FUNC
* @tc.require: NA
*/
HWTEST_F(HwCastStreamPlayerTest, GetMediaCapabilitiesOfAudio002, TestSize.Level1)
{
    string capabilities = R"(
    {
        "decoderType_NA": "mp3"
    })";
    nlohmann::json value = nlohmann::json::parse(capabilities);
    EXPECT_NE(value.empty(), true);
    hwCastStreamPlayer->GetMediaCapabilitiesOfAudio(value);
    auto vec = hwCastStreamPlayer->jsonCapabilitiesSptr_->decoderTypes_;
    EXPECT_EQ(std::find(vec.begin(), vec.end(), "mp3"), vec.end());
}

/**
* @tc.name: checkCmdsFromAbility001
* @tc.desc: test checkCmdsFromAbility when isFastForwardSupported is true
* @tc.type: FUNC
* @tc.require: NA
*/
HWTEST_F(HwCastStreamPlayerTest, checkCmdsFromAbility001, TestSize.Level1)
{
    StreamCapability avStreamCapability = {
        .isFastForwardSupported = true,
        .isFastRewindSupported = true,
        .isLoopModeSupported = true,
        .isSetVolumeSupported = true,
    };
    std::vector<int32_t> supportedCastCmds;
    hwCastStreamPlayer->checkCmdsFromAbility(avStreamCapability, supportedCastCmds);
    EXPECT_NE(std::find(supportedCastCmds.begin(), supportedCastCmds.end(), 5), supportedCastCmds.end());
}

/**
* @tc.name: checkAbilityFromCmds001
* @tc.desc: test checkAbilityFromCmds
* @tc.type: FUNC
* @tc.require: NA
*/
HWTEST_F(HwCastStreamPlayerTest, checkAbilityFromCmds001, TestSize.Level1)
{
    std::vector<int32_t> supportedCastCmds;
    for (auto i = 0; i <= AVCastControlCommand::CAST_CONTROL_CMD_MAX; i++) {
        supportedCastCmds.push_back(i);
    }
    CastEngine::StreamCapability streamCapability;
    hwCastStreamPlayer->checkAbilityFromCmds(supportedCastCmds, streamCapability);
    EXPECT_EQ(streamCapability.isFastForwardSupported, true);
}
} // namespace AVSession
} // namespace OHOS
