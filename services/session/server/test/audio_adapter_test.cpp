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
#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>
#include "audio_adapter.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "audio_info.h"
#include "audio_device_info.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using OHOS::AudioStandard::AudioDeviceUsage;
using OHOS::AudioStandard::AudioRendererChangeInfo;
using OHOS::AudioStandard::RendererState;
using OHOS::AudioStandard::AudioStreamManager;

static std::vector<std::shared_ptr<AudioRendererChangeInfo>> g_mockRendererInfos;

class AudioAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static constexpr int32_t TEST_CLIENT_UID = 1;
    static constexpr int32_t TEST_CLIENT_PID = 1;
    static constexpr int32_t TEST_SESSION_ID = 2;
    static constexpr int32_t TEST_SESSION_FAIL_ID = -1;
};

void AudioAdapterTest::SetUpTestCase()
{}

void AudioAdapterTest::TearDownTestCase()
{}

void AudioAdapterTest::SetUp()
{}

void AudioAdapterTest::TearDown()
{}

/**
* @tc.name: OnRendererStateChange001
* @tc.desc: verifying the renderer state listener
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, OnRendererStateChange001, TestSize.Level0)
{
    SLOGI("OnRendererStateChange001 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    AudioAdapter::GetInstance().OnRendererStateChange(infosExpected);

    ASSERT_NE(infosActual.size(), 0);
    const auto& infoExpected = infosExpected[0];
    const auto& infoActual = infosActual[0];
    EXPECT_EQ(infoExpected->clientUID, infoActual->clientUID);
    EXPECT_EQ(infoExpected->sessionId, infoActual->sessionId);
    EXPECT_EQ(infoExpected->rendererState, infoActual->rendererState);
    SLOGI("OnRendererStateChange001 end!");
}

/**
* @tc.name: MuteAudioStream001
* @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, MuteAudioStream001, TestSize.Level0)
{
    SLOGI("MuteAudioStream001 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([](const AudioRendererChangeInfos& infos) {
        SLOGI("MuteAudioStream001 AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID);
    EXPECT_NE(ret, AVSESSION_ERROR_BASE);

    ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_SESSION_FAIL_ID,
        AudioAdapterTest::TEST_SESSION_FAIL_ID);
    EXPECT_NE(ret, AVSESSION_ERROR_BASE);
}

/**
* @tc.name: MuteAudioStream002
* @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
*/
static HWTEST(AudioAdapterTest, MuteAudioStream002, TestSize.Level0)
{
    SLOGI("MuteAudioStream002 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([](const AudioRendererChangeInfos& infos) {
        SLOGI("MuteAudioStream002 AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(ret, AVSESSION_ERROR);

    ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MUSIC);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("MuteAudioStream002 done!");
}

/**
* @tc.name: MuteAudioStream003
* @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, MuteAudioStream003, TestSize.Level0)
{
    SLOGI("MuteAudioStream003 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([](const AudioRendererChangeInfos& infos) {
        SLOGI("MuteAudioStream003 AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.isCastableDevice_ = true;
    auto ret = audioAdapter.MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: MuteAudioStream004
* @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, MuteAudioStream004, TestSize.Level0)
{
    SLOGI("MuteAudioStream004 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([](const AudioRendererChangeInfos& infos) {
        SLOGI("MuteAudioStream004 AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.isCastableDevice_ = true;
    auto ret = audioAdapter.MuteAudioStream(AudioAdapterTest::TEST_SESSION_FAIL_ID,
        AudioAdapterTest::TEST_SESSION_FAIL_ID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: MuteAudioStream005
 * @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, MuteAudioStream005, TestSize.Level4)
{
    SLOGI("MuteAudioStream005 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->backMute = false;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.MuteAudioStream(
        AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID
    );
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: MuteAudioStream006
 * @tc.desc: mute audio stream with invalid UID (UID not match)
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, MuteAudioStream006, TestSize.Level4)
{
    SLOGI("MuteAudioStream006 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID + 1;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->backMute = false;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.MuteAudioStream(
        AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID
    );
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: MuteAudioStream007
 * @tc.desc: mute audio stream with invalid PID (PID not match)
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, MuteAudioStream007, TestSize.Level4)
{
    SLOGI("MuteAudioStream007 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID + 1;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->backMute = false;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.MuteAudioStream(
        AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID
    );
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: MuteAudioStream008
 * @tc.desc: mute audio stream with renderer state not RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, MuteAudioStream008, TestSize.Level4)
{
    SLOGI("MuteAudioStream008 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->rendererState = RendererState::RENDERER_STOPPED;
    info->backMute = false;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.MuteAudioStream(
        AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID
    );
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: MuteAudioStream009
 * @tc.desc: mute audio stream with backMute already true
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, MuteAudioStream009, TestSize.Level4)
{
    SLOGI("MuteAudioStream009 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->backMute = true;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.MuteAudioStream(
        AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID
    );
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: MuteAudioStream010
 * @tc.desc: mute audio stream with streamUsage not in BACKGROUND_MUTE_STREAM_USAGE
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, MuteAudioStream010, TestSize.Level4)
{
    SLOGI("MuteAudioStream010 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->backMute = false;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_VOICE_COMMUNICATION;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.MuteAudioStream(
        AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID
    );
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: UnMuteAudioStream001
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream001, TestSize.Level0)
{
    SLOGI("UnMuteAudioStream001 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([](const AudioRendererChangeInfos& infos) {
        SLOGI("UnMuteAudioStream001 AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto ret = AudioAdapter::GetInstance().UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_NE(ret, AVSESSION_ERROR_BASE);
}

/**
* @tc.name: UnMuteAudioStream002
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream002, TestSize.Level0)
{
    SLOGI("UnMuteAudioStream002 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([](const AudioRendererChangeInfos& infos) {
        SLOGI("UnMuteAudioStream002 AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.isCastableDevice_ = true;
    auto ret = audioAdapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: UnMuteAudioStream003
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream003, TestSize.Level0)
{
    SLOGI("UnMuteAudioStream003 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([](const AudioRendererChangeInfos& infos) {
        SLOGI("UnMuteAudioStream003 AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.isCastableDevice_ = true;
    auto ret = audioAdapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("UnMuteAudioStream003 done!");
}

/**
* @tc.name: UnMuteAudioStream004
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream004, TestSize.Level0)
{
    SLOGI("UnMuteAudioStream004 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([](const AudioRendererChangeInfos& infos) {
        SLOGI("UnMuteAudioStream004 AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    auto ret = audioAdapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: UnMuteAudioStream005
 * @tc.desc: unmute audio stream for valid uid, all conditions matched
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, UnMuteAudioStream005, TestSize.Level4)
{
    SLOGI("UnMuteAudioStream005 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->rendererState = OHOS::AudioStandard::RENDERER_RUNNING;
    info->backMute = true;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: UnMuteAudioStream006
 * @tc.desc: unmute audio stream with invalid UID (not match)
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, UnMuteAudioStream006, TestSize.Level4)
{
    SLOGI("UnMuteAudioStream006 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID + 1;
    info->rendererState = OHOS::AudioStandard::RENDERER_RUNNING;
    info->backMute = true;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: UnMuteAudioStream007
 * @tc.desc: unmute audio stream with renderer state not RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, UnMuteAudioStream007, TestSize.Level4)
{
    SLOGI("UnMuteAudioStream007 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->rendererState = OHOS::AudioStandard::RENDERER_STOPPED;
    info->backMute = true;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: UnMuteAudioStream008
 * @tc.desc: unmute audio stream with backMute == false (no need unmute)
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, UnMuteAudioStream008, TestSize.Level4)
{
    SLOGI("UnMuteAudioStream008 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->rendererState = OHOS::AudioStandard::RENDERER_RUNNING;
    info->backMute = false;
    info->rendererInfo.streamUsage = OHOS::AudioStandard::STREAM_USAGE_MUSIC;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: UnMuteAudioStream009
 * @tc.desc: unmute with multiple renderers, only one matches UID
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, UnMuteAudioStream009, TestSize.Level4)
{
    SLOGI("UnMuteAudioStream009 begin!");
    auto info1 = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info1 != nullptr);
    info1->clientUID = AudioAdapterTest::TEST_CLIENT_UID + 1;
    info1->rendererState = OHOS::AudioStandard::RENDERER_RUNNING;
    info1->backMute = true;

    auto info2 = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info2 != nullptr);
    info2->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info2->rendererState = OHOS::AudioStandard::RENDERER_RUNNING;
    info2->backMute = true;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info1);
    g_mockRendererInfos.push_back(info2);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: UnMuteAudioStream010
 * @tc.desc: unmute with no renderer matching any condition
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, UnMuteAudioStream010, TestSize.Level4)
{
    SLOGI("UnMuteAudioStream010 begin!");
    auto info = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info != nullptr);
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID + 1;
    info->rendererState = OHOS::AudioStandard::RENDERER_STOPPED;
    info->backMute = false;

    g_mockRendererInfos.clear();
    g_mockRendererInfos.push_back(info);

    auto& adapter = AudioAdapter::GetInstance();
    adapter.Init();
    adapter.isCastableDevice_ = false;

    auto ret = adapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: GetRendererRunning001
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, GetRendererRunning001, TestSize.Level0)
{
    SLOGI("GetRendererRunning001 begin!");
    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().GetRendererRunning(AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID);
    SLOGI("GetRendererRunning001 end!");
}

/**
* @tc.name: GetRendererRunning002
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, GetRendererRunning002, TestSize.Level0)
{
    SLOGI("GetRendererRunning002 begin!");
    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().GetRendererRunning(AudioAdapterTest::TEST_SESSION_FAIL_ID,
        AudioAdapterTest::TEST_SESSION_FAIL_ID);
    SLOGI("GetRendererRunning002 end!");
}

/**
* @tc.name: PauseAudioStream001
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, PauseAudioStream001, TestSize.Level0)
{
    SLOGI("PauseAudioStream001 begin!");
    AudioAdapter::GetInstance().Init();
    int32_t uid = 10001;
    OHOS::AudioStandard::StreamUsage streamUsage {};
    int32_t ret = AudioAdapter::GetInstance().PauseAudioStream(uid, streamUsage);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("PauseAudioStream001 end!");
}

/**
 * @tc.name: OnPreferredOutputDeviceUpdated001
 * @tc.desc: Notify registered listeners when the preferred audio output device is updated.
 *           This method iterates through all registered listeners and calls their callback functions
 *           with the updated device descriptor.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnPreferredOutputDeviceUpdated001, TestSize.Level0)
{
    SLOGD("OnPreferredOutputDeviceUpdated001 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().AddDeviceChangeListener(
        [&ret] (const AudioDeviceDescriptors &desc) {
        ret = desc.empty();
    });
    AudioAdapter::GetInstance().Init();
    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptors desc = audioAdapter.GetAvailableDevices();
    audioAdapter.deviceChangeListeners_ =
        std::vector<OHOS::AVSession::AudioAdapter::PreferOutputDeviceChangeListener>();
    audioAdapter.OnPreferredOutputDeviceUpdated(desc);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnPreferredOutputDeviceUpdated002
 * @tc.desc: Verify that null listeners are safely skipped in OnPreferredOutputDeviceUpdated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnPreferredOutputDeviceUpdated002, TestSize.Level4)
{
    SLOGD("OnPreferredOutputDeviceUpdated002 begin!");
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.Init();
    audioAdapter.deviceChangeListeners_.clear();
    AudioAdapter::PreferOutputDeviceChangeListener nullListener;
    audioAdapter.deviceChangeListeners_.push_back(nullListener);
    audioAdapter.deviceChangeListeners_.push_back([](const AudioDeviceDescriptors&){});
    AudioDeviceDescriptors desc;
    EXPECT_FALSE(audioAdapter.deviceChangeListeners_.empty());
    auto device = std::make_shared<AudioDeviceDescriptor>(OHOS::AudioStandard::DEVICE_TYPE_SPEAKER);
    desc.push_back(device);
    audioAdapter.OnPreferredOutputDeviceUpdated(desc);
    audioAdapter.deviceChangeListeners_.clear();
}

/**
 * @tc.name: OnAvailableDeviceChange001
 * @tc.desc: Notify registered listener when the available audio output devices are updated.
 *           This method calls registered listener's callback function with the device change action.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnAvailableDeviceChange001, TestSize.Level0)
{
    SLOGD("OnAvailableDeviceChange001 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetAvailableDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        ret = desc.empty();
    });

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnAvailableDeviceChange(AudioDeviceUsage::MEDIA_OUTPUT_DEVICES, action);
    sleep(1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnAvailableDeviceChange002
 * @tc.desc: Notify registered listener when the available audio output devices are updated.
 *           This method calls registered listener's callback function with the device change action.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnAvailableDeviceChange002, TestSize.Level0)
{
    SLOGD("OnAvailableDeviceChange002 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetAvailableDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        ret = desc.empty();
    });

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::DISCONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnAvailableDeviceChange(AudioDeviceUsage::MEDIA_OUTPUT_DEVICES, action);
    sleep(1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnAvailableDeviceChange003
 * @tc.desc: Notify registered listener when the available audio output devices are updated.
 *           This method calls registered listener's callback function with the device change action.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnAvailableDeviceChange003, TestSize.Level0)
{
    SLOGD("OnAvailableDeviceChange003 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetAvailableDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        ret = desc.empty();
    });
    AudioAdapter::GetInstance().UnsetAvailableDeviceChangeCallback();

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnAvailableDeviceChange(AudioDeviceUsage::MEDIA_OUTPUT_DEVICES, action);
    sleep(1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnVolumeKeyEvent001
 * @tc.desc: Notify registered listener when the volume is updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnVolumeKeyEvent001, TestSize.Level0)
{
    SLOGD("OnVolumeKeyEvent001 begin!");
    int32_t volume = -1;
    AudioAdapter::GetInstance().RegisterVolumeKeyEventCallback(
        [&volume] (int32_t volumeNum) {
        volume = volumeNum;
    });

    AudioAdapter::GetInstance().SetVolume(AudioAdapter::GetInstance().GetVolume());
    sleep(1);
    EXPECT_TRUE(volume != -1);
}

/**
 * @tc.name: OnVolumeKeyEvent002
 * @tc.desc: Notify registered listener when the volume is updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnVolumeKeyEvent002, TestSize.Level0)
{
    SLOGD("OnVolumeKeyEvent002 begin!");
    int32_t volume = -1;
    AudioAdapter::GetInstance().RegisterVolumeKeyEventCallback(
        [&volume] (int32_t volumeNum) {
        volume = volumeNum;
    });
    AudioAdapter::GetInstance().UnregisterVolumeKeyEventCallback();

    AudioAdapter::GetInstance().SetVolume(AudioAdapter::GetInstance().GetVolume());
    sleep(1);
    EXPECT_TRUE(volume == -1);
}

/**
* @tc.name: OnDeviceChange001
* @tc.desc: Test OnDeviceChange
* @tc.type: FUNC
*/
static HWTEST(AudioAdapterTest, OnDeviceChange001, TestSize.Level0)
{
    SLOGD("OnDeviceChange001 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().AddDeviceChangeListener(
        [&ret] (const AudioDeviceDescriptors &desc) {
        ret = desc.empty();
    });
    AudioAdapter::GetInstance().AddDeviceChangeListener(nullptr);

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    AudioAdapter::GetInstance().OnDeviceChange(action);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnDeviceChange002
 * @tc.desc: Notify registered listener when the audio output devices are updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnDeviceChange002, TestSize.Level0)
{
    SLOGD("OnDeviceChange002 begin!");
    bool ret = OHOS::AVSession::AVSESSION_SUCCESS;
    ret = AudioAdapter::GetInstance().SetDeviceChangeCallback();

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnDeviceChange(action);
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnDeviceChange003
 * @tc.desc: Notify registered listener when the audio output devices are updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnDeviceChange003, TestSize.Level0)
{
    SLOGD("OnDeviceChange003 begin!");
    bool ret = OHOS::AVSession::AVSESSION_SUCCESS;
    ret = AudioAdapter::GetInstance().SetDeviceChangeCallback();
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_SUCCESS);

    ret = AudioAdapter::GetInstance().UnsetDeviceChangeCallback();
    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnDeviceChange(action);
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnPreferredOutputDeviceChange001
 * @tc.desc: Notify registered listener when the audio preferred device is updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnPreferredOutputDeviceChange001, TestSize.Level0)
{
    SLOGD("OnPreferredOutputDeviceChange001 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetPreferredOutputDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        auto device = AudioAdapter::GetInstance().GetPreferredOutputDeviceForRendererInfo();
        ret = device.empty();
    });

    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptors availableDevices = audioAdapter.GetAvailableDevices();
    CHECK_AND_RETURN_LOG(availableDevices.size() > 0, "No available devices for testing");
    audioAdapter.SelectOutputDevice(availableDevices[0]);
    sleep(1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnPreferredOutputDeviceChange002
 * @tc.desc: Notify registered listener when the audio preferred device is updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnPreferredOutputDeviceChange002, TestSize.Level0)
{
    SLOGD("OnPreferredOutputDeviceChange002 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetPreferredOutputDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        auto device = AudioAdapter::GetInstance().GetPreferredOutputDeviceForRendererInfo();
        ret = device.empty();
    });
    AudioAdapter::GetInstance().UnsetPreferredOutputDeviceChangeCallback();

    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptors availableDevices = audioAdapter.GetAvailableDevices();
    CHECK_AND_RETURN_LOG(availableDevices.size() > 0, "No available devices for testing");
    audioAdapter.SelectOutputDevice(availableDevices[0]);
    sleep(1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SelectOutputDevice001
 * @tc.desc: Test SelectOutputDevice with a valid device descriptor that matches one available device.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, SelectOutputDevice001, TestSize.Level0)
{
    SLOGD("SelectOutputDevice001 begin!");
    AudioAdapter::GetInstance().Init();
    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptorWithSptr desc {new OHOS::AudioStandard::AudioDeviceDescriptor()};
    auto ret = audioAdapter.SelectOutputDevice(desc);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: SelectOutputDevice002
 * @tc.desc: Test SelectOutputDevice with a valid device descriptor that matches one available device.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, SelectOutputDevice002, TestSize.Level0)
{
    SLOGD("SelectOutputDevice002 begin!");
    AudioAdapter::GetInstance().Init();
    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptors availableDevices = audioAdapter.GetAvailableDevices();

    CHECK_AND_RETURN_LOG(availableDevices.size() > 0, "No available devices for testing");
    auto testDevice = availableDevices[0];
    AudioDeviceDescriptorWithSptr desc {new OHOS::AudioStandard::AudioDeviceDescriptor()};
    desc->deviceCategory_ = testDevice->deviceCategory_;
    EXPECT_NE(desc->deviceType_, testDevice->deviceType_);
    int32_t ret = audioAdapter.SelectOutputDevice(desc);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}
