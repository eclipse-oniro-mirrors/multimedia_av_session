/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "audio_adapter.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "audio_info.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using OHOS::AudioStandard::AudioRendererChangeInfo;
using OHOS::AudioStandard::RendererState;

class AudioAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static constexpr int32_t TEST_CLIENT_UID = 1;
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
static HWTEST(AudioAdapterTest, OnRendererStateChange001, TestSize.Level1)
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
static HWTEST(AudioAdapterTest, MuteAudioStream001, TestSize.Level1)
{
    SLOGI("MuteAudioStream001 begin!");
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
    auto ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_NE(ret, AVSESSION_ERROR_BASE);
}

/**
* @tc.name: UnMuteAudioStream001
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream001, TestSize.Level1)
{
    SLOGI("UnMuteAudioStream001 begin!");
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
    auto ret = AudioAdapter::GetInstance().UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_NE(ret, AVSESSION_ERROR_BASE);
}

/**
* @tc.name: GetRendererRunning001
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, GetRendererRunning001, TestSize.Level1)
{
    SLOGI("GetRendererRunning001 begin!");
    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().GetRendererRunning(AudioAdapterTest::TEST_CLIENT_UID);
    SLOGI("GetRendererRunning001 end!");
}

/**
* @tc.name: GetRendererRunning002
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, GetRendererRunning002, TestSize.Level1)
{
    SLOGI("GetRendererRunning002 begin!");
    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().GetRendererRunning(AudioAdapterTest::TEST_SESSION_FAIL_ID);
    SLOGI("GetRendererRunning002 end!");
}

/**
* @tc.name: PauseAudioStream001
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, PauseAudioStream001, TestSize.Level1)
{
    SLOGD("PauseAudioStream001 begin!");
    AudioAdapter::GetInstance().Init();
    int32_t uid = 10001;
    OHOS::AudioStandard::StreamUsage streamUsage {};
    int32_t ret = AudioAdapter::GetInstance().PauseAudioStream(uid, streamUsage);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGD("PauseAudioStream001 end!");
}