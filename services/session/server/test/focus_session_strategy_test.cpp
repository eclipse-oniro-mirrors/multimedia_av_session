/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "audio_info.h"
#include "audio_adapter.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "focus_session_strategy.h"

using namespace OHOS;
using namespace OHOS::AVSession;
using OHOS::AudioStandard::AudioRendererChangeInfo;
using OHOS::AudioStandard::RendererState;

static std::string g_errLog;
constexpr auto USAGE_INVALID = static_cast<AudioStandard::StreamUsage>(999);
static void MyLogCallback(const LogType type, const LogLevel level,
    const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}

class FocusSessionStrategyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void FocusSessionStrategyTest::SetUpTestCase()
{}

void FocusSessionStrategyTest::TearDownTestCase()
{}

void FocusSessionStrategyTest::SetUp()
{}

void FocusSessionStrategyTest::TearDown()
{}

/**
 * @tc.name: HandleAudioRenderStateChangeEvent001
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent001, testing::ext::TestSize.Level0)
{
    SLOGD("HandleAudioRenderStateChangeEvent001 begin!");
    LOG_SetCallback(MyLogCallback);
    FocusSessionStrategy focusSessionStrategy;
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGD("HandleAudioRenderStateChangeEvent001 end!");
}

/**
 * @tc.name: HandleAudioRenderStateChangeEvent002
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent002, testing::ext::TestSize.Level0)
{
    SLOGD("HandleAudioRenderStateChangeEvent002 begin!");
    LOG_SetCallback(MyLogCallback);
    FocusSessionStrategy focusSessionStrategy;
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    
    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&, bool) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGD("HandleAudioRenderStateChangeEvent002 end!");
}

/**
 * @tc.name: HandleAudioRenderStateChangeEvent003
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent003, testing::ext::TestSize.Level0)
{
    SLOGD("HandleAudioRenderStateChangeEvent003 begin!");
    LOG_SetCallback(MyLogCallback);
    FocusSessionStrategy focusSessionStrategy;
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RUNNING;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGD("HandleAudioRenderStateChangeEvent003 end!");
}

/**
 * @tc.name: HandleAudioRenderStateChangeEvent004
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent004, testing::ext::TestSize.Level0)
{
    SLOGD("HandleAudioRenderStateChangeEvent004 begin!");
    LOG_SetCallback(MyLogCallback);
    FocusSessionStrategy focusSessionStrategy;
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RUNNING;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    
    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&, bool) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGD("HandleAudioRenderStateChangeEvent004 end!");
}

/**
 * @tc.name: HandleAudioRenderStateChangeEvent005
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent005, testing::ext::TestSize.Level0)
{
    SLOGD("HandleAudioRenderStateChangeEvent005 begin!");
    LOG_SetCallback(MyLogCallback);
    FocusSessionStrategy focusSessionStrategy;
    std::shared_ptr<AudioRendererChangeInfo> info1 = std::make_shared<AudioRendererChangeInfo>();
    info1->clientUID = 1;
    info1->sessionId = 2;
    info1->rendererState = RendererState::RENDERER_RELEASED;

    std::shared_ptr<AudioRendererChangeInfo> info2 = std::make_shared<AudioRendererChangeInfo>();
    info2->clientUID = 3;
    info2->sessionId = 4;
    info2->rendererState = RendererState::RENDERER_RUNNING;
    
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info1));
    infos.push_back(std::move(info2));

    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&, bool) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGD("HandleAudioRenderStateChangeEvent005 end!");
}

/**
 * @tc.name: IsFocusSession001
 * @tc.desc: Test IsFocusSession
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, IsFocusSession001, testing::ext::TestSize.Level0)
{
    SLOGD("IsFocusSession001 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    FocusSessionStrategy focusSessionStrategy;
    auto func = [](const OHOS::AVSession::FocusSessionStrategy::FocusSessionChangeInfo&) {
        return false;
    };
    focusSessionStrategy.RegisterFocusSessionSelector(func);
    AudioRendererChangeInfo audioRendererChangeInfo;
    audioRendererChangeInfo.clientUID = 1;
    audioRendererChangeInfo.clientPid = 1;
    std::pair<int32_t, int32_t> key = std::make_pair(audioRendererChangeInfo.clientUID,
        audioRendererChangeInfo.clientPid);
    audioRendererChangeInfo.sessionId = 2;
    audioRendererChangeInfo.rendererState = RendererState::RENDERER_RELEASED;
    bool ret = focusSessionStrategy.IsFocusSession(key);
    EXPECT_EQ(ret, true);
    SLOGD("IsFocusSession001 end!");
}

/**
 * @tc.name: IsFocusSession002
 * @tc.desc: Test IsFocusSession
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, IsFocusSession002, testing::ext::TestSize.Level0)
{
    SLOGD("IsFocusSession002 begin!");
    
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    FocusSessionStrategy focusSessionStrategy;
    auto func = [](const OHOS::AVSession::FocusSessionStrategy::FocusSessionChangeInfo&) {
        return true;
    };
    focusSessionStrategy.RegisterFocusSessionSelector(func);
    AudioRendererChangeInfo audioRendererChangeInfo;
    audioRendererChangeInfo.clientUID = 1;
    audioRendererChangeInfo.clientPid = 1;
    std::pair<int32_t, int32_t> key = std::make_pair(audioRendererChangeInfo.clientUID,
        audioRendererChangeInfo.clientPid);
    audioRendererChangeInfo.sessionId = 2;
    audioRendererChangeInfo.rendererState = RendererState::RENDERER_RUNNING;
    bool ret = focusSessionStrategy.IsFocusSession(key);
    EXPECT_EQ(ret, true);
    SLOGD("IsFocusSession002 end!");
}

/**
* @tc.name: HandleAudioRenderStateChangeEvent006
* @tc.desc: Test HandleAudioRenderStateChangeEvent
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent006, testing::ext::TestSize.Level0)
{
    SLOGD("HandleAudioRenderStateChangeEvent006 begin!");
    LOG_SetCallback(MyLogCallback);
    FocusSessionStrategy focusSessionStrategy;
    std::shared_ptr<AudioRendererChangeInfo> info1 = std::make_shared<AudioRendererChangeInfo>();
    info1->clientUID = 1;
    info1->sessionId = 2;
    info1->rendererState = RendererState::RENDERER_RELEASED;

    std::shared_ptr<AudioRendererChangeInfo> info2 = std::make_shared<AudioRendererChangeInfo>();
    info2->clientUID = 3;
    info2->sessionId = 4;
    info2->rendererState = RendererState::RENDERER_RUNNING;
    
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info1));
    infos.push_back(std::move(info2));

    focusSessionStrategy.currentStates_.insert({std::make_pair(1, 1), 1});

    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&, bool) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGD("HandleAudioRenderStateChangeEvent006 end!");
}

/**
* @tc.name: UpdateFocusSession001
* @tc.desc: Test UpdateFocusSession
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, UpdateFocusSession001, testing::ext::TestSize.Level0)
{
    SLOGD("UpdateFocusSession001 begin!");
    LOG_SetCallback(MyLogCallback);
    FocusSessionStrategy focusSessionStrategy;
    auto func = [](const OHOS::AVSession::FocusSessionStrategy::FocusSessionChangeInfo&) {
        return false;
    };
    focusSessionStrategy.RegisterFocusSessionSelector(func);
    std::pair<int32_t, int32_t> key = std::make_pair(1, 1);
    focusSessionStrategy.UpdateFocusSession(key);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGD("UpdateFocusSession001 end!");
}

/**
* @tc.name: IsFocusSession003
* @tc.desc: Test IsFocusSession
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, IsFocusSession003, testing::ext::TestSize.Level0)
{
    SLOGD("IsFocusSession003 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.lastStates_.insert({std::make_pair(1, 1), 2});
    std::pair<int32_t, int32_t> key = std::make_pair(1, 1);
    bool ret = focusSessionStrategy.IsFocusSession(key);
    EXPECT_EQ(ret, false);
    SLOGD("IsFocusSession003 end!");
}

/**
* @tc.name: CheckFocusSessionStop001
* @tc.desc: Test CheckFocusSessionStop
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, CheckFocusSessionStop001, testing::ext::TestSize.Level0)
{
    SLOGD("CheckFocusSessionStop001 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.lastStates_.insert({std::make_pair(1, 1), 2});
    std::pair<int32_t, int32_t> key = std::make_pair(1, 1);
    bool ret = focusSessionStrategy.CheckFocusSessionStop(key);
    EXPECT_EQ(ret, true);
    SLOGD("CheckFocusSessionStop001 end!");
}

/**
* @tc.name: DelayStopFocusSession001
* @tc.desc: Test DelayStopFocusSession
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, DelayStopFocusSession001, testing::ext::TestSize.Level0)
{
    SLOGD("DelayStopFocusSession001 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.lastStates_.insert({std::make_pair(1, 1), 1});
    std::pair<int32_t, int32_t> key = std::make_pair(1, 1);
    focusSessionStrategy.DelayStopFocusSession(key);
    sleep(6);
    SLOGD("DelayStopFocusSession001 end!");
}

/**
* @tc.name: DelayStopFocusSession002
* @tc.desc: Test DelayStopFocusSession
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, DelayStopFocusSession002, testing::ext::TestSize.Level0)
{
    SLOGD("DelayStopFocusSession002 begin!");
    FocusSessionStrategy focusSessionStrategy;
    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&, bool) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.lastStates_.insert({std::make_pair(1, 1), 2});
    std::pair<int32_t, int32_t> key = std::make_pair(1, 1);
    focusSessionStrategy.DelayStopFocusSession(key);
    sleep(6);
    SLOGD("DelayStopFocusSession002 end!");
}

/**
* @tc.name: DelayStopFocusSession003
* @tc.desc: Test DelayStopFocusSession
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, DelayStopFocusSession003, testing::ext::TestSize.Level0)
{
    SLOGD("DelayStopFocusSession003 begin!");
    FocusSessionStrategy focusSessionStrategy;
    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&, bool) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.lastStates_.insert({std::make_pair(1, 1), 1});
    std::pair<int32_t, int32_t> key = std::make_pair(1, 1);
    focusSessionStrategy.DelayStopFocusSession(key);
    sleep(6);
    SLOGD("DelayStopFocusSession003 end!");
}

/**
* @tc.name: ProcAudioRenderChange001
* @tc.desc: Test ProcAudioRenderChange
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange001, testing::ext::TestSize.Level0)
{
    SLOGI("ProcAudioRenderChange001 begin!");
    std::shared_ptr<AudioRendererChangeInfo> infoA = std::make_shared<AudioRendererChangeInfo>();
    infoA->clientUID = 1;
    infoA->sessionId = 1;
    infoA->rendererState = RendererState::RENDERER_RUNNING;
    infoA->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    std::shared_ptr<AudioRendererChangeInfo> infoB = std::make_shared<AudioRendererChangeInfo>();
    infoB->clientUID = 1;
    infoB->sessionId = 2;
    infoB->rendererState = RendererState::RENDERER_RUNNING;
    infoB->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(std::move(infoA));
    infos.push_back(std::move(infoB));
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.ProcAudioRenderChange(infos);
    SLOGE("ProcAudioRenderChange001 num:%{public}d aft ProcAudioRenderChange",
        static_cast<int>(focusSessionStrategy.audioPlayingUids_.size()));
    EXPECT_TRUE(focusSessionStrategy.audioPlayingUids_.size() == 1);
    SLOGI("ProcAudioRenderChange001 end!");
}

/**
* @tc.name: ProcAudioRenderChange002
* @tc.desc: Test ProcAudioRenderChange
* @tc.type: FUNC
*/
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange002, testing::ext::TestSize.Level0)
{
    SLOGI("ProcAudioRenderChange002 begin!");
    std::shared_ptr<AudioRendererChangeInfo> infoA = std::make_shared<AudioRendererChangeInfo>();
    infoA->clientUID = 2;
    infoA->sessionId = 1;
    infoA->rendererState = RendererState::RENDERER_RELEASED;
    infoA->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    std::shared_ptr<AudioRendererChangeInfo> infoB = std::make_shared<AudioRendererChangeInfo>();
    infoB->clientUID = 2;
    infoB->sessionId = 2;
    infoB->rendererState = RendererState::RENDERER_RUNNING;
    infoB->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_GAME;

    AudioRendererChangeInfos infos;
    infos.push_back(std::move(infoA));
    infos.push_back(std::move(infoB));
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.ProcAudioRenderChange(infos);
    SLOGE("ProcAudioRenderChange002 num:%{public}d aft ProcAudioRenderChange",
        static_cast<int>(focusSessionStrategy.audioPlayingUids_.size()));
    EXPECT_TRUE(focusSessionStrategy.audioPlayingUids_.size() == 0);
    SLOGI("ProcAudioRenderChange002 end!");
}

/**
 * @tc.name: ProcAudioRenderChange003
 * @tc.desc: Test non-ANCO uid, allowed usage, RUNNING, enter state machine (playingKey == key).
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange003, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange003 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.currentStates_.clear();
    int32_t notAnco = focusSessionStrategy.ancoUid + 1;

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = notAnco;
    info->clientPid = 101;
    info->sessionId = 1;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { notAnco, 101 };
    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 1);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) != focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange003 end!");
}

/**
 * @tc.name: ProcAudioRenderChange004
 * @tc.desc: Test non-ANCO uid, invalid usage (not in whitelist), RUNNING, state machine not updated.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange004, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange004 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.currentStates_.clear();
    int32_t notAnco = focusSessionStrategy.ancoUid + 2;

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = notAnco;
    info->clientPid = 102;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = USAGE_INVALID;

    focusSessionStrategy.controlBundleList_.insert(std::make_pair(info->clientUID, info->clientPid));
    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { notAnco, 102 };
    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 0);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) == focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange004 end!");
}

/**
 * @tc.name: ProcAudioRenderChange005
 * @tc.desc: Test ANCO uid, allowed usage, RUNNING; not continue and enter state machine (playingKey == key).
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange005, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange005 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.currentStates_.clear();

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = focusSessionStrategy.ancoUid;
    info->clientPid = 103;
    info->sessionId = 3;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { focusSessionStrategy.ancoUid, 103 };
    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 1);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) != focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange005 end!");
}

/**
 * @tc.name: ProcAudioRenderChange006
 * @tc.desc: Test ANCO uid and invalid usage, RUNNING; should continue early and skip state machine updates.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange006, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange006 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.currentStates_.clear();

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = focusSessionStrategy.ancoUid;
    info->clientPid = 104;
    info->sessionId = 4;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = USAGE_INVALID;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { focusSessionStrategy.ancoUid, 104 };
    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 0);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) == focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange006 end!");
}

/**
 * @tc.name: ProcAudioRenderChange007
 * @tc.desc: Test Non-ANCO uid, allowed usage, RELEASED, pass guards and update state machine (playingKey != key).
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange007, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange007 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.currentStates_.clear();
    int32_t notAnco = focusSessionStrategy.ancoUid + 5;

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = notAnco;
    info->clientPid = 105;
    info->sessionId = 5;
    info->rendererState = RendererState::RENDERER_RELEASED;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { notAnco, 105 };
    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 0);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) != focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange007 end!");
}

/**
 * @tc.name: ProcAudioRenderChange008
 * @tc.desc: Test noANCO uid with invalid usage, RELEASED; rejected by media whitelist; no state machine updates.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange008, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange008 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.currentStates_.clear();
    int32_t notAnco = focusSessionStrategy.ancoUid + 6;

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = notAnco;
    info->clientPid = 106;
    info->sessionId = 6;
    info->rendererState = RendererState::RENDERER_RELEASED;
    info->rendererInfo.streamUsage = USAGE_INVALID;

    focusSessionStrategy.controlBundleList_.insert(std::make_pair(info->clientUID, info->clientPid));
    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { notAnco, 106 };
    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 0);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) == focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange008 end!");
}

/**
 * @tc.name: ProcAudioRenderChange009
 * @tc.desc: Test ANCO uid with allowed usage, RELEASED; passes guards and writes state (non-RUNNING path).
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange009, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange009 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.currentStates_.clear();

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = focusSessionStrategy.ancoUid;
    info->clientPid = 107;
    info->sessionId = 7;
    info->rendererState = RendererState::RENDERER_RELEASED;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { focusSessionStrategy.ancoUid, 107 };
    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 0);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) != focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange009 end!");
}

/**
 * @tc.name: ProcAudioRenderChange010
 * @tc.desc: Test ANCO uid with invalid usage, RELEASED; continue early due to ANCO guard; no state machine updates.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange010, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange010 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    focusSessionStrategy.currentStates_.clear();

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = focusSessionStrategy.ancoUid;
    info->clientPid = 108;
    info->sessionId = 8;
    info->rendererState = RendererState::RENDERER_RELEASED;
    info->rendererInfo.streamUsage = USAGE_INVALID;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { focusSessionStrategy.ancoUid, 108 };
    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 0);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) == focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange010 end!");
}

/**
 * @tc.name: ProcAudioRenderChange011
 * @tc.desc: Test it == currentStates_.end() true.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange011, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange011 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.currentStates_.clear();
    int32_t uid = focusSessionStrategy.ancoUid + 9;
    int32_t pid = 109;

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = uid;
    info->clientPid = pid;
    info->sessionId = 9;
    info->rendererState = RendererState::RENDERER_RELEASED;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { uid, pid };
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) != focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange011 end!");
}

/**
 * @tc.name: ProcAudioRenderChange012
 * @tc.desc: Test it == currentStates_.end() false (key already exists).
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange012, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange012 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.currentStates_.clear();
    int32_t uid = focusSessionStrategy.ancoUid + 10;
    int32_t pid = 110;
    std::pair<int32_t, int32_t> key = { uid, pid };
    focusSessionStrategy.currentStates_.insert({ key, 0 });

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = uid;
    info->clientPid = pid;
    info->sessionId = 10;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);
    
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key)->second == focusSessionStrategy.runningState);
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) != focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange012 end!");
}

/**
 * @tc.name: ProcAudioRenderChange013
 * @tc.desc: Test info->rendererState == RENDERER_RUNNING is true.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange013, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange013 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    int32_t uid = focusSessionStrategy.ancoUid + 11;

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = uid;
    info->clientPid = 111;
    info->sessionId = 11;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 1);
    SLOGI("ProcAudioRenderChange013 end!");
}

/**
 * @tc.name: ProcAudioRenderChange014
 * @tc.desc: Test info->rendererState == RENDERER_RUNNING is false.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange014, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange014 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.audioPlayingUids_.clear();
    int32_t uid = focusSessionStrategy.ancoUid + 12;

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = uid;
    info->clientPid = 112;
    info->sessionId = 12;
    info->rendererState = RendererState::RENDERER_RELEASED;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    EXPECT_EQ(focusSessionStrategy.audioPlayingUids_.size(), 0);
    SLOGI("ProcAudioRenderChange014 end!");
}

/**
 * @tc.name: ProcAudioRenderChange015
 * @tc.desc: Test playingKey != key is false.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange015, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange015 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.currentStates_.clear();
    int32_t uid = focusSessionStrategy.ancoUid + 13;

    auto info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = uid;
    info->clientPid = 113;
    info->sessionId = 13;
    info->rendererState = RendererState::RENDERER_RUNNING;
    info->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key = { uid, 113 };
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key) != focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange015 end!");
}

/**
 * @tc.name: ProcAudioRenderChange016
 * @tc.desc: Test playingKey != key is true.
 * @tc.type: FUNC
 */
static HWTEST_F(FocusSessionStrategyTest, ProcAudioRenderChange016, testing::ext::TestSize.Level4)
{
    SLOGI("ProcAudioRenderChange016 begin!");
    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.currentStates_.clear();

    auto info1 = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info1 != nullptr);
    info1->clientUID = focusSessionStrategy.ancoUid + 14;
    info1->clientPid = 114;
    info1->sessionId = 14;
    info1->rendererState = RendererState::RENDERER_RUNNING;
    info1->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    auto info2 = std::make_shared<AudioRendererChangeInfo>();
    CHECK_AND_RETURN(info2 != nullptr);
    info2->clientUID = focusSessionStrategy.ancoUid + 15;
    info2->clientPid = 115;
    info2->sessionId = 15;
    info2->rendererState = RendererState::RENDERER_RELEASED;
    info2->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;

    AudioRendererChangeInfos infos;
    infos.push_back(info1);
    infos.push_back(info2);
    focusSessionStrategy.ProcAudioRenderChange(infos);

    std::pair<int32_t, int32_t> key1 = { info1->clientUID, info1->clientPid };
    std::pair<int32_t, int32_t> key2 = { info2->clientUID, info2->clientPid };
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key1) != focusSessionStrategy.currentStates_.end());
    EXPECT_TRUE(focusSessionStrategy.currentStates_.find(key2) != focusSessionStrategy.currentStates_.end());
    SLOGI("ProcAudioRenderChange016 end!");
}