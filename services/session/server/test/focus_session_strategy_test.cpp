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
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent001, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent002, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent003, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent004, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent005, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, IsFocusSession001, testing::ext::TestSize.Level1)
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
    std::pair<int32_t, int32_t> key = std::make_pair(audioRendererChangeInfo.clientUID, audioRendererChangeInfo.clientPid);
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
static HWTEST_F(FocusSessionStrategyTest, IsFocusSession002, testing::ext::TestSize.Level1)
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
    std::pair<int32_t, int32_t> key = std::make_pair(audioRendererChangeInfo.clientUID, audioRendererChangeInfo.clientPid);
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
static HWTEST_F(FocusSessionStrategyTest, HandleAudioRenderStateChangeEvent006, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, UpdateFocusSession001, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, IsFocusSession003, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, CheckFocusSessionStop001, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, DelayStopFocusSession001, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, DelayStopFocusSession002, testing::ext::TestSize.Level1)
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
static HWTEST_F(FocusSessionStrategyTest, DelayStopFocusSession003, testing::ext::TestSize.Level1)
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
