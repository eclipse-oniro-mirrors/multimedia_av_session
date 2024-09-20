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
    FocusSessionStrategy focusSessionStrategy;
    std::unique_ptr<AudioRendererChangeInfo> info = std::make_unique<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
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
    FocusSessionStrategy focusSessionStrategy;
    std::unique_ptr<AudioRendererChangeInfo> info = std::make_unique<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    
    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
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
    FocusSessionStrategy focusSessionStrategy;
    std::unique_ptr<AudioRendererChangeInfo> info = std::make_unique<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RUNNING;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
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
    FocusSessionStrategy focusSessionStrategy;
    std::unique_ptr<AudioRendererChangeInfo> info = std::make_unique<AudioRendererChangeInfo>();
    info->clientUID = 1;
    info->sessionId = 2;
    info->rendererState = RendererState::RENDERER_RUNNING;
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info));
    
    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
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
    FocusSessionStrategy focusSessionStrategy;
    std::unique_ptr<AudioRendererChangeInfo> info1 = std::make_unique<AudioRendererChangeInfo>();
    info1->clientUID = 1;
    info1->sessionId = 2;
    info1->rendererState = RendererState::RENDERER_RELEASED;

    std::unique_ptr<AudioRendererChangeInfo> info2 = std::make_unique<AudioRendererChangeInfo>();
    info2->clientUID = 3;
    info2->sessionId = 4;
    info2->rendererState = RendererState::RENDERER_RUNNING;
    
    AudioRendererChangeInfos infos;
    infos.push_back(std::move(info1));
    infos.push_back(std::move(info2));

    auto func = [](const FocusSessionStrategy::FocusSessionChangeInfo&) {};
    focusSessionStrategy.RegisterFocusSessionChangeCallback(func);
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
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
    std::unique_ptr<AudioRendererChangeInfo> info = std::make_unique<AudioRendererChangeInfo>();
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
    FocusSessionStrategy::FocusSessionChangeInfo sessionInfo;
    bool ret = focusSessionStrategy.SelectFocusSession(infos, sessionInfo);
    EXPECT_EQ(ret, false);
    AudioRendererChangeInfo audioRendererChangeInfo;
    audioRendererChangeInfo.clientUID = 1;
    audioRendererChangeInfo.sessionId = 2;
    audioRendererChangeInfo.rendererState = RendererState::RENDERER_RELEASED;
    ret = focusSessionStrategy.IsFocusSession(audioRendererChangeInfo);
    EXPECT_EQ(ret, false);
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
    
    std::unique_ptr<AudioRendererChangeInfo> info = std::make_unique<AudioRendererChangeInfo>();
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
    FocusSessionStrategy::FocusSessionChangeInfo sessionInfo;
    bool ret = focusSessionStrategy.SelectFocusSession(infos, sessionInfo);
    EXPECT_EQ(ret, false);
    AudioRendererChangeInfo audioRendererChangeInfo;
    audioRendererChangeInfo.clientUID = 1;
    audioRendererChangeInfo.sessionId = 2;
    audioRendererChangeInfo.rendererState = RendererState::RENDERER_RUNNING;
    ret = focusSessionStrategy.IsFocusSession(audioRendererChangeInfo);
    EXPECT_EQ(ret, true);
    SLOGD("IsFocusSession002 end!");
}