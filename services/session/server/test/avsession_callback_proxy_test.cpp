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
#include "avsession_log.h"
#include "iservice_registry.h"
#include "avmedia_description.h"
#include "av_file_descriptor.h"
#include "system_ability_definition.h"
#include "avsession_callback_proxy.h"

using namespace OHOS::AVSession;

class AVSessionCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    OHOS::sptr<AVSessionCallbackProxy> aVSessionCallbackProxy;
};

void AVSessionCallbackProxyTest::SetUpTestCase()
{
}

void AVSessionCallbackProxyTest::TearDownTestCase()
{
}

void AVSessionCallbackProxyTest::SetUp()
{
    auto mgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGI("failed to get sa mgr");
        return;
    }
    auto object = mgr->GetSystemAbility(OHOS::AVSESSION_SERVICE_ID);
    if (object == nullptr) {
        SLOGI("failed to get service");
        return;
    }
    aVSessionCallbackProxy = OHOS::iface_cast<AVSessionCallbackProxy>(object);
}

void AVSessionCallbackProxyTest::TearDown()
{
}

/**
 * @tc.name: OnAVCallAnswer001
 * @tc.desc: Test OnAVCallAnswer
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnAVCallAnswer001, testing::ext::TestSize.Level1)
{
    SLOGI("OnAVCallAnswer001, start");
    aVSessionCallbackProxy->OnAVCallAnswer();
    SLOGI("OnAVCallAnswer001, end");
}

/**
 * @tc.name: OnAVCallHangUp001
 * @tc.desc: Test OnAVCallHangUp
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnAVCallHangUp001, testing::ext::TestSize.Level1)
{
    SLOGI("OnAVCallHangUp001, start");
    aVSessionCallbackProxy->OnAVCallHangUp();
    SLOGI("OnAVCallHangUp001, end");
}

/**
 * @tc.name: OnAVCallToggleCallMute001
 * @tc.desc: Test OnAVCallToggleCallMute
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnAVCallToggleCallMute001, testing::ext::TestSize.Level1)
{
    SLOGI("OnAVCallToggleCallMute001, start");
    aVSessionCallbackProxy->OnAVCallToggleCallMute();
    SLOGI("OnAVCallToggleCallMute001, end");
}

/**
 * @tc.name: OnPlay001
 * @tc.desc: Test OnPlay
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnPlay001, testing::ext::TestSize.Level1)
{
    SLOGI("OnPlay001, start");
    aVSessionCallbackProxy->OnPlay();
    SLOGI("OnPlay001, end");
}

/**
 * @tc.name: OnPause001
 * @tc.desc: Test OnPause
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnPause001, testing::ext::TestSize.Level1)
{
    SLOGI("OnPause001, start");
    aVSessionCallbackProxy->OnPause();
    SLOGI("OnPause001, end");
}

/**
 * @tc.name: OnStop001
 * @tc.desc: Test OnStop
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnStop001, testing::ext::TestSize.Level1)
{
    SLOGI("OnStop001, start");
    aVSessionCallbackProxy->OnStop();
    SLOGI("OnStop001, end");
}

/**
 * @tc.name: OnPlayNext001
 * @tc.desc: Test OnPlayNext
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnPlayNext001, testing::ext::TestSize.Level1)
{
    SLOGI("OnPlayNext001, start");
    aVSessionCallbackProxy->OnPlayNext();
    SLOGI("OnPlayNext001, end");
}

/**
 * @tc.name: OnPlayPrevious001
 * @tc.desc: Test OnPlayPrevious
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnPlayPrevious001, testing::ext::TestSize.Level1)
{
    SLOGI("OnPlayPrevious001, start");
    aVSessionCallbackProxy->OnPlayPrevious();
    SLOGI("OnPlayPrevious001, end");
}

/**
 * @tc.name: OnFastForward001
 * @tc.desc: Test OnFastForward
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnFastForward001, testing::ext::TestSize.Level1)
{
    SLOGI("OnFastForward001, start");
    int64_t time = 0;
    aVSessionCallbackProxy->OnFastForward(time);
    SLOGI("OnFastForward001, end");
}

/**
 * @tc.name: OnRewind001
 * @tc.desc: Test OnRewind
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnRewind001, testing::ext::TestSize.Level1)
{
    SLOGI("OnRewind001, start");
    int64_t time = 0;
    aVSessionCallbackProxy->OnRewind(time);
    SLOGI("OnRewind001, end");
}

/**
 * @tc.name: OnSeek001
 * @tc.desc: Test OnSeek
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnSeek001, testing::ext::TestSize.Level1)
{
    SLOGI("OnSeek001, start");
    int64_t time = 0;
    aVSessionCallbackProxy->OnSeek(time);
    SLOGI("OnSeek001, end");
}

/**
 * @tc.name: OnSeek001
 * @tc.desc: Test OnSetSpeed
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnSetSpeed001, testing::ext::TestSize.Level1)
{
    SLOGI("OnSetSpeed001, start");
    double speed = 0;
    aVSessionCallbackProxy->OnSetSpeed(speed);
    SLOGI("OnSetSpeed001, end");
}

/**
 * @tc.name: OnSetLoopMode001
 * @tc.desc: Test OnSetLoopMode
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnSetLoopMode001, testing::ext::TestSize.Level1)
{
    SLOGI("OnSetLoopMode001, start");
    int32_t loopMode = 0;
    aVSessionCallbackProxy->OnSetLoopMode(loopMode);
    SLOGI("OnSetLoopMode001, end");
}

/**
 * @tc.name: OnToggleFavorite001
 * @tc.desc: Test OnToggleFavorite
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnToggleFavorite001, testing::ext::TestSize.Level1)
{
    SLOGI("OnToggleFavorite001, start");
    std::string mediaId = "mediaId";
    aVSessionCallbackProxy->OnToggleFavorite(mediaId);
    SLOGI("OnToggleFavorite001, end");
}

/**
 * @tc.name: OnMediaKeyEvent001
 * @tc.desc: Test OnMediaKeyEvent
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnMediaKeyEvent001, testing::ext::TestSize.Level1)
{
    SLOGI("OnMediaKeyEvent001, start");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    aVSessionCallbackProxy->OnMediaKeyEvent(*keyEvent);
    SLOGI("OnMediaKeyEvent001, end");
}

/**
 * @tc.name: OnOutputDeviceChange001
 * @tc.desc: Test OnOutputDeviceChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnOutputDeviceChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnOutputDeviceChange001, start");
    int32_t connectionState = 0;
    OutputDeviceInfo outputDeviceInfo;
    aVSessionCallbackProxy->OnOutputDeviceChange(connectionState, outputDeviceInfo);
    SLOGI("OnOutputDeviceChange001, end");
}

/**
 * @tc.name: OnCommonCommand001
 * @tc.desc: Test OnCommonCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnCommonCommand001, testing::ext::TestSize.Level1)
{
    SLOGI("OnCommonCommand001, start");
    std::string commonCommand = "commonCommand";
    OHOS::AAFwk::WantParams commandArgs;
    aVSessionCallbackProxy->OnCommonCommand(commonCommand, commandArgs);
    SLOGI("OnCommonCommand001, end");
}

/**
 * @tc.name: OnSkipToQueueItem001
 * @tc.desc: Test OnSkipToQueueItem
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnSkipToQueueItem001, testing::ext::TestSize.Level1)
{
    SLOGI("OnSkipToQueueItem001, start");
    int32_t itemId = 0;
    aVSessionCallbackProxy->OnSkipToQueueItem(itemId);
    SLOGI("OnSkipToQueueItem001, end");
}

/**
 * @tc.name: OnPlayFromAssetId001
 * @tc.desc: Test OnPlayFromAssetId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnPlayFromAssetId001, testing::ext::TestSize.Level1)
{
    SLOGI("OnPlayFromAssetId001, start");
    int64_t assetId = 0;
    aVSessionCallbackProxy->OnPlayFromAssetId(assetId);
    SLOGI("OnPlayFromAssetId001, end");
}

/**
 * @tc.name: OnCastDisplayChange001
 * @tc.desc: Test OnCastDisplayChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackProxyTest, OnCastDisplayChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnCastDisplayChange001, start");
    CastDisplayInfo castDisplayInfo;
    aVSessionCallbackProxy->OnCastDisplayChange(castDisplayInfo);
    SLOGI("OnCastDisplayChange001, end");
}