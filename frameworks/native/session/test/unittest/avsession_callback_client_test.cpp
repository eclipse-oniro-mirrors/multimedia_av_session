/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#include "gtest/gtest.h"
 
#include "avsession_callback_client.h"
#include "avsession_errors.h"
#include "avsession_log.h"

using namespace testing::ext;
 
namespace OHOS {
namespace AVSession {
 
namespace {
std::string g_errLog;
void MyLogCallback(const LogType type, const LogLevel level, const unsigned int domain, const char *tag,
                   const char *msg)
{
    g_errLog = msg;
}
}  // namespace
 
class AVSessionCallbackImpl : public AVSessionCallback {
public:
    void OnPlay(const AVControlCommand& cmd) override {};
    void OnPause() override {};
    void OnStop() override {};
    void OnPlayNext(const AVControlCommand& cmd) override {};
    void OnPlayPrevious(const AVControlCommand& cmd) override {};
    void OnFastForward(int64_t time, const AVControlCommand& cmd) override {};
    void OnRewind(int64_t time, const AVControlCommand& cmd) override {};
    void OnSeek(int64_t time) override {};
    void OnSetSpeed(double speed) override {};
    void OnSetLoopMode(int32_t loopMode) override {};
    void OnSetTargetLoopMode(int32_t targetLoopMode) override {};
    void OnToggleFavorite(const std::string& mediaId) override {};
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override {};
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override {};
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override {};
    void OnSkipToQueueItem(int32_t itemId) override {};
    void OnAVCallAnswer() override {};
    void OnAVCallHangUp() override {};
    void OnAVCallToggleCallMute() override {};
    void OnPlayFromAssetId(int64_t assetId) override {};
    void OnPlayWithAssetId(const std::string& assetId) override {};
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override {};
    void OnCustomData(const OHOS::AAFwk::WantParams& data) override {};

    ~AVSessionCallbackImpl() override {};
};
 
class AVSessionCallbackClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};
 
void AVSessionCallbackClientTest::SetUpTestCase()
{}
 
void AVSessionCallbackClientTest::TearDownTestCase()
{}
 
void AVSessionCallbackClientTest::SetUp()
{}
 
void AVSessionCallbackClientTest::TearDown()
{}
 
/**
* @tc.name: OnAVCallAnswer001
* @tc.desc: test OnAVCallAnswer
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnAVCallAnswer001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    ErrCode ret = sessionCallbackClient->OnAVCallAnswer();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnAVCallHangUp001
* @tc.desc: test OnAVCallHangUp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnAVCallHangUp001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    ErrCode ret = sessionCallbackClient->OnAVCallHangUp();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnAVCallToggleCallMute001
* @tc.desc: test OnAVCallToggleCallMute
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnAVCallToggleCallMute001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    ErrCode ret = sessionCallbackClient->OnAVCallToggleCallMute();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnPlay001
* @tc.desc: test OnPlay
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnPlay001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    AVControlCommand cmd;
    ErrCode ret = sessionCallbackClient->OnPlay(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnPause001
* @tc.desc: test OnPause
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnPause001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    ErrCode ret = sessionCallbackClient->OnPause();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnStop001
* @tc.desc: test OnStop
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnStop001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    ErrCode ret = sessionCallbackClient->OnStop();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnPlayNext001
* @tc.desc: test OnPlayNext
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnPlayNext001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    AVControlCommand cmd;
    ErrCode ret = sessionCallbackClient->OnPlayNext(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnPlayPrevious001
* @tc.desc: test OnPlayPrevious
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnPlayPrevious001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    AVControlCommand cmd;
    ErrCode ret = sessionCallbackClient->OnPlayPrevious(cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnFastForward001
* @tc.desc: test OnFastForward
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnFastForward001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    int64_t time = 100;
    AVControlCommand cmd;
    ErrCode ret = sessionCallbackClient->OnFastForward(time, cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnRewind001
* @tc.desc: test OnRewind
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnRewind001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    int64_t time = 100;
    AVControlCommand cmd;
    ErrCode ret = sessionCallbackClient->OnRewind(time, cmd);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnSeek001
* @tc.desc: test OnSeek
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnSeek001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    int64_t time = 100;
    ErrCode ret = sessionCallbackClient->OnSeek(time);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnSetSpeed001
* @tc.desc: test OnSetSpeed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnSetSpeed001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    double speed = 100;
    ErrCode ret = sessionCallbackClient->OnSetSpeed(speed);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnSetLoopMode001
* @tc.desc: test OnSetLoopMode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnSetLoopMode001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    int32_t loopMode = 100;
    ErrCode ret = sessionCallbackClient->OnSetLoopMode(loopMode);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnSetTargetLoopMode001
* @tc.desc: test OnSetTargetLoopMode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnSetTargetLoopMode001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    int32_t targetLoopMode = 100;
    ErrCode ret = sessionCallbackClient->OnSetTargetLoopMode(targetLoopMode);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnToggleFavorite001
* @tc.desc: test OnToggleFavorite
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnToggleFavorite001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    const std::string& mediaId = "123";
    ErrCode ret = sessionCallbackClient->OnToggleFavorite(mediaId);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnMediaKeyEvent001
* @tc.desc: test OnMediaKeyEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnMediaKeyEvent001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ErrCode ret = sessionCallbackClient->OnMediaKeyEvent(*(keyEvent.get()));
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnOutputDeviceChange001
* @tc.desc: test OnOutputDeviceChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnOutputDeviceChange001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    const int32_t connectionState = 1;
    const OutputDeviceInfo& outputDeviceInfo = OutputDeviceInfo();
    ErrCode ret = sessionCallbackClient->OnOutputDeviceChange(connectionState, outputDeviceInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnCommonCommand001
* @tc.desc: test OnCommonCommand
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnCommonCommand001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    const std::string& commonCommand = "test";
    const AAFwk::WantParams& commandArgs = AAFwk::WantParams();
    ErrCode ret = sessionCallbackClient->OnCommonCommand(commonCommand, commandArgs);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnSkipToQueueItem001
* @tc.desc: test OnSkipToQueueItem
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnSkipToQueueItem001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    int32_t itemId = 10;
    ErrCode ret = sessionCallbackClient->OnSkipToQueueItem(itemId);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnPlayFromAssetId001
* @tc.desc: test OnPlayFromAssetId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnPlayFromAssetId001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    int64_t assetId = 10;
    ErrCode ret = sessionCallbackClient->OnPlayFromAssetId(assetId);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnPlayWithAssetId001
* @tc.desc: test OnPlayWithAssetId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnPlayWithAssetId001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    const std::string& assetId = "123";
    ErrCode ret = sessionCallbackClient->OnPlayWithAssetId(assetId);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
 
/**
* @tc.name: OnCastDisplayChange001
* @tc.desc: test OnCastDisplayChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionCallbackClientTest, OnCastDisplayChange001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    const CastDisplayInfo& castDisplayInfo = CastDisplayInfo();
    ErrCode ret = sessionCallbackClient->OnCastDisplayChange(castDisplayInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnCustomData001
 * @tc.desc: test OnCustomData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionCallbackClientTest, OnCustomData001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    EXPECT_NE(sessionCallbackClient, nullptr);
    OHOS::AAFwk::WantParams extras;
    ErrCode ret = sessionCallbackClient->OnCustomData(extras);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnDesktopLyricVisibilityChanged001
 * @tc.desc: test OnDesktopLyricVisibilityChanged
 * @tc.type: FUNC
 * @tc.require: #1998
 */
HWTEST_F(AVSessionCallbackClientTest, OnDesktopLyricVisibilityChanged001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    ASSERT_NE(sessionCallback, nullptr);
    sessionCallback->OnDesktopLyricVisibilityChanged(true);
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    ASSERT_NE(sessionCallbackClient, nullptr);
    ErrCode ret = sessionCallbackClient->OnDesktopLyricVisibilityChanged(true);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnDesktopLyricStateChanged001
 * @tc.desc: test OnDesktopLyricStateChanged
 * @tc.type: FUNC
 * @tc.require: #1998
 */
HWTEST_F(AVSessionCallbackClientTest, OnDesktopLyricStateChanged001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVSessionCallback> sessionCallback = std::make_shared<AVSessionCallbackImpl>();
    ASSERT_NE(sessionCallback, nullptr);
    DesktopLyricState state = {};
    sessionCallback->OnDesktopLyricStateChanged(state);
    std::shared_ptr<AVSessionCallbackClient> sessionCallbackClient =
        std::make_shared<AVSessionCallbackClient>(sessionCallback);
    ASSERT_NE(sessionCallbackClient, nullptr);
    ErrCode ret = sessionCallbackClient->OnDesktopLyricStateChanged(state);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
} // namespace AVSession
} // namespace OHOS