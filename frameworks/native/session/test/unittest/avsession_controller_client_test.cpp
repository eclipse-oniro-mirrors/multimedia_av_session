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

#include <gtest/gtest.h>

#include "avsession_errors.h"
#include "avsession_manager.h"
#include "accesstoken_kit.h"
#include "bool_wrapper.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "iavsession_controller.h"
#include "iremote_stub.h"
#include "want_params.h"
#include "ipc_skeleton.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "avsession_log.h"


using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AVSession {
static uint64_t g_selfTokenId = 0;
static HapInfoParams g_info = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demo",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demo",
    .isSystemApp = true
};

static HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .bundleName = "ohos.permission_test.demo",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

class AVSessionControllerDemo : public AVSessionController {
public:
    int32_t GetAVCallState(AVCallState& avCallState) override;
    int32_t GetAVCallMetaData(AVCallMetaData& avCallMetaData) override;
    int32_t SetAVCallMetaFilter(const AVCallMetaData::AVCallMetaMaskType& filter) override;
    int32_t SetAVCallStateFilter(const AVCallState::AVCallStateMaskType& filter) override;
    int32_t GetAVPlaybackState(AVPlaybackState& state) override;
    int32_t GetAVMetaData(AVMetaData& data) override;
    int32_t SendAVKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override;
    int32_t GetValidCommands(std::vector<int32_t>& cmds) override;
    int32_t IsSessionActive(bool& isActive) override;
    int32_t SendControlCommand(const AVControlCommand& cmd) override;
    int32_t SendCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override;
    int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback) override;
    int32_t SetMetaFilter(const AVMetaData::MetaMaskType& filter) override;
    int32_t SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) override;
    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;
    int32_t GetAVQueueTitle(std::string& title) override;
    int32_t SkipToQueueItem(int32_t& itemId) override;
    int32_t GetExtras(OHOS::AAFwk::WantParams& extras) override;
    int32_t GetExtrasWithEvent(const std::string& extraEvent, OHOS::AAFwk::WantParams& extras) override;
    int32_t Destroy() override;
    std::string GetSessionId() override;
    int64_t GetRealPlaybackPosition() override;
    bool IsDestroy() override;
};

int32_t AVSessionControllerDemo::GetAVCallState(AVCallState& avCallState)
{
    return 0;
}

int32_t AVSessionControllerDemo::GetAVCallMetaData(AVCallMetaData& avCallMetaData)
{
    return 0;
}

int32_t AVSessionControllerDemo::SetAVCallMetaFilter(const AVCallMetaData::AVCallMetaMaskType& filter)
{
    return 0;
}

int32_t AVSessionControllerDemo::SetAVCallStateFilter(const AVCallState::AVCallStateMaskType& filter)
{
    return 0;
}

int32_t AVSessionControllerDemo::GetAVPlaybackState(AVPlaybackState& state)
{
    return 0;
}

int32_t AVSessionControllerDemo::GetAVMetaData(AVMetaData& data)
{
    return 0;
}

int32_t AVSessionControllerDemo::SendAVKeyEvent(const OHOS::MMI::KeyEvent& keyEvent)
{
    return 0;
}

int32_t AVSessionControllerDemo::GetValidCommands(std::vector<int32_t>& cmds)
{
    return 0;
}

int32_t AVSessionControllerDemo::IsSessionActive(bool& isActive)
{
    return 0;
}

int32_t AVSessionControllerDemo::SendControlCommand(const AVControlCommand& cmd)
{
    return 0;
}

int32_t AVSessionControllerDemo::SendCommonCommand(const std::string& commonCommand,
    const OHOS::AAFwk::WantParams& commandArgs)
{
    return 0;
}

int32_t AVSessionControllerDemo::RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback)
{
    return 0;
}

int32_t AVSessionControllerDemo::SetMetaFilter(const AVMetaData::MetaMaskType& filter)
{
    return 0;
}

int32_t AVSessionControllerDemo::SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter)
{
    return 0;
}

int32_t AVSessionControllerDemo::GetAVQueueItems(std::vector<AVQueueItem>& items)
{
    return 0;
}

int32_t AVSessionControllerDemo::GetAVQueueTitle(std::string& title)
{
    return 0;
}

int32_t AVSessionControllerDemo::SkipToQueueItem(int32_t& itemId)
{
    return 0;
}

int32_t AVSessionControllerDemo::GetExtras(OHOS::AAFwk::WantParams& extras)
{
    return 0;
}

int32_t AVSessionControllerDemo::GetExtrasWithEvent(
    const std::string& extraEvent, OHOS::AAFwk::WantParams& extras)
{
    return 0;
}

int32_t AVSessionControllerDemo::Destroy()
{
    return 0;
}

std::string AVSessionControllerDemo::GetSessionId()
{
    return NULL;
}

int64_t AVSessionControllerDemo::GetRealPlaybackPosition()
{
    return 0;
}

bool AVSessionControllerDemo::IsDestroy()
{
    return false;
}

class AVSessionControllerClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AVSessionController> controller_ = nullptr;

    static constexpr int64_t TestMicroSecond = 1000;
};

void AVSessionControllerClientTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionControllerClientTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionControllerClientTest::SetUp()
{
    std::vector<AVSessionDescriptor> descriptors;
    auto retForGet = AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
    ASSERT_EQ(retForGet, AVSESSION_SUCCESS);
    SLOGI("GetAllSessionDescriptors size:%{public}d", static_cast<int>(descriptors.size()));
    if (descriptors.size() > 0) {
        auto res = AVSessionManager::GetInstance().CreateController(descriptors[0].sessionId_, controller_);
        SLOGI("CreateController res:%{public}d", res);
        ASSERT_EQ(res, AVSESSION_SUCCESS);
        ASSERT_NE(controller_, nullptr);
    }
}

void AVSessionControllerClientTest::TearDown()
{
    if (controller_ != nullptr) {
        SLOGI("Destroy controller");
        controller_->Destroy();
    }
}

/**
* @tc.name: IsSessionActive001
* @tc.desc: Return is Session Actived
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerClientTest, IsSessionActive001, TestSize.Level1)
{
    bool active = false;
    if (controller_ != nullptr) {
        EXPECT_EQ(controller_->IsSessionActive(active), AVSESSION_SUCCESS);
    } else {
        std::vector<AVSessionDescriptor> descriptors;
        auto res = AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
        ASSERT_EQ(res, AVSESSION_SUCCESS);
        EXPECT_EQ(descriptors.size() <= 0, true);
    }
}

/**
* @tc.name: AVSessionControllerDemoGetSupportedPlaySpeeds001
* @tc.desc: Get supported play speeds in demo class
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionControllerClientTest, AVSessionControllerDemoGetSupportedPlaySpeeds001, TestSize.Level1)
{
    SLOGD("AVSessionControllerDemoGetSupportedPlaySpeeds001 Begin");
    AVSessionControllerDemo avsessionControllerDemo = AVSessionControllerDemo();
    std::vector<double> speeds = {};
    EXPECT_EQ(avsessionControllerDemo.GetSupportedPlaySpeeds(speeds), AVSESSION_SUCCESS);
    SLOGD("AVSessionControllerDemoGetSupportedPlaySpeeds001 End");
}

/**
* @tc.name: AVSessionControllerDemoGetMediaCenterControlType001
* @tc.desc: Get media center control type in demo class
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionControllerClientTest, AVSessionControllerDemoGetMediaCenterControlType001, TestSize.Level1)
{
    SLOGD("AVSessionControllerDemoGetMediaCenterControlType001 Begin");
    AVSessionControllerDemo avsessionControllerDemo = AVSessionControllerDemo();
    std::vector<int32_t> controlTypes = {};
    EXPECT_EQ(avsessionControllerDemo.GetMediaCenterControlType(controlTypes), AVSESSION_SUCCESS);
    SLOGD("AVSessionControllerDemoGetMediaCenterControlType001 End");
}

/**
* @tc.name: AVSessionControllerDemoGetSupportedLoopModes001
* @tc.desc: Get supported loopmodes in demo class
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionControllerClientTest, AVSessionControllerDemoGetSupportedLoopModes001, TestSize.Level1)
{
    SLOGD("AVSessionControllerDemoGetSupportedLoopModes001 Begin");
    AVSessionControllerDemo avsessionControllerDemo = AVSessionControllerDemo();
    std::vector<int32_t> loopModes = {};
    EXPECT_EQ(avsessionControllerDemo.GetSupportedLoopModes(loopModes), AVSESSION_SUCCESS);
    SLOGD("AVSessionControllerDemoGetSupportedLoopModes001 End");
}
} // namespace AVSession
} // namespace OHOS
