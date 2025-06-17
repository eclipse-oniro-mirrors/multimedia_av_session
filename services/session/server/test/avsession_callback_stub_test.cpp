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
#include "avsession_callback_stub.h"
#include "avsession_log.h"
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"

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
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1}
        }
    }
};

class AVSessionCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionCallbackStubTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionCallbackStubTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionCallbackStubTest::SetUp()
{
}

void AVSessionCallbackStubTest::TearDown()
{
}

class AVSessionCallbackStubDemo : public AVSessionCallbackStub {
    void OnPlay() override {};
    void OnPause() override {};
    void OnStop() override {};
    void OnPlayNext() override {};
    void OnPlayPrevious() override {};
    void OnFastForward(int64_t time) override {};
    void OnRewind(int64_t time) override {};
    void OnSeek(int64_t time) override {};
    void OnSetSpeed(double speed) override {};
    void OnSetLoopMode(int32_t loopMode) override {};
    void OnSetTargetLoopMode(int32_t targetLoopMode) override {};
    void OnToggleFavorite(const std::string &mediaId) override {};
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent &keyEvent) override {};
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo &outputDeviceInfo) override {};
    void OnCommonCommand(const std::string &commonCommand, const OHOS::AAFwk::WantParams &commandArgs) override {};
    void OnSkipToQueueItem(int32_t itemId) override {};
    void OnAVCallAnswer() override {};
    void OnAVCallHangUp() override {};
    void OnAVCallToggleCallMute() override {};
    void OnPlayFromAssetId(int64_t assetId) override {};
    void OnPlayWithAssetId(const std::string &assetId) override {};
    void OnCastDisplayChange(const CastDisplayInfo &castDisplayInfo) override {};
};

/**
 * @tc.name: OnRemoteRequest000
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest000, TestSize.Level1)
{
    SLOGI("OnRemoteRequest000 begin!");
    uint32_t code = 0;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("OnRemoteRequest000 end!");
}
/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest001, TestSize.Level1)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = 11;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest001 end!");
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest002, TestSize.Level1)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = 12;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    SLOGI("OnRemoteRequest002");
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest002 end!");
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest003, TestSize.Level1)
{
    SLOGI("OnRemoteRequest003 begin!");
    uint32_t code = 13;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest003 end!");
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest004, TestSize.Level1)
{
    SLOGI("OnRemoteRequest004 begin!");
    uint32_t code = 14;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest004 end!");
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest005, TestSize.Level1)
{
    SLOGI("OnRemoteRequest005 begin!");
    uint32_t code = 19;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest005 end!");
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest006, TestSize.Level1)
{
    SLOGI("OnRemoteRequest006 begin!");
    uint32_t code = 25;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, 305);
    SLOGI("OnRemoteRequest006 end!");
}

/**
* @tc.name: OnRemoteRequest007
* @tc.desc: Test OnRemoteRequest
* @tc.type: FUNC
*/
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest007, TestSize.Level1)
{
    SLOGI("OnRemoteRequest007 begin!");
    uint32_t code = 20;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    data.WriteInt32(0);
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest007 end!");
}

/**
 * @tc.name: OnSetTargetLoopMode001
 * @tc.desc: Test OnSetTargetLoopMode
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnSetTargetLoopMode001, TestSize.Level1)
{
    SLOGI("OnSetTargetLoopMode001 begin!");
    uint32_t code = 12;
    std::string assetId = "test";
    int32_t targetLoopMode = 0;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    avSessionCallbackStub.OnPlayWithAssetId(assetId);
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    avSessionCallbackStub.OnSetTargetLoopMode(targetLoopMode);
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnSetTargetLoopMode001 end!");
}
}
}
