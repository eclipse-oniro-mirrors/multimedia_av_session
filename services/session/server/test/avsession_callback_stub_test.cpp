/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "av_session_callback_stub.h"
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
    ErrCode OnPlay() override { return AVSESSION_SUCCESS; };
    ErrCode OnPause() override { return AVSESSION_SUCCESS; };
    ErrCode OnStop() override { return AVSESSION_SUCCESS; };
    ErrCode OnPlayNext() override { return AVSESSION_SUCCESS; };
    ErrCode OnPlayPrevious() override { return AVSESSION_SUCCESS; };
    ErrCode OnFastForward(int64_t time) override { return AVSESSION_SUCCESS; };
    ErrCode OnRewind(int64_t time) override { return AVSESSION_SUCCESS; };
    ErrCode OnSeek(int64_t time) override { return AVSESSION_SUCCESS; };
    ErrCode OnSetSpeed(double speed) override { return AVSESSION_SUCCESS; };
    ErrCode OnSetLoopMode(int32_t loopMode) override { return AVSESSION_SUCCESS; };
    ErrCode OnSetTargetLoopMode(int32_t targetLoopMode) override
    {
        onSetTargetLoopMode_ = true;
        return AVSESSION_SUCCESS;
    };
    ErrCode OnToggleFavorite(const std::string &mediaId) override { return AVSESSION_SUCCESS; };
    ErrCode OnMediaKeyEvent(const OHOS::MMI::KeyEvent &keyEvent) override { return AVSESSION_SUCCESS; };
    ErrCode OnOutputDeviceChange(const int32_t connectionState,
        const OutputDeviceInfo &outputDeviceInfo) override { return AVSESSION_SUCCESS; };
    ErrCode OnCommonCommand(const std::string &commonCommand,
        const OHOS::AAFwk::WantParams &commandArgs) override { return AVSESSION_SUCCESS; };
    ErrCode OnSkipToQueueItem(int32_t itemId) override { return AVSESSION_SUCCESS; };
    ErrCode OnAVCallAnswer() override { return AVSESSION_SUCCESS; };
    ErrCode OnAVCallHangUp() override { return AVSESSION_SUCCESS; };
    ErrCode OnAVCallToggleCallMute() override { return AVSESSION_SUCCESS; };
    ErrCode OnPlayFromAssetId(int64_t assetId) override
    {
        onPlayFromAssetId_ = true;
        return AVSESSION_SUCCESS;
    };
    ErrCode OnPlayWithAssetId(const std::string &assetId) override
    {
        onPlayWithAssetId_ = true;
        return AVSESSION_SUCCESS;
    };
    ErrCode OnCastDisplayChange(const CastDisplayInfo &castDisplayInfo) override { return AVSESSION_SUCCESS; };
    ErrCode OnCustomData(const OHOS::AAFwk::WantParams& data) override
    {
        return AVSESSION_SUCCESS;
    };
public:
    bool onSetTargetLoopMode_ = false;
    bool onPlayFromAssetId_ = false;
    bool onPlayWithAssetId_ = false;
};

/**
 * @tc.name: OnRemoteRequest000
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest000, TestSize.Level0)
{
    SLOGI("OnRemoteRequest000 begin!");
    uint32_t code = 1;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_TRANSACTION_FAILED);
    SLOGI("OnRemoteRequest000 end!");
}
/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest001, TestSize.Level0)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = 2;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
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
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest002, TestSize.Level0)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = 3;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
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
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest003, TestSize.Level0)
{
    SLOGI("OnRemoteRequest003 begin!");
    uint32_t code = 4;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
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
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest004, TestSize.Level0)
{
    SLOGI("OnRemoteRequest004 begin!");
    uint32_t code = 5;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
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
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest005, TestSize.Level0)
{
    SLOGI("OnRemoteRequest005 begin!");
    uint32_t code = 6;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
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
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest006, TestSize.Level0)
{
    SLOGI("OnRemoteRequest006 begin!");
    uint32_t code = 7;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest006 end!");
}

/**
* @tc.name: OnRemoteRequest007
* @tc.desc: Test OnRemoteRequest
* @tc.type: FUNC
*/
static HWTEST_F(AVSessionCallbackStubTest, OnRemoteRequest007, TestSize.Level0)
{
    SLOGI("OnRemoteRequest007 begin!");
    uint32_t code = 8;
    AVSessionCallbackStubDemo avSessionCallbackStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    data.WriteInterfaceToken(IAVSessionCallback::GetDescriptor());
    int ret = avSessionCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest007 end!");
}

/**
 * @tc.name: OnSetTargetLoopMode_001
 * @tc.desc: Test OnSetTargetLoopMode
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnSetTargetLoopMode001, TestSize.Level0)
{
    SLOGI("OnSetTargetLoopMode001 begin!");
    std::string assetId = "test";
    AVSessionCallbackStubDemo avSessionCallbackStub;
    avSessionCallbackStub.OnPlayWithAssetId(assetId);
    EXPECT_EQ(avSessionCallbackStub.onPlayWithAssetId_, true);
    int32_t targetLoopMode = 0;
    avSessionCallbackStub.OnSetTargetLoopMode(targetLoopMode);
    EXPECT_EQ(avSessionCallbackStub.onSetTargetLoopMode_, true);
    SLOGI("OnSetTargetLoopMode001 end!");
}

/**
 * @tc.name: OnPlayWithAssetId001
 * @tc.desc: Test OnPlayWithAssetId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionCallbackStubTest, OnPlayWithAssetId001, TestSize.Level0)
{
    SLOGI("OnPlayWithAssetId001 begin!");
    std::string assetId = "test";
    AVSessionCallbackStubDemo avSessionCallbackStub;
    avSessionCallbackStub.OnPlayWithAssetId(assetId);
    EXPECT_EQ(avSessionCallbackStub.onPlayWithAssetId_, true);
    SLOGI("OnPlayWithAssetId001 end!");
}
}
}
