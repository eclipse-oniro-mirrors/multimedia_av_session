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
#include "av_controller_callback_stub.h"
#include "avsession_log.h"
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AVSession {
static uint64_t g_selfTokenId = 0;
static int32_t MAX_IMAGE_SIZE = 10 * 1024 * 1024;
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

class AVControllerCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVControllerCallbackStubTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVControllerCallbackStubTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVControllerCallbackStubTest::SetUp()
{
}

void AVControllerCallbackStubTest::TearDown()
{
}

class AVControllerCallbackStubDemo : public AVControllerCallbackStub {
    ErrCode OnAVCallMetaDataChange(const AVCallMetaData &avCallMetaData) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnAVCallStateChange(const AVCallState &avCallState) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnSessionDestroy() override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnPlaybackStateChange(const AVPlaybackState &state) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnMetaDataChange(const AVMetaData &data) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnActiveStateChange(bool isActive) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnValidCommandChange(const std::vector<int32_t> &cmds) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo &outputDeviceInfo) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnSessionEventChange(const std::string &event, const OHOS::AAFwk::WantParams &args) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnQueueItemsChange(const std::vector<AVQueueItem> &items) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnQueueTitleChange(const std::string &title) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnExtrasChange(const OHOS::AAFwk::WantParams &extras) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnCustomData(const OHOS::AAFwk::WantParams& data) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDesktopLyricVisibilityChanged(bool isVisible) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDesktopLyricStateChanged(const DesktopLyricState &state) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDesktopLyricEnabled(bool isEnabled) override
    {
        return AVSESSION_SUCCESS;
    };
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest001, TestSize.Level0)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = 0;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_TRANSACTION_FAILED);
    SLOGI("OnRemoteRequest001 end!");
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest002, TestSize.Level0)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = 10;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    SLOGI("OnRemoteRequest002 end!");
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest003, TestSize.Level0)
{
    SLOGI("OnRemoteRequest003 begin!");
    uint32_t code = 11;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest003 end!");
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest004, TestSize.Level0)
{
    SLOGI("OnRemoteRequest004 begin!");
    uint32_t code = 1;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest004 end!");
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest005, TestSize.Level0)
{
    SLOGI("OnRemoteRequest005 begin!");
    uint32_t code = 1;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_TRANSACTION_FAILED);
    SLOGI("OnRemoteRequest005 end!");
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest006, TestSize.Level0)
{
    SLOGI("OnRemoteRequest006 begin!");
    uint32_t code = 2;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    SLOGI("OnRemoteRequest006 end!");
}

/**
 * @tc.name: OnRemoteRequest007
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest007, TestSize.Level0)
{
    SLOGI("OnRemoteRequest007 begin!");
    uint32_t code = 2;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteInt32(-1);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    SLOGI("OnRemoteRequest007 end!");
}

/**
 * @tc.name: OnRemoteRequest008
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest008, TestSize.Level0)
{
    SLOGI("OnRemoteRequest008 begin!");
    uint32_t code = 2;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteInt32(MAX_IMAGE_SIZE + 1);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    SLOGI("OnRemoteRequest008 end!");
}

/**
 * @tc.name: OnRemoteRequest009
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest009, TestSize.Level0)
{
    SLOGI("OnRemoteRequest009 begin!");
    uint32_t code = 2;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteInt32(MAX_IMAGE_SIZE - 1);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    SLOGI("OnRemoteRequest009 end!");
}

/**
 * @tc.name: OnRemoteRequest010
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest010, TestSize.Level0)
{
    SLOGI("OnRemoteRequest010 begin!");
    uint32_t code = 5;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequest010 end!");
}

/**
 * @tc.name: OnRemoteRequest011
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest011, TestSize.Level0)
{
    SLOGI("OnRemoteRequest011 begin!");
    uint32_t code = 6;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest011 end!");
}

/**
 * @tc.name: OnRemoteRequest012
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest012, TestSize.Level0)
{
    SLOGI("OnRemoteRequest012 begin!");
    uint32_t code = 7;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest012 end!");
}

/**
 * @tc.name: OnRemoteRequest013
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest013, TestSize.Level0)
{
    SLOGI("OnRemoteRequest013 begin!");
    uint32_t code = 7;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_TRANSACTION_FAILED);
    SLOGI("OnRemoteRequest013 end!");
}

/**
 * @tc.name: OnRemoteRequest014
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest014, TestSize.Level0)
{
    SLOGI("OnRemoteRequest014 begin!");
    uint32_t code = 8;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest014 end!");
}

/**
 * @tc.name: OnRemoteRequest015
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackStubTest, OnRemoteRequest015, TestSize.Level0)
{
    SLOGI("OnRemoteRequest015 begin!");
    uint32_t code = 9;
    AVControllerCallbackStubDemo avControllerCallbackStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::IAVControllerCallback::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avControllerCallbackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    SLOGI("OnRemoteRequest015 end!");
}
} // namespace AVSession
} // namespace OHOS