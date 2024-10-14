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
#include "session_listener_stub.h"
#include "avsession_log.h"
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;

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

class SessionListenerStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void SessionListenerStubTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void SessionListenerStubTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void SessionListenerStubTest::SetUp()
{
}

void SessionListenerStubTest::TearDown()
{
}

class SessionListenerStubDemo : public SessionListenerStub {
    void OnSessionCreate(const AVSessionDescriptor &descriptor) override {};
    void OnSessionRelease(const AVSessionDescriptor &descriptor) override {};
    void OnTopSessionChange(const AVSessionDescriptor &descriptor) override {};
    void OnAudioSessionChecked(const int32_t uid) override {};
    void OnDeviceAvailable(const OutputDeviceInfo &castOutputDeviceInfo) override {};
    void OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) override {};
    void OnDeviceOffline(const std::string &deviceId) override {};
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerStubTest, OnRemoteRequest001, TestSize.Level1)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = 0;
    SessionListenerStubDemo sessionListenerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = sessionListenerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_ERROR);
    SLOGI("OnRemoteRequest001 end!");
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerStubTest, OnRemoteRequest002, TestSize.Level1)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = 0;
    SessionListenerStubDemo sessionListenerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ISessionListener::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = sessionListenerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest002 end!");
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerStubTest, OnRemoteRequest003, TestSize.Level1)
{
    SLOGI("OnRemoteRequest003 begin!");
    uint32_t code = 1;
    SessionListenerStubDemo sessionListenerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ISessionListener::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = sessionListenerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest003 end!");
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerStubTest, OnRemoteRequest004, TestSize.Level1)
{
    SLOGI("OnRemoteRequest004 begin!");
    uint32_t code = 2;
    SessionListenerStubDemo sessionListenerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ISessionListener::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = sessionListenerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest004 end!");
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerStubTest, OnRemoteRequest005, TestSize.Level1)
{
    SLOGI("OnRemoteRequest005 begin!");
    uint32_t code = 3;
    SessionListenerStubDemo sessionListenerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ISessionListener::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = sessionListenerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest005 end!");
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerStubTest, OnRemoteRequest006, TestSize.Level1)
{
    SLOGI("OnRemoteRequest006 begin!");
    uint32_t code = 4;
    SessionListenerStubDemo sessionListenerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ISessionListener::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = sessionListenerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest006 end!");
}

/**
 * @tc.name: OnRemoteRequest007
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerStubTest, OnRemoteRequest007, TestSize.Level1)
{
    SLOGI("OnRemoteRequest007 begin!");
    uint32_t code = 5;
    SessionListenerStubDemo sessionListenerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ISessionListener::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = sessionListenerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest007 end!");
}

/**
 * @tc.name: OnRemoteRequest008
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerStubTest, OnRemoteRequest008, TestSize.Level1)
{
    SLOGI("OnRemoteRequest008 begin!");
    uint32_t code = 25;
    SessionListenerStubDemo sessionListenerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ISessionListener::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = sessionListenerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, 305);
    SLOGI("OnRemoteRequest008 end!");
}