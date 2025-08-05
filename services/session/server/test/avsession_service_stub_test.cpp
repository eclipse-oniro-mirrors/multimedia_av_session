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
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"

#define private public
#define protected public
#include "avsession_service_stub.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AVSession;

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
            .isGeneral = true,
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1}
        }
    }
};

class AVSessionServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionServiceStubTest::SetUpTestCase()
{
    g_selfTokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionServiceStubTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionServiceStubTest::SetUp()
{
}

void AVSessionServiceStubTest::TearDown()
{
}

class AVSessionServiceStubPerDemo : public AVSessionServiceStub {
public:
    OHOS::sptr<IRemoteObject> CreateSessionInner(const std::string &tag, int32_t type,
        const OHOS::AppExecFwk::ElementName &elementName) override { return nullptr; };
    int32_t CreateSessionInner(const std::string &tag, int32_t type, const OHOS::AppExecFwk::ElementName &elementName,
        OHOS::sptr<IRemoteObject> &session) override { return 0; };
    int32_t CreateSessionInnerWithExtra(const std::string &tag, int32_t type, const std::string& extraInfo,
        const OHOS::AppExecFwk::ElementName &elementName, OHOS::sptr<IRemoteObject> &session) override { return 0; };
    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor> &descriptors) override { return 0; };
    int32_t GetSessionDescriptorsBySessionId(const std::string &sessionId,
        AVSessionDescriptor &descriptor) override { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; };
    int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor> &descriptors) override
    {
        return 0;
    };
    int32_t SendSystemAVKeyEvent(const OHOS::MMI::KeyEvent& keyEvent, const OHOS::AAFwk::Want &wantParam) override
    {
        return 0;
    };
    int32_t GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
        std::vector<AVQueueInfo> &avQueueInfos) override { return 0; };
    int32_t StartAVPlayback(const std::string &bundleName, const std::string &assetId) override { return 0; };
    int32_t CreateControllerInner(const std::string &sessionId, OHOS::sptr<IRemoteObject> &object) override
    {
        return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR;
    };
    int32_t RegisterSessionListener(const OHOS::sptr<ISessionListener> &listener) override { return 0; };
    int32_t RegisterSessionListenerForAllUsers(const OHOS::sptr<ISessionListener> &listener) override { return 0; };
    int32_t SendSystemAVKeyEvent(const OHOS::MMI::KeyEvent &keyEvent) override { return 0; };
    int32_t SendSystemControlCommand(const AVControlCommand &command) override { return 0; };
    int32_t RegisterClientDeathObserver(const OHOS::sptr<IClientDeath> &observer) override { return 0; };
    int32_t CastAudio(const SessionToken &token,
        const std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> &descriptors) override { return 0; };
    int32_t CastAudioForAll(const std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> &descriptors) override
    {
        return 0;
    };
    int32_t ProcessCastAudioCommand(const RemoteServiceCommand command, const std::string &input,
        std::string &output) override { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; };
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t GetAVCastControllerInner(const std::string &sessionId, OHOS::sptr<IRemoteObject> &object) override
    {
        return 0;
    };
    int32_t StartCast(const SessionToken &sessionToken, const OutputDeviceInfo &outputDeviceInfo) override
    {
        return 0;
    };
    int32_t StopCast(const SessionToken &sessionToken) override { return 0; };
    int32_t checkEnableCast(bool enable) override { return 0; };
#endif

    int32_t Close() override { return 0; };
    int32_t GetDistributedSessionControllersInner(const DistributedSessionType& sessionType,
        std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers) override { return 0; };
    bool isSuccess = true;
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest001, TestSize.Level0)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = 1;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest001 end!");
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest002, TestSize.Level0)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = 2;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest002 end!");
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest003, TestSize.Level0)
{
    SLOGI("OnRemoteRequest003 begin!");
    uint32_t code = 3;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest003 end!");
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest004, TestSize.Level0)
{
    SLOGI("OnRemoteRequest004 begin!");
    uint32_t code = 4;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest004 end!");
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest005, TestSize.Level0)
{
    SLOGI("OnRemoteRequest005 begin!");
    uint32_t code = 5;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest005 end!");
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest006, TestSize.Level0)
{
    SLOGI("OnRemoteRequest006 begin!");
    uint32_t code = 6;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest006 end!");
}

/**
 * @tc.name: OnRemoteRequest007
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest007, TestSize.Level0)
{
    SLOGI("OnRemoteRequest007 begin!");
    uint32_t code = 7;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest007 end!");
}

/**
 * @tc.name: OnRemoteRequest008
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest008, TestSize.Level0)
{
    SLOGI("OnRemoteRequest008 begin!");
    uint32_t code = 8;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest008 end!");
}

/**
 * @tc.name: OnRemoteRequest009
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest009, TestSize.Level0)
{
    SLOGI("OnRemoteRequest009 begin!");
    uint32_t code = 9;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest009 end!");
}

/**
 * @tc.name: OnRemoteRequest010
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest010, TestSize.Level0)
{
    SLOGI("OnRemoteRequest010 begin!");
    uint32_t code = 10;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest010 end!");
}

/**
 * @tc.name: OnRemoteRequest011
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest011, TestSize.Level0)
{
    SLOGI("OnRemoteRequest011 begin!");
    uint32_t code = 12;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest011 end!");
}

/**
 * @tc.name: OnRemoteRequest012
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest012, TestSize.Level0)
{
    SLOGI("OnRemoteRequest012 begin!");
    uint32_t code = 12;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    data.WriteInt32(100);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest012 end!");
}

/**
 * @tc.name: OnRemoteRequest013
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest013, TestSize.Level0)
{
    SLOGI("OnRemoteRequest013 begin!");
    uint32_t code = 12;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    data.WriteInt32(1);

    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest013 end!");
}

/**
 * @tc.name: OnRemoteRequest014
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest014, TestSize.Level0)
{
    SLOGI("OnRemoteRequest014 begin!");
    uint32_t code = 13;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest014 end!");
}

/**
 * @tc.name: OnRemoteRequest015
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest015, TestSize.Level0)
{
    SLOGI("OnRemoteRequest015 begin!");
    uint32_t code = 13;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("");
    data.WriteInt32(100);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest015 end!");
}

/**
 * @tc.name: OnRemoteRequest016
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest016, TestSize.Level0)
{
    SLOGI("OnRemoteRequest016 begin!");
    uint32_t code = 13;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("");
    data.WriteInt32(1);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest016 end!");
}

/**
 * @tc.name: OnRemoteRequest017
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest017, TestSize.Level0)
{
    SLOGI("OnRemoteRequest017 begin!");
    uint32_t code = 14;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest017 end!");
}

/**
 * @tc.name: OnRemoteRequest018
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest018, TestSize.Level0)
{
    SLOGI("OnRemoteRequest018 begin!");
    uint32_t code = 15;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest018 end!");
}

/**
 * @tc.name: OnRemoteRequest019
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest019, TestSize.Level0)
{
    SLOGI("OnRemoteRequest019 begin!");
    uint32_t code = 16;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest019 end!");
}

#ifndef CASTPLUS_CAST_ENGINE_ENABLE
/**
 * @tc.name: OnRemoteRequest020
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest020, TestSize.Level0)
{
    SLOGI("OnRemoteRequest020 begin!");
    uint32_t code = 17;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    data.WriteBool(true);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest020 end!");
}

/**
 * @tc.name: OnRemoteRequest021
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest021, TestSize.Level0)
{
    SLOGI("OnRemoteRequest021 begin!");
    uint32_t code = 18;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    data.WriteBool(true);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest021 end!");
}

/**
 * @tc.name: OnRemoteRequest022
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest022, TestSize.Level0)
{
    SLOGI("OnRemoteRequest022 begin!");
    uint32_t code = 19;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    data.WriteBool(true);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest022 end!");
}
#endif
/**
 * @tc.name: OnRemoteRequest023
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest023, TestSize.Level0)
{
    SLOGI("OnRemoteRequest023 begin!");
    uint32_t code = 20;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest023 end!");
}

/**
 * @tc.name: OnRemoteRequest024
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest024, TestSize.Level0)
{
    SLOGI("OnRemoteRequest024 begin!");
    uint32_t code = static_cast<uint32_t>(OHOS::AVSession::AvsessionSeviceInterfaceCode::SERVICE_CMD_START_CAST);
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest024 end!");
}

/**
 * @tc.name: OnRemoteRequest0025
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest0025, TestSize.Level0)
{
    SLOGI("OnRemoteRequest0025 begin!");
    uint32_t code = 4;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    data.WriteString("test2");
    data.WriteString("test3");
    data.WriteString("test4");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest0025 end!");
}

/**
 * @tc.name: OnRemoteRequest0026
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, OnRemoteRequest0026, TestSize.Level0)
{
    SLOGI("OnRemoteRequest0026 begin!");
    uint32_t code = 5;
    AVSessionServiceStubPerDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    data.WriteString("test2");
    data.WriteString("test3");
    data.WriteString("test4");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest0026 end!");
}

/**
 * @tc.name: HandleCreateSessionInner_001
 * @tc.desc: Test HandleCreateSessionInner with CreateSessionInner returning AVSESSION_SUCCESS.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceStubTest, HandleCreateSessionInner_001, TestSize.Level0)
{
    SLOGD("HandleCreateSessionInner_001 begin!");
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    std::string sessionTag = "TestSessionTag";
    int32_t sessionType = 1;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("TestBundleName");
    std::u16string interfaceToken = u"AVSessionService";
    data.WriteInterfaceToken(interfaceToken);
    data.WriteString(sessionTag);
    data.WriteInt32(sessionType);
    data.WriteParcelable(&elementName);
    AVSessionServiceStubPerDemo stub;
    int32_t result = stub.HandleCreateSessionInner(data, reply);
    EXPECT_EQ(result, OHOS::ERR_NONE);
    SLOGD("HandleCreateSessionInner_001 end!");
}

/**
 * @tc.name: AVSessionServiceStub_HandleStartCast_001
 * @tc.desc: Test HandleStartCast with deviceInfoSize over RECEIVE_DEVICE_NUM_MAX.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionServiceStubTest, AVSessionServiceStub_HandleStartCast_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceStub_HandleStartCast_001 begin!");
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("TestSessionId");
    data.WriteInt32(1234);
    data.WriteInt32(5678);
    data.WriteInt32(AVSessionServiceStubPerDemo::RECEIVE_DEVICE_NUM_MAX + 1);
    AVSessionServiceStubPerDemo stub;
    int32_t result = stub.HandleStartCast(data, reply);
    EXPECT_EQ(result, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_PERMISSION_DENIED);
    SLOGD("AVSessionServiceStub_HandleStartCast_001 end!");
}

/**
 * @tc.name: AVSessionServiceStub_HandleStartCast_002
 * @tc.desc: Test HandleStartCast with CheckBeforeHandleStartCast returning false.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionServiceStubTest, AVSessionServiceStub_HandleStartCast_002, TestSize.Level1)
{
    SLOGD("AVSessionServiceStub_HandleStartCast_002 begin!");
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("TestSessionId");
    data.WriteInt32(1234);
    data.WriteInt32(5678);
    data.WriteInt32(1);
    AVSessionServiceStubPerDemo stub;
    stub.isSuccess = false;
    int32_t result = stub.HandleStartCast(data, reply);
    EXPECT_EQ(result, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_PERMISSION_DENIED);
    SLOGD("AVSessionServiceStub_HandleStartCast_002 end!");
}

/**
 * @tc.name: AVSessionServiceStub_HandleStartCast_003
 * @tc.desc: Test HandleStartCast with CheckBeforeHandleStartCast returning true.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionServiceStubTest, AVSessionServiceStub_HandleStartCast_003, TestSize.Level1)
{
    SLOGD("AVSessionServiceStub_HandleStartCast_003 begin!");
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("TestSessionId");
    data.WriteInt32(1234);
    data.WriteInt32(5678);
    data.WriteInt32(1);
    AVSessionServiceStubPerDemo stub;
    stub.isSuccess = true;
    int32_t result = stub.HandleStartCast(data, reply);
    EXPECT_EQ(result, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_PERMISSION_DENIED);
    SLOGD("AVSessionServiceStub_HandleStartCast_003 end!");
}

/**
 * @tc.name: AVSessionServiceStub_HandleStopCast_001
 * @tc.desc: Test HandleStopCast with CheckPermission returning non-ERR_NONE.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionServiceStubTest, AVSessionServiceStub_HandleStopCast_001, TestSize.Level0)
{
    SLOGD("AVSessionServiceStub_HandleStopCast_001 begin!");
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("TestSessionId");
    data.WriteInt32(1234);
    data.WriteInt32(5678);
    AVSessionServiceStubPerDemo stub;
    int32_t result = stub.HandleStopCast(data, reply);
    EXPECT_EQ(result, OHOS::ERR_NONE);
    SLOGD("AVSessionServiceStub_HandleStopCast_001 end!");
}

/**
 * @tc.name: AVSessionServiceStub_HandleStopDeviceLogging_001
 * @tc.desc: Test HandleStopDeviceLogging with CheckPermission returning non-ERR_NONE.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionServiceStubTest, AVSessionServiceStub_HandleStopDeviceLogging_001, TestSize.Level0)
{
    SLOGD("AVSessionServiceStub_HandleStopDeviceLogging_001 begin!");
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    AVSessionServiceStubPerDemo stub;
    int32_t result = stub.HandleStopDeviceLogging(data, reply);
    EXPECT_EQ(result, OHOS::ERR_NONE);
    SLOGD("AVSessionServiceStub_HandleStopDeviceLogging_001 end!");
}

/**
 * @tc.name: AVSessionServiceStub_HandleGetDistributedSessionControllersInner_001
 * @tc.desc: Test HandleGetDistributedSessionControllersInner with TYPE_SESSION_REMOTE.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(
    AVSessionServiceStubTest, AVSessionServiceStub_HandleGetDistributedSessionControllersInner_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceStub_HandleGetDistributedSessionControllersInner_001 begin!");
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteInt32(static_cast<int32_t>(DistributedSessionType::TYPE_SESSION_REMOTE));
    AVSessionServiceStubPerDemo stub;
    int32_t result = stub.HandleGetDistributedSessionControllersInner(data, reply);
    EXPECT_EQ(result, OHOS::ERR_NONE);
    SLOGD("AVSessionServiceStub_HandleGetDistributedSessionControllersInner_001 end!");
}

/**
 * @tc.name: HandleGetHistoricalAVQueueInfos001
 * @tc.desc: Test HandleGetHistoricalAVQueueInfos
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubTest, HandleGetHistoricalAVQueueInfos001, TestSize.Level0)
{
    SLOGI("HandleGetHistoricalAVQueueInfos001 begin!");
    AVQueueInfo info = AVQueueInfo();
    OHOS::MessageParcel data;
    data.WriteString("test");
    data.WriteString("test2");
    data.WriteString("test3");
    data.WriteString("test4");
    info.Marshalling(data);
    OHOS::MessageParcel reply;
    AVSessionServiceStubPerDemo avsessionservicestub;
    int ret = avsessionservicestub.HandleGetHistoricalAVQueueInfos(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleGetHistoricalAVQueueInfos001 end!");
}
} // AVSession
} // OHOS