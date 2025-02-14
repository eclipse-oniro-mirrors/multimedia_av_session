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
#include "audio_system_manager.h"

#define private public
#define protected public
#include "avsession_service_stub.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AVSession;

static uint64_t g_selfTokenId = 0;
static std::string g_errLog;

static void MyLogCallback(const LogType type, const LogLevel level,
    const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}

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

class AVSessionServiceStubPermissionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionServiceStubPermissionTest::SetUpTestCase()
{
    g_selfTokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionServiceStubPermissionTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionServiceStubPermissionTest::SetUp()
{
}

void AVSessionServiceStubPermissionTest::TearDown()
{
}

class AVSessionServiceStubDemo : public AVSessionServiceStub {
public:
    OHOS::sptr<IRemoteObject> CreateSessionInner(const std::string &tag, int32_t type,
        const OHOS::AppExecFwk::ElementName &elementName) override { return nullptr; };
    int32_t CreateSessionInner(const std::string &tag, int32_t type, const OHOS::AppExecFwk::ElementName &elementName,
        OHOS::sptr<IRemoteObject> &session) override { return 0; };
    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor> &descriptors) override { return 0; };
    int32_t GetSessionDescriptorsBySessionId(const std::string &sessionId,
        AVSessionDescriptor &descriptor) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor> &descriptors) override
    {
        return 0;
    };
    int32_t GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
        std::vector<AVQueueInfo> &avQueueInfos) override { return 0; };
    int32_t StartAVPlayback(const std::string &bundleName, const std::string &assetId) override { return 0; };
    bool IsAudioPlaybackAllowed(const int32_t uid, const int32_t pid) override { return 0; };
    int32_t CreateControllerInner(const std::string &sessionId, OHOS::sptr<IRemoteObject> &object) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
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
                                    std::string &output) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest001, TestSize.Level1)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = 0;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_ERROR);
    SLOGI("OnRemoteRequest001 end!");
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest002, TestSize.Level1)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = 0;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::ElementName element;
    want.SetElement(element);
    data.WriteParcelable(&want);
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest002 end!");
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest003, TestSize.Level1)
{
    SLOGI("OnRemoteRequest003 begin!");
    uint32_t code = 0;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::ElementName element("", "12345", "12345");
    want.SetElement(element);
    data.WriteParcelable(&want);
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest003 end!");
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest004, TestSize.Level1)
{
    SLOGI("OnRemoteRequest004 begin!");
    uint32_t code = 0;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest005, TestSize.Level1)
{
    SLOGI("OnRemoteRequest005 begin!");
    uint32_t code = 0;
    AVSessionServiceStubDemo avsessionservicestub;
    avsessionservicestub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::ElementName element("", "12345", "12345");
    want.SetElement(element);
    data.WriteParcelable(&want);
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest005 end!");
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest006, TestSize.Level1)
{
    SLOGI("OnRemoteRequest006 begin!");
    uint32_t code = 1;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest007, TestSize.Level1)
{
    SLOGI("OnRemoteRequest007 begin!");
    uint32_t code = 2;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest008, TestSize.Level1)
{
    SLOGI("OnRemoteRequest008 begin!");
    uint32_t code = 3;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest009, TestSize.Level1)
{
    SLOGI("OnRemoteRequest009 begin!");
    uint32_t code = 4;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest010, TestSize.Level1)
{
    SLOGI("OnRemoteRequest010 begin!");
    uint32_t code = 5;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest011, TestSize.Level1)
{
    SLOGI("OnRemoteRequest011 begin!");
    uint32_t code = 6;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest012, TestSize.Level1)
{
    SLOGI("OnRemoteRequest012 begin!");
    uint32_t code = 7;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest013, TestSize.Level1)
{
    SLOGI("OnRemoteRequest013 begin!");
    uint32_t code = 8;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest014, TestSize.Level1)
{
    SLOGI("OnRemoteRequest014 begin!");
    uint32_t code = 9;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest015, TestSize.Level1)
{
    SLOGI("OnRemoteRequest015 begin!");
    uint32_t code = 10;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest016, TestSize.Level1)
{
    SLOGI("OnRemoteRequest016 begin!");
    uint32_t code = 11;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest017, TestSize.Level1)
{
    SLOGI("OnRemoteRequest017 begin!");
    uint32_t code = 12;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest018, TestSize.Level1)
{
    SLOGI("OnRemoteRequest018 begin!");
    uint32_t code = 13;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest019, TestSize.Level1)
{
    SLOGI("OnRemoteRequest019 begin!");
    uint32_t code = 14;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest019 end!");
}

/**
 * @tc.name: OnRemoteRequest020
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest020, TestSize.Level1)
{
    SLOGI("OnRemoteRequest020 begin!");
    uint32_t code = 15;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest021, TestSize.Level1)
{
    SLOGI("OnRemoteRequest021 begin!");
    uint32_t code = 16;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest021 end!");
}

#ifndef CASTPLUS_CAST_ENGINE_ENABLE
/**
 * @tc.name: OnRemoteRequest022
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest022, TestSize.Level1)
{
    SLOGI("OnRemoteRequest022 begin!");
    uint32_t code = 17;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest022 end!");
}

/**
 * @tc.name: OnRemoteRequest023
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest023, TestSize.Level1)
{
    SLOGI("OnRemoteRequest023 begin!");
    uint32_t code = 18;
    AVSessionServiceStubDemo avsessionservicestub;
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
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest024, TestSize.Level1)
{
    SLOGI("OnRemoteRequest024 begin!");
    uint32_t code = 19;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest024 end!");
}
#endif

/**
 * @tc.name: OnRemoteRequest025
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest025, TestSize.Level1)
{
    SLOGI("OnRemoteRequest025 begin!");
    uint32_t code = 20;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest025 end!");
}

/**
 * @tc.name: OnRemoteRequest026
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest026, TestSize.Level1)
{
    SLOGI("OnRemoteRequest026 begin!");
    uint32_t code = 25;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, 305);
    SLOGI("OnRemoteRequest026 end!");
}

/**
 * @tc.name: HandleStartDeviceLogging001
 * @tc.desc: Test HandleStartDeviceLogging
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleStartDeviceLogging001, TestSize.Level1)
{
    SLOGI("HandleStartDeviceLogging001 begin!");
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avsessionservicestub.HandleStartDeviceLogging(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);

    ret = avsessionservicestub.HandleStopDeviceLogging(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleStartDeviceLogging001 end!");
}

/**
 * @tc.name: MarshallingAVQueueInfos001
 * @tc.desc: Test MarshallingAVQueueInfos
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, MarshallingAVQueueInfos001, TestSize.Level1)
{
    SLOGI("MarshallingAVQueueInfos001 begin!");
    LOG_SetCallback(MyLogCallback);
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel reply;
    AVQueueInfo aVQueueInfo;
    std::vector<AVQueueInfo> avQueueInfos = {aVQueueInfo};
    avsessionservicestub.MarshallingAVQueueInfos(reply, avQueueInfos);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("MarshallingAVQueueInfos001 end!");
}

/**
 * @tc.name: GetAVQueueInfosImgLength002
 * @tc.desc: Test GetAVQueueInfosImgLength
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, GetAVQueueInfosImgLength002, TestSize.Level1)
{
    SLOGI("GetAVQueueInfosImgLength002 begin!");
    AVSessionServiceStubDemo avsessionservicestub;
    AVQueueInfo aVQueueInfo;
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 2, 3};
    mediaPixelMap->SetInnerImgBuffer(imgBuffer);
    aVQueueInfo.SetAVQueueImage(mediaPixelMap);
    std::vector<AVQueueInfo> avQueueInfos = {aVQueueInfo};
    int ret = avsessionservicestub.GetAVQueueInfosImgLength(avQueueInfos);
    EXPECT_EQ(ret, 3);
    SLOGI("GetAVQueueInfosImgLength002 end!");
}

/**
 * @tc.name: AVQueueInfoImgToBuffer001
 * @tc.desc: Test AVQueueInfoImgToBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, AVQueueInfoImgToBuffer001, TestSize.Level1)
{
    SLOGI("AVQueueInfoImgToBuffer001 begin!");
    LOG_SetCallback(MyLogCallback);
    AVSessionServiceStubDemo avsessionservicestub;
    AVQueueInfo aVQueueInfo;
    std::vector<AVQueueInfo> avQueueInfos = {aVQueueInfo};
    unsigned char *buffer = new unsigned char[255];
    avsessionservicestub.AVQueueInfoImgToBuffer(avQueueInfos, buffer);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("AVQueueInfoImgToBuffer001 end!");
}

/**
 * @tc.name: AVQueueInfoImgToBuffer002
 * @tc.desc: Test AVQueueInfoImgToBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, AVQueueInfoImgToBuffer002, TestSize.Level1)
{
    SLOGI("AVQueueInfoImgToBuffer002 begin!");
    LOG_SetCallback(MyLogCallback);
    AVSessionServiceStubDemo avsessionservicestub;
    AVQueueInfo aVQueueInfo;
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 2, 3};
    mediaPixelMap->SetInnerImgBuffer(imgBuffer);
    aVQueueInfo.SetAVQueueImage(mediaPixelMap);
    std::vector<AVQueueInfo> avQueueInfos = {aVQueueInfo};
    unsigned char *buffer = new unsigned char[255];
    avsessionservicestub.AVQueueInfoImgToBuffer(avQueueInfos, buffer);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("AVQueueInfoImgToBuffer002 end!");
}

/**
 * @tc.name: HandleClose001
 * @tc.desc: Test HandleClose
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleClose001, TestSize.Level1)
{
    SLOGI("HandleClose001 begin!");
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avsessionservicestub.HandleClose(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleClose001 end!");
}