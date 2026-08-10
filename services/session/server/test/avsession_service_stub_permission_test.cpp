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

#ifdef CAR_FEATURE_ENABLE
#include "audio_zone_types.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AVSession;

namespace OHOS::AudioStandard {
struct AudioZoneDescriptor {
    int32_t zoneId;
    std::string zoneName;
};

class AudioZoneCallback {
public:
    virtual ~AudioZoneCallback() = default;
    virtual void OnAudioZoneAdd(const AudioZoneDescriptor &zoneDescriptor) = 0;
    virtual void OnAudioZoneRemove(int32_t zoneId) = 0;
};

class AudioZoneManager {
public:
    static AudioZoneManager* GetInstance()
    {
        static AudioZoneManager instance;
        return &instance;
    }
    
    int32_t RegisterAudioZoneCallback(const std::shared_ptr<AudioZoneCallback>& callback)
    {
        callback_ = callback;
        return callback ? 0 : -1;
    }
    
    void UnRegisterAudioZoneCallback()
    {
        callback_ = nullptr;
    }
    
    void TriggerZoneAddEvent(int32_t zoneId, const std::string& zoneName)
    {
        if (callback_) {
            AudioZoneDescriptor desc;
            desc.zoneId = zoneId;
            desc.zoneName = zoneName;
            callback_->OnAudioZoneAdd(desc);
        }
    }
    
    void TriggerZoneRemoveEvent(int32_t zoneId)
    {
        if (callback_) {
            callback_->OnAudioZoneRemove(zoneId);
        }
    }
    
    int32_t GetZoneIdForUser(int32_t userId)
    {
        auto it = userToZoneMap_.find(userId);
        return it != userToZoneMap_.end() ? it->second : -1;
    }
    
    void SetUserZoneMapping(int32_t userId, int32_t zoneId)
    {
        userToZoneMap_[userId] = zoneId;
    }
    
    void ClearMappings()
    {
        userToZoneMap_.clear();
    }

private:
    std::shared_ptr<AudioZoneCallback> callback_;
    std::map<int32_t, int32_t> userToZoneMap_;
};
}

class AudioZoneTestData {
public:
    struct ZoneConfig {
        int32_t zoneId;
        std::string zoneName;
        std::vector<int32_t> userIds;
    };
    
    static std::vector<ZoneConfig> GetTestZones()
    {
        return {
            {1, "DriverZone", {100}},
            {2, "PassengerZone", {101, 102}},
            {3, "RearZone", {103}},
        };
    }
    
    static AVSessionDescriptor CreateTestSessionDescriptor(
        const std::string& sessionId, int32_t userId, const std::string& bundleName)
    {
        AVSessionDescriptor desc;
        desc.sessionId_ = sessionId;
        desc.userId_ = userId;
        desc.bundleName_ = bundleName;
        desc.sessionTag_ = "TestSession";
        desc.isActive_ = true;
        desc.isTopSession_ = false;
        return desc;
    }
    
    static CommandInfo CreateTestCommandInfo(
        const std::string& deviceId = "test_device",
        const std::string& bundleName = "test_bundle",
        const std::string& moduleName = "test_module",
        const std::string& callerType = "test_type")
    {
        CommandInfo info;
        info.SetCallerDeviceId(deviceId);
        info.SetCallerBundleName(bundleName);
        info.SetCallerModuleName(moduleName);
        info.SetCallerType(callerType);
        return info;
    }
};
#endif

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

using OHOS::ErrCode;

class ISessionListenerMock : public ISessionListener {
public:
    ErrCode OnSessionCreate(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; };
    ErrCode OnSessionRelease(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; };
    ErrCode OnTopSessionChange(
        const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; };
    ErrCode OnAudioSessionChecked(const int32_t uid) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceAvailable(
        const OutputDeviceInfo& castOutputDeviceInfo) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceLogEvent(
        const int32_t eventId, const int64_t param) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceOffline(
        const std::string& deviceId) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceStateChange(const DeviceState& deviceState) override { return AVSESSION_SUCCESS; };
    ErrCode OnSystemCommonEvent(
        const std::string& commonEvent, const std::string& args) override { return AVSESSION_SUCCESS; };
    ErrCode OnRemoteDistributedSessionChange(
        const std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers) override { return AVSESSION_SUCCESS; };
    ErrCode OnActiveSessionChanged(
        const std::vector<AVSessionDescriptor> &descriptors) override { return AVSESSION_SUCCESS; };
    void OnSessionAddForAudioZone(
        int32_t userId, const AVSessionDescriptor &descriptor) override {};
    void OnSessionRemoveForAudioZone(
        int32_t userId, const AVSessionDescriptor &descriptor) override {};
    void OnTopSessionChangeForAudioZone(
        int32_t userId, const AVSessionDescriptor &descriptor) override {};
    OHOS::sptr<IRemoteObject> AsObject() override { return nullptr; };
};

class AVSessionServiceStubDemo : public AVSessionServiceStub {
public:
    OHOS::sptr<IRemoteObject> CreateSessionInner(const std::string &tag, int32_t type,
        const OHOS::AppExecFwk::ElementName &elementName) override { return nullptr; };
    int32_t CreateSessionInner(const std::string &tag, int32_t type, const OHOS::AppExecFwk::ElementName &elementName,
        OHOS::sptr<IRemoteObject> &session) override { return 0; };
    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor> &descriptors) override { return 0; };
    int32_t GetSessionDescriptors(int32_t category,
        std::vector<AVSessionDescriptor> &descriptors) override { return 0; };
    int32_t GetSessionDescriptorsBySessionId(const std::string &sessionId,
        AVSessionDescriptor &descriptor) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
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
    int32_t StartAVPlayback(const std::string &bundleName, const std::string &assetId,
        const std::string& moduleName) override { return 0; };
#ifdef CAR_FEATURE_ENABLE
    int32_t GetSessionDescriptorsForAudioZone(int32_t userId,
        std::vector<AVSessionDescriptor> &descriptors) override
    {
        if (!isSuccess) {
            return AVSESSION_ERROR;
        }
        AVSessionDescriptor desc = AudioZoneTestData::CreateTestSessionDescriptor(
            "test_session_" + std::to_string(userId), userId, "test_bundle");
        descriptors.push_back(desc);
        return AVSESSION_SUCCESS;
    };
    int32_t StartAVPlaybackForAudioZone(const std::string &bundleName, int32_t userId,
        const std::string &assetId, const CommandInfo &info) override
    {
        return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR;
    };
    int32_t RegisterSessionListenerForUser(int32_t userId,
        const OHOS::sptr<ISessionListener> &listener) override { return AVSESSION_SUCCESS; };
#endif
    int32_t RegisterAncoMediaSessionListener(const OHOS::sptr<IAncoMediaSessionListener> &listener) override
    {
        return 0;
    };
    int32_t CreateControllerInner(const std::string &sessionId, OHOS::sptr<IRemoteObject> &object) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    int32_t RegisterSessionListener(const OHOS::sptr<ISessionListener> &listener) override { return 0; };
    int32_t RegisterSessionListenerForAllUsers(const OHOS::sptr<ISessionListener> &listener) override { return 0; };
    int32_t SendSystemAVKeyEvent(const OHOS::MMI::KeyEvent &keyEvent) override { return 0; };
    int32_t SendSystemControlCommand(const AVControlCommand &command) override { return 0; };
    int32_t SendSystemCommonCommand(const std::string& commonCommand,
        const OHOS::AAFwk::WantParams& commandArgs) override { return 0; };
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

    int32_t GetSessionInner(const OHOS::AppExecFwk::ElementName& elementName,
        std::string& tag, OHOS::sptr<IRemoteObject>& session) override { return 0; };
    int32_t IsDesktopLyricSupported(bool &isSupported) override { return 0; };
    bool isSuccess = true;
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest001, TestSize.Level0)
{
    uint32_t code = 0;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_ERROR);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest002, TestSize.Level0)
{
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
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest003, TestSize.Level0)
{
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
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest004, TestSize.Level0)
{
    uint32_t code = 0;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest005, TestSize.Level0)
{
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
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest006, TestSize.Level0)
{
    uint32_t code = 1;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest007
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest007, TestSize.Level0)
{
    uint32_t code = 2;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest008
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest008, TestSize.Level0)
{
    uint32_t code = 3;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest009
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest009, TestSize.Level0)
{
    uint32_t code = 4;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest010
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest010, TestSize.Level0)
{
    uint32_t code = 5;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest011
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest011, TestSize.Level0)
{
    uint32_t code = 6;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest012
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest012, TestSize.Level0)
{
    uint32_t code = 7;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest013
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest013, TestSize.Level0)
{
    uint32_t code = 8;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest014
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest014, TestSize.Level0)
{
    uint32_t code = 9;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest015
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest015, TestSize.Level0)
{
    uint32_t code = 10;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest016
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest016, TestSize.Level0)
{
    uint32_t code = 11;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest017
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest017, TestSize.Level0)
{
    uint32_t code = 12;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest018
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest018, TestSize.Level0)
{
    uint32_t code = 13;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest019
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest019, TestSize.Level0)
{
    uint32_t code = 14;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest020
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest020, TestSize.Level0)
{
    uint32_t code = 15;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest021
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest021, TestSize.Level0)
{
    uint32_t code = 16;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

#ifndef CASTPLUS_CAST_ENGINE_ENABLE
/**
 * @tc.name: OnRemoteRequest022
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest022, TestSize.Level0)
{
    uint32_t code = 17;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest023
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest023, TestSize.Level0)
{
    uint32_t code = 18;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest024
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest024, TestSize.Level0)
{
    uint32_t code = 19;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}
#endif

/**
 * @tc.name: OnRemoteRequest025
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest025, TestSize.Level0)
{
    uint32_t code = 20;
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest026
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, OnRemoteRequest026, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_MAX);
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avsessionservicestub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: HandleStartDeviceLogging001
 * @tc.desc: Test HandleStartDeviceLogging
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleStartDeviceLogging001, TestSize.Level0)
{
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avsessionservicestub.HandleStartDeviceLogging(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);

    ret = avsessionservicestub.HandleStopDeviceLogging(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: MarshallingAVQueueInfos001
 * @tc.desc: Test MarshallingAVQueueInfos
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, MarshallingAVQueueInfos001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel reply;
    AVQueueInfo aVQueueInfo;
    std::vector<AVQueueInfo> avQueueInfos = {aVQueueInfo};
    avsessionservicestub.MarshallingAVQueueInfos(reply, avQueueInfos);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
 * @tc.name: GetAVQueueInfosImgLength002
 * @tc.desc: Test GetAVQueueInfosImgLength
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, GetAVQueueInfosImgLength002, TestSize.Level0)
{
    AVSessionServiceStubDemo avsessionservicestub;
    AVQueueInfo aVQueueInfo;
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 2, 3};
    mediaPixelMap->SetInnerImgBuffer(imgBuffer);
    aVQueueInfo.SetAVQueueImage(mediaPixelMap);
    std::vector<AVQueueInfo> avQueueInfos = {aVQueueInfo};
    int ret = avsessionservicestub.GetAVQueueInfosImgLength(avQueueInfos);
    EXPECT_EQ(ret, 3);
}

/**
 * @tc.name: AVQueueInfoImgToBuffer001
 * @tc.desc: Test AVQueueInfoImgToBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, AVQueueInfoImgToBuffer001, TestSize.Level0)
{
    LOG_SetCallback(MyLogCallback);
    AVSessionServiceStubDemo avsessionservicestub;
    AVQueueInfo aVQueueInfo;
    std::vector<AVQueueInfo> avQueueInfos = {aVQueueInfo};
    unsigned char *buffer = new unsigned char[255];
    avsessionservicestub.AVQueueInfoImgToBuffer(avQueueInfos, buffer);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
}

/**
 * @tc.name: AVQueueInfoImgToBuffer002
 * @tc.desc: Test AVQueueInfoImgToBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, AVQueueInfoImgToBuffer002, TestSize.Level0)
{
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
}

/**
 * @tc.name: HandleClose001
 * @tc.desc: Test HandleClose
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleClose001, TestSize.Level0)
{
    AVSessionServiceStubDemo avsessionservicestub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avsessionservicestub.HandleClose(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}


#ifdef CAR_FEATURE_ENABLE
/**
 * @tc.name: HandleRegisterSessionListenerForUser001
 * @tc.desc: Test HandleRegisterSessionListenerForUser with permission and valid parameters
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleRegisterSessionListenerForUser001, TestSize.Level0)
{
    SLOGI("HandleRegisterSessionListenerForUser001 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(100);
    
    sptr<ISessionListenerMock> listener = new ISessionListenerMock();
    data.WriteRemoteObject(listener->AsObject());
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleRegisterSessionListenerForUser(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), AVSESSION_SUCCESS);
    SLOGI("HandleRegisterSessionListenerForUser001 end!");
}

/**
 * @tc.name: HandleRegisterSessionListenerForUser002
 * @tc.desc: Test HandleRegisterSessionListenerForUser with invalid userId (negative)
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleRegisterSessionListenerForUser002, TestSize.Level0)
{
    SLOGI("HandleRegisterSessionListenerForUser002 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(-1);
    
    sptr<ISessionListenerMock> listener = new ISessionListenerMock();
    data.WriteRemoteObject(listener->AsObject());
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleRegisterSessionListenerForUser(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_INVALID_PARAM);
    SLOGI("HandleRegisterSessionListenerForUser002 end!");
}

/**
 * @tc.name: HandleRegisterSessionListenerForUser003
 * @tc.desc: Test HandleRegisterSessionListenerForUser with userId = 0
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleRegisterSessionListenerForUser003, TestSize.Level0)
{
    SLOGI("HandleRegisterSessionListenerForUser003 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(0);
    
    sptr<ISessionListenerMock> listener = new ISessionListenerMock();
    data.WriteRemoteObject(listener->AsObject());
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleRegisterSessionListenerForUser(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_INVALID_PARAM);
    SLOGI("HandleRegisterSessionListenerForUser003 end!");
}

/**
 * @tc.name: HandleRegisterSessionListenerForUser004
 * @tc.desc: Test HandleRegisterSessionListenerForUser with nullptr remoteObject
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleRegisterSessionListenerForUser004, TestSize.Level0)
{
    SLOGI("HandleRegisterSessionListenerForUser004 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(100);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleRegisterSessionListenerForUser(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), OHOS::ERR_UNMARSHALLING);
    SLOGI("HandleRegisterSessionListenerForUser004 end!");
}

/**
 * @tc.name: HandleRegisterSessionListenerForUser005
 * @tc.desc: Test HandleRegisterSessionListenerForUser with incomplete parcel data
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleRegisterSessionListenerForUser005, TestSize.Level0)
{
    SLOGI("HandleRegisterSessionListenerForUser005 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleRegisterSessionListenerForUser(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_UNMARSHALLING);
    SLOGI("HandleRegisterSessionListenerForUser005 end!");
}

/**
 * @tc.name: HandleRegisterSessionListenerForUser006
 * @tc.desc: Test HandleRegisterSessionListenerForUser with large userId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleRegisterSessionListenerForUser006, TestSize.Level0)
{
    SLOGI("HandleRegisterSessionListenerForUser006 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(999999);
    
    sptr<ISessionListenerMock> listener = new ISessionListenerMock();
    data.WriteRemoteObject(listener->AsObject());
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleRegisterSessionListenerForUser(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleRegisterSessionListenerForUser006 end!");
}

/**
 * @tc.name: HandleGetSessionDescriptorsForAudioZone001
 * @tc.desc: Test HandleGetSessionDescriptorsForAudioZone with permission and valid userId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleGetSessionDescriptorsForAudioZone001, TestSize.Level0)
{
    SLOGI("HandleGetSessionDescriptorsForAudioZone001 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(100);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleGetSessionDescriptorsForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), AVSESSION_SUCCESS);
    uint32_t size = reply.ReadUint32();
    EXPECT_GT(size, 0);
    SLOGI("HandleGetSessionDescriptorsForAudioZone001 end!");
}

/**
 * @tc.name: HandleGetSessionDescriptorsForAudioZone002
 * @tc.desc: Test HandleGetSessionDescriptorsForAudioZone when GetSessionDescriptorsForAudioZone fails
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleGetSessionDescriptorsForAudioZone002, TestSize.Level0)
{
    SLOGI("HandleGetSessionDescriptorsForAudioZone002 begin!");
    AVSessionServiceStubDemo stub;
    stub.isSuccess = false;
    
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(100);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleGetSessionDescriptorsForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), AVSESSION_ERROR);
    SLOGI("HandleGetSessionDescriptorsForAudioZone002 end!");
}

/**
 * @tc.name: HandleGetSessionDescriptorsForAudioZone003
 * @tc.desc: Test HandleGetSessionDescriptorsForAudioZone with userId = 0
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleGetSessionDescriptorsForAudioZone003, TestSize.Level0)
{
    SLOGI("HandleGetSessionDescriptorsForAudioZone003 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(0);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleGetSessionDescriptorsForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleGetSessionDescriptorsForAudioZone003 end!");
}

/**
 * @tc.name: HandleGetSessionDescriptorsForAudioZone004
 * @tc.desc: Test HandleGetSessionDescriptorsForAudioZone with negative userId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleGetSessionDescriptorsForAudioZone004, TestSize.Level0)
{
    SLOGI("HandleGetSessionDescriptorsForAudioZone004 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(-1);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleGetSessionDescriptorsForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleGetSessionDescriptorsForAudioZone004 end!");
}

/**
 * @tc.name: HandleGetSessionDescriptorsForAudioZone005
 * @tc.desc: Test HandleGetSessionDescriptorsForAudioZone with large userId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleGetSessionDescriptorsForAudioZone005, TestSize.Level0)
{
    SLOGI("HandleGetSessionDescriptorsForAudioZone005 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteInt32(999999);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleGetSessionDescriptorsForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleGetSessionDescriptorsForAudioZone005 end!");
}

/**
 * @tc.name: HandleStartAVPlaybackForAudioZone001
 * @tc.desc: Test HandleStartAVPlaybackForAudioZone with permission and valid parameters
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleStartAVPlaybackForAudioZone001, TestSize.Level0)
{
    SLOGI("HandleStartAVPlaybackForAudioZone001 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test_bundle");
    data.WriteInt32(100);
    data.WriteString("test_asset_id");
    
    CommandInfo info = AudioZoneTestData::CreateTestCommandInfo();
    info.Marshalling(data);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleStartAVPlaybackForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), AVSESSION_SUCCESS);
    SLOGI("HandleStartAVPlaybackForAudioZone001 end!");
}

/**
 * @tc.name: HandleStartAVPlaybackForAudioZone002
 * @tc.desc: Test HandleStartAVPlaybackForAudioZone when StartAVPlaybackForAudioZone fails
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleStartAVPlaybackForAudioZone002, TestSize.Level0)
{
    SLOGI("HandleStartAVPlaybackForAudioZone002 begin!");
    AVSessionServiceStubDemo stub;
    stub.isSuccess = false;
    
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test_bundle");
    data.WriteInt32(100);
    data.WriteString("test_asset_id");
    
    CommandInfo info = AudioZoneTestData::CreateTestCommandInfo();
    info.Marshalling(data);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleStartAVPlaybackForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), AVSESSION_ERROR);
    SLOGI("HandleStartAVPlaybackForAudioZone002 end!");
}

/**
 * @tc.name: HandleStartAVPlaybackForAudioZone003
 * @tc.desc: Test HandleStartAVPlaybackForAudioZone with empty bundleName
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleStartAVPlaybackForAudioZone003, TestSize.Level0)
{
    SLOGI("HandleStartAVPlaybackForAudioZone003 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("");
    data.WriteInt32(100);
    data.WriteString("test_asset_id");
    
    CommandInfo info = AudioZoneTestData::CreateTestCommandInfo();
    info.Marshalling(data);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleStartAVPlaybackForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleStartAVPlaybackForAudioZone003 end!");
}

/**
 * @tc.name: HandleStartAVPlaybackForAudioZone004
 * @tc.desc: Test HandleStartAVPlaybackForAudioZone with empty assetId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleStartAVPlaybackForAudioZone004, TestSize.Level0)
{
    SLOGI("HandleStartAVPlaybackForAudioZone004 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test_bundle");
    data.WriteInt32(100);
    data.WriteString("");
    
    CommandInfo info = AudioZoneTestData::CreateTestCommandInfo();
    info.Marshalling(data);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleStartAVPlaybackForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleStartAVPlaybackForAudioZone004 end!");
}

/**
 * @tc.name: HandleStartAVPlaybackForAudioZone005
 * @tc.desc: Test HandleStartAVPlaybackForAudioZone with large userId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceStubPermissionTest, HandleStartAVPlaybackForAudioZone005, TestSize.Level0)
{
    SLOGI("HandleStartAVPlaybackForAudioZone005 begin!");
    AVSessionServiceStubDemo stub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionService::GetDescriptor());
    data.WriteString("test_bundle");
    data.WriteInt32(999999);
    data.WriteString("test_asset_id");
    
    CommandInfo info = AudioZoneTestData::CreateTestCommandInfo();
    info.Marshalling(data);
    
    OHOS::MessageParcel reply;
    int32_t ret = stub.HandleStartAVPlaybackForAudioZone(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleStartAVPlaybackForAudioZone005 end!");
}
#endif