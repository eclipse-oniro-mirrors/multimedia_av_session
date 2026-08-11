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
#include "avsession_errors.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "iservice_registry.h"
#include "avmedia_description.h"
#include "av_file_descriptor.h"
#include "system_ability_definition.h"
#include "avsession_service.h"
#include "avsession_service_proxy.h"

using namespace OHOS;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;

class TestISessionListener : public ISessionListener {
public:
    ErrCode OnSessionCreate(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; }
    ErrCode OnSessionRelease(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; }
    ErrCode OnTopSessionChange(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; }
    ErrCode OnAudioSessionChecked(const int32_t uid) override { return AVSESSION_SUCCESS; }
    ErrCode OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override { return AVSESSION_SUCCESS; }
    ErrCode OnDeviceLogEvent(const int32_t eventId, const int64_t param) override { return AVSESSION_SUCCESS; }
    ErrCode OnDeviceOffline(const std::string& deviceId) override { return AVSESSION_SUCCESS; }
    ErrCode OnDeviceStateChange(const DeviceState& deviceState) override { return AVSESSION_SUCCESS; }
    ErrCode OnSystemCommonEvent(const std::string& commonEvent, const std::string& args) override { return AVSESSION_SUCCESS; }
    ErrCode OnRemoteDistributedSessionChange(const std::vector<sptr<IRemoteObject>>& sessionControllers) override { return AVSESSION_SUCCESS; }
    ErrCode OnActiveSessionChanged(const std::vector<AVSessionDescriptor> &descriptors) override { return AVSESSION_SUCCESS; }
    ErrCode OnSessionAddForAudioZone(int32_t userId, const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; }
    ErrCode OnSessionRemoveForAudioZone(int32_t userId, const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; }
    ErrCode OnTopSessionChangeForAudioZone(int32_t userId, const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; }
};

class AVSessionServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionServiceProxyTest::SetUpTestCase()
{
}

void AVSessionServiceProxyTest::TearDownTestCase()
{
}

void AVSessionServiceProxyTest::SetUp()
{
}

void AVSessionServiceProxyTest::TearDown()
{
}

/**
 * @tc.name: GetAllSessionDescriptors001
 * @tc.desc: Test GetAllSessionDescriptors
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, GetAllSessionDescriptors001, testing::ext::TestSize.Level0)
{
    SLOGI("GetAllSessionDescriptors001, start");

    int32_t ret = AVSESSION_ERROR;

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(mgr, nullptr);
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    ASSERT_NE(sessionService, nullptr);

    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    std::shared_ptr<OHOS::AVSession::AVSession> session;
    ret = avSessionServiceProxy->CreateSession(tag, type, elementName, session);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(session != nullptr);

    std::vector<AVSessionDescriptor> descriptors;
    ret = avSessionServiceProxy->GetAllSessionDescriptors(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(descriptors[0].sessionId_ != "");

    session = nullptr;
    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("GetAllSessionDescriptors001, end");
}

/**
 * @tc.name: GetSessionDescriptors001
 * @tc.desc: Test GetSessionDescriptors
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, GetSessionDescriptors001, testing::ext::TestSize.Level0)
{
    SLOGI("GetSessionDescriptors001, start");

    int32_t ret = AVSESSION_ERROR;

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(mgr, nullptr);
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    ASSERT_NE(sessionService, nullptr);

    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    std::shared_ptr<OHOS::AVSession::AVSession> session;
    ret = avSessionServiceProxy->CreateSession(tag, type, elementName, session);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(session != nullptr);

    std::vector<AVSessionDescriptor> descriptors;
    ret = avSessionServiceProxy->GetSessionDescriptors(SessionCategory::CATEGORY_ALL, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    session = nullptr;
    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("GetSessionDescriptors001, end");
}

#ifdef AUDIO_ZONE_ENABLE
/**
 * @tc.name: GetSessionDescriptorsForAudioZone001
 * @tc.desc: Test GetSessionDescriptorsForAudioZone with valid userId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, GetSessionDescriptorsForAudioZone001, testing::ext::TestSize.Level0)
{
    SLOGI("GetSessionDescriptorsForAudioZone001, start");

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(mgr, nullptr);
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    ASSERT_NE(sessionService, nullptr);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    int32_t userId = 100;
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = avSessionServiceProxy->GetSessionDescriptorsForAudioZone(userId, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("GetSessionDescriptorsForAudioZone001, end");
}

/**
 * @tc.name: GetSessionDescriptorsForAudioZone002
 * @tc.desc: Test GetSessionDescriptorsForAudioZone with invalid userId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, GetSessionDescriptorsForAudioZone002, testing::ext::TestSize.Level0)
{
    SLOGI("GetSessionDescriptorsForAudioZone002, start");

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(mgr, nullptr);
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    ASSERT_NE(sessionService, nullptr);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    int32_t userId = -1;
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = avSessionServiceProxy->GetSessionDescriptorsForAudioZone(userId, descriptors);
    EXPECT_NE(ret, AVSESSION_SUCCESS);

    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("GetSessionDescriptorsForAudioZone002, end");
}

/**
 * @tc.name: StartAVPlaybackForAudioZone001
 * @tc.desc: Test StartAVPlaybackForAudioZone with valid params
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, StartAVPlaybackForAudioZone001, testing::ext::TestSize.Level0)
{
    SLOGI("StartAVPlaybackForAudioZone001, start");

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(mgr, nullptr);
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    ASSERT_NE(sessionService, nullptr);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    std::string bundleName = "test_bundle";
    int32_t userId = 100;
    std::string assetId = "test_asset";
    CommandInfo info;
    info.SetCallerDeviceId("test_device");
    info.SetCallerBundleName("test_bundle");
    info.SetCallerModuleName("test_module");
    info.SetCallerType("test_type");

    int32_t ret = avSessionServiceProxy->StartAVPlaybackForAudioZone(bundleName, userId, assetId, info);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("StartAVPlaybackForAudioZone001, end");
}

/**
 * @tc.name: StartAVPlaybackForAudioZone002
 * @tc.desc: Test StartAVPlaybackForAudioZone with empty bundleName
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, StartAVPlaybackForAudioZone002, testing::ext::TestSize.Level0)
{
    SLOGI("StartAVPlaybackForAudioZone002, start");

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(mgr, nullptr);
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    ASSERT_NE(sessionService, nullptr);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    std::string bundleName = "";
    int32_t userId = 100;
    std::string assetId = "test_asset";
    CommandInfo info;
    info.SetCallerDeviceId("test_device");
    info.SetCallerBundleName("test_bundle");
    info.SetCallerModuleName("test_module");
    info.SetCallerType("test_type");

    int32_t ret = avSessionServiceProxy->StartAVPlaybackForAudioZone(bundleName, userId, assetId, info);
    EXPECT_NE(ret, AVSESSION_SUCCESS);

    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("StartAVPlaybackForAudioZone002, end");
}

/**
 * @tc.name: RegisterSessionListenerForUser001
 * @tc.desc: Test RegisterSessionListenerForUser with valid userId and listener
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, RegisterSessionListenerForUser001, testing::ext::TestSize.Level0)
{
    SLOGI("RegisterSessionListenerForUser001, start");

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(mgr, nullptr);
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    ASSERT_NE(sessionService, nullptr);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    int32_t userId = 100;
    sptr<ISessionListener> listener = new TestISessionListener();
    ASSERT_NE(listener, nullptr);

    int32_t ret = avSessionServiceProxy->RegisterSessionListenerForUser(userId, listener);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("RegisterSessionListenerForUser001, end");
}

/**
 * @tc.name: RegisterSessionListenerForUser002
 * @tc.desc: Test RegisterSessionListenerForUser with invalid userId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, RegisterSessionListenerForUser002, testing::ext::TestSize.Level0)
{
    SLOGI("RegisterSessionListenerForUser002, start");

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(mgr, nullptr);
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    ASSERT_NE(sessionService, nullptr);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    int32_t userId = -1;
    sptr<ISessionListener> listener = new TestISessionListener();
    ASSERT_NE(listener, nullptr);

    int32_t ret = avSessionServiceProxy->RegisterSessionListenerForUser(userId, listener);
    EXPECT_NE(ret, AVSESSION_SUCCESS);

    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("RegisterSessionListenerForUser002, end");
}
#endif