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
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_info.h"
#include "collaboration_manager_utils.h"
#include "collaboration_manager_urlcasting.cpp"
#include "collaboration_manager_hiplay.cpp"
#include "collaboration_manager_urlcasting.h"
#include "collaboration_manager_hiplay.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class CollaborationManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CollaborationManagerTest::SetUpTestCase()
{
}

void CollaborationManagerTest::TearDownTestCase()
{
}

void CollaborationManagerTest::SetUp()
{
}

void CollaborationManagerTest::TearDown()
{
}

/**
 * @tc.name: RegisterLifecycleCallback001
 * @tc.desc: Test RegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, RegisterLifecycleCallback001, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterLifecycleCallback001, start");
    int32_t ret = CollaborationManagerURLCasting::GetInstance().RegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("RegisterLifecycleCallback001, end");
}

/**
 * @tc.name: RegisterLifecycleCallback002
 * @tc.desc: Test RegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, RegisterLifecycleCallback002, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterLifecycleCallback002, start");
    auto registerLifecycleCallback = [](const char* serviceName, ServiceCollaborationManager_Callback* callback) {
        return static_cast<int32_t>(0);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback
        = registerLifecycleCallback;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().RegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("RegisterLifecycleCallback002, end");
}


/**
 * @tc.name: RegisterLifecycleCallback003
 * @tc.desc: Test RegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, RegisterLifecycleCallback003, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterLifecycleCallback003, start");
    auto registerLifecycleCallback = [](const char* serviceName, ServiceCollaborationManager_Callback* callback) {
        return static_cast<int32_t>(1);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback
        = registerLifecycleCallback;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().RegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("RegisterLifecycleCallback003, end");
}

/**
 * @tc.name: RegisterLifecycleCallback004
 * @tc.desc: Test RegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, RegisterLifecycleCallback004, testing::ext::TestSize.Level0)
{
    SLOGI("RegisterLifecycleCallback004, start");
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback
        = nullptr;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().RegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("RegisterLifecycleCallback004, end");
}

/**
 * @tc.name: RegisterLifecycleCallback005
 * @tc.desc: Test RegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, RegisterLifecycleCallback005, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterLifecycleCallback005, start");
    int32_t ret = CollaborationManagerHiPlay::GetInstance().RegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("RegisterLifecycleCallback005, end");
}

/**
 * @tc.name: UnRegisterLifecycleCallback001
 * @tc.desc: Test UnRegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, UnRegisterLifecycleCallback001, testing::ext::TestSize.Level1)
{
    SLOGI("UnRegisterLifecycleCallback001, start");
    int32_t ret = CollaborationManagerURLCasting::GetInstance().UnRegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("UnRegisterLifecycleCallback001, end");
}

/**
 * @tc.name: UnRegisterLifecycleCallback002
 * @tc.desc: Test UnRegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, UnRegisterLifecycleCallback002, testing::ext::TestSize.Level1)
{
    SLOGI("UnRegisterLifecycleCallback002, start");
    auto unRegisterLifecycleCallback = [](const char* serviceName) {
        return static_cast<int32_t>(0);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_UnRegisterLifecycleCallback
        = unRegisterLifecycleCallback;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().UnRegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("UnRegisterLifecycleCallback002, end");
}

/**
 * @tc.name: UnRegisterLifecycleCallback003
 * @tc.desc: Test UnRegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, UnRegisterLifecycleCallback003, testing::ext::TestSize.Level1)
{
    SLOGI("UnRegisterLifecycleCallback003, start");
    auto unRegisterLifecycleCallback = [](const char* serviceName) {
        return static_cast<int32_t>(1);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_UnRegisterLifecycleCallback
        = unRegisterLifecycleCallback;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().UnRegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("UnRegisterLifecycleCallback003, end");
}

/**
 * @tc.name: UnRegisterLifecycleCallback004
 * @tc.desc: Test UnRegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, UnRegisterLifecycleCallback004, testing::ext::TestSize.Level1)
{
    SLOGI("UnRegisterLifecycleCallback004, start");
    int32_t ret = CollaborationManagerHiPlay::GetInstance().UnRegisterLifecycleCallback();
    CollaborationManagerHiPlay::ReleaseInstance();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("UnRegisterLifecycleCallback004, end");
}

/**
 * @tc.name: PublishServiceState001
 * @tc.desc: Test PublishServiceState
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, PublishServiceState001, testing::ext::TestSize.Level1)
{
    SLOGI("PublishServiceState001, start");
    const char* peerNetworkId = "";
    ServiceCollaborationManagerBussinessStatus state = ServiceCollaborationManagerBussinessStatus::SCM_IDLE;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().PublishServiceState(peerNetworkId, state);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("PublishServiceState001, end");
}

/**
 * @tc.name: PublishServiceState002
 * @tc.desc: Test PublishServiceState
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, PublishServiceState002, testing::ext::TestSize.Level1)
{
    SLOGI("PublishServiceState002, start");
    const char* peerNetworkId = "";
    ServiceCollaborationManagerBussinessStatus state = ServiceCollaborationManagerBussinessStatus::SCM_IDLE;
    auto publishServiceState = [](ServiceCollaborationManager_ServiceStateInfo *serviceStateInfo,
        ServiceCollaborationManager_ResourceRequestInfoSets *resourceRequest, int32_t userId) {
            return static_cast<int32_t>(0);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_PublishServiceState
        = publishServiceState;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().PublishServiceState(peerNetworkId, state);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("PublishServiceState002, end");
}

/**
 * @tc.name: PublishServiceState003
 * @tc.desc: Test PublishServiceState
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, PublishServiceState003, testing::ext::TestSize.Level1)
{
    SLOGI("PublishServiceState003, start");
    const char* peerNetworkId = "";
    ServiceCollaborationManagerBussinessStatus state = ServiceCollaborationManagerBussinessStatus::SCM_IDLE;
    auto publishServiceState = [](ServiceCollaborationManager_ServiceStateInfo *serviceStateInfo,
        ServiceCollaborationManager_ResourceRequestInfoSets *resourceRequest, int32_t userId) {
            return static_cast<int32_t>(1);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_PublishServiceState
        = publishServiceState;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().PublishServiceState(peerNetworkId, state);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("PublishServiceState003, end");
}

/**
 * @tc.name: PublishServiceState004
 * @tc.desc: Test PublishServiceState
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, PublishServiceState004, testing::ext::TestSize.Level1)
{
    SLOGI("PublishServiceState004, start");
    auto originalResourceRequest = CollaborationManagerURLCasting::GetInstance().resourceRequest_;
    auto publishServiceState = [](ServiceCollaborationManager_ServiceStateInfo *serviceStateInfo,
        ServiceCollaborationManager_ResourceRequestInfoSets *resourceRequest, int32_t userId) {
            return static_cast<int32_t>(0);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_PublishServiceState
        = publishServiceState;
    CollaborationManagerURLCasting::GetInstance().resourceRequest_ = nullptr;
    const char* peerNetworkId = "test_network_id";
    ServiceCollaborationManagerBussinessStatus state = ServiceCollaborationManagerBussinessStatus::SCM_IDLE;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().PublishServiceState(peerNetworkId, state);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    CollaborationManagerURLCasting::GetInstance().resourceRequest_ = originalResourceRequest;
    SLOGI("PublishServiceState004, end");
}

/**
 * @tc.name: ApplyAdvancedResource001
 * @tc.desc: Test ApplyAdvancedResource
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ApplyAdvancedResource001, testing::ext::TestSize.Level1)
{
    SLOGI("ApplyAdvancedResource001, start");
    const char* peerNetworkId = "";
    DeviceInfo deviceInfo;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    int32_t retHiPlay = CollaborationManagerHiPlay::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(retHiPlay, AVSESSION_ERROR);
    SLOGI("ApplyAdvancedResource001, end");
}

/**
 * @tc.name: ApplyAdvancedResource002
 * @tc.desc: Test ApplyAdvancedResource
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ApplyAdvancedResource002, testing::ext::TestSize.Level1)
{
    SLOGI("ApplyAdvancedResource002, start");
    const char* peerNetworkId = "";
    DeviceInfo deviceInfo;
    auto applyAdvancedResource = [](const char* peerNetworkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest, int32_t userId,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(0);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    CollaborationManagerHiPlay::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t retHiPlay = CollaborationManagerHiPlay::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(retHiPlay, AVSESSION_SUCCESS);
    SLOGI("ApplyAdvancedResource002, end");
}

/**
 * @tc.name: ApplyAdvancedResource003
 * @tc.desc: Test ApplyAdvancedResource
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ApplyAdvancedResource003, testing::ext::TestSize.Level1)
{
    SLOGI("ApplyAdvancedResource003, start");
    const char* peerNetworkId = "";
    DeviceInfo deviceInfo;
    auto applyAdvancedResource = [](const char* peerNetworkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest, int32_t userId,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(1);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    CollaborationManagerHiPlay::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t retHiPlay = CollaborationManagerHiPlay::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(retHiPlay, AVSESSION_ERROR);
    SLOGI("ApplyAdvancedResource003, end");
}

/**
 * @tc.name: ApplyAdvancedResource004
 * @tc.desc: Test ApplyAdvancedResource when resourceRequest_ is nullptr.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ApplyAdvancedResource004, testing::ext::TestSize.Level1)
{
    SLOGI("ApplyAdvancedResource004, start");
    auto& instance = CollaborationManagerURLCasting::GetInstance();
    auto originalResourceRequest = instance.resourceRequest_;
    const char* peerNetworkId = "";
    DeviceInfo deviceInfo;
    auto applyAdvancedResource = [](const char* networkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest, int32_t userId,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(1);
    };
    instance.exportapi_.ServiceCollaborationManager_ApplyAdvancedResource = applyAdvancedResource;
    instance.resourceRequest_ = nullptr;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    instance.resourceRequest_ = originalResourceRequest;
    SLOGI("ApplyAdvancedResource004, end");
}

/**
 * @tc.name: ApplyAdvancedResource005
 * @tc.desc: Test ApplyAdvancedResource with HiPlay P2P device.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ApplyAdvancedResource005, testing::ext::TestSize.Level1)
{
    SLOGI("ApplyAdvancedResource005, start");
    const char* peerNetworkId = "";
    DeviceInfo deviceInfo;
    deviceInfo.supportedProtocols_ = ProtocolType::TYPE_CAST_PLUS_AUDIO;
    deviceInfo.ipAddress_ = "";
    auto applyAdvancedResource = [](const char* peerNetworkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest, int32_t userId,
        ServiceCollaborationManager_Callback* callback) {
            EXPECT_EQ(resourceRequest->linkType, ServiceCollaborationManagerLinkType::NATIVE_P2P);
            return static_cast<int32_t>(0);
    };
    CollaborationManagerURLCasting::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManagerURLCasting::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("ApplyAdvancedResource005, end");
}

/**
 * @tc.name: ApplyAdvancedResource006
 * @tc.desc: Test ApplyAdvancedResource when resourceRequest_ is nullptr.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ApplyAdvancedResource006, testing::ext::TestSize.Level1)
{
    SLOGI("ApplyAdvancedResource006, start");
    auto& instance = CollaborationManagerHiPlay::GetInstance();
    auto originalResourceRequest = instance.resourceRequest_;
    const char* peerNetworkId = "";
    DeviceInfo deviceInfo;
    auto applyAdvancedResourceHiPlay = [](const char* networkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest, int32_t userId,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(1);
    };
    instance.exportapi_.ServiceCollaborationManager_ApplyAdvancedResource = applyAdvancedResourceHiPlay;
    instance.resourceRequest_ = nullptr;
    int32_t ret = CollaborationManagerHiPlay::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    instance.resourceRequest_ = originalResourceRequest;
    SLOGI("ApplyAdvancedResource006, end");
}

/**
 * @tc.name: ApplyAdvancedResource007
 * @tc.desc: Test ApplyAdvancedResource with HiPlay P2P device.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ApplyAdvancedResource007, testing::ext::TestSize.Level1)
{
    SLOGI("ApplyAdvancedResource007, start");
    const char* peerNetworkId = "";
    DeviceInfo deviceInfo;
    deviceInfo.supportedProtocols_ = ProtocolType::TYPE_CAST_PLUS_AUDIO;
    deviceInfo.ipAddress_ = "";
    auto applyAdvancedResource = [](const char* peerNetworkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest, int32_t userId,
        ServiceCollaborationManager_Callback* callback) {
            EXPECT_EQ(resourceRequest->linkType, ServiceCollaborationManagerLinkType::NATIVE_P2P);
            return static_cast<int32_t>(0);
    };
    CollaborationManagerHiPlay::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManagerHiPlay::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    deviceInfo.supportedProtocols_ = ProtocolType::TYPE_LOCAL;
    EXPECT_FALSE(CollaborationManagerHiPlay::GetInstance().IsHiPlayDevice(deviceInfo));
    EXPECT_FALSE(CollaborationManagerHiPlay::GetInstance().IsHiPlayP2PDevice(deviceInfo));
    CollaborationManagerHiPlay::GetInstance().UpdataLinkType(deviceInfo);
    EXPECT_EQ(CollaborationManagerHiPlay::GetInstance().resourceRequest_->linkType,
        ServiceCollaborationManagerLinkType::UNKNOWN);

    deviceInfo.supportedProtocols_ = ProtocolType::TYPE_CAST_PLUS_AUDIO;
    deviceInfo.ipAddress_ = "xxxxx";
    EXPECT_TRUE(CollaborationManagerHiPlay::GetInstance().IsHiPlayDevice(deviceInfo));
    EXPECT_FALSE(CollaborationManagerHiPlay::GetInstance().IsHiPlayP2PDevice(deviceInfo));
    CollaborationManagerHiPlay::GetInstance().UpdataLinkType(deviceInfo);
    EXPECT_EQ(CollaborationManagerHiPlay::GetInstance().resourceRequest_->linkType,
        ServiceCollaborationManagerLinkType::WLAN);

    deviceInfo.ipAddress_.clear();
    EXPECT_TRUE(CollaborationManagerHiPlay::GetInstance().IsHiPlayDevice(deviceInfo));
    EXPECT_TRUE(CollaborationManagerHiPlay::GetInstance().IsHiPlayP2PDevice(deviceInfo));
    CollaborationManagerHiPlay::GetInstance().UpdataLinkType(deviceInfo);
    EXPECT_EQ(CollaborationManagerHiPlay::GetInstance().resourceRequest_->linkType,
        ServiceCollaborationManagerLinkType::NATIVE_P2P);

    SLOGI("ApplyAdvancedResource007, end");
}

/**
 * @tc.name: SendCollaborationOnStop001
 * @tc.desc: Test SendCollaborationOnStop with null callback.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationOnStop001, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationOnStop001, start");
    CollaborationManagerURLCasting::GetInstance().SendCollaborationOnStop(nullptr);
    auto& sendCallback = CollaborationManagerURLCasting::GetInstance().sendCollaborationOnStop_;
    OnStopUrlCasting(nullptr);
    EXPECT_EQ(sendCallback, nullptr);
    SLOGI("SendCollaborationOnStop001, end");
}

/**
 * @tc.name: SendCollaborationOnStop002
 * @tc.desc: Test SendCollaborationOnStop with valid callback and OnStop invocation.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationOnStop002, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationOnStop002, start");
    bool callbackCalled = false;
    CollaborationManagerURLCasting::GetInstance().SendCollaborationOnStop([&callbackCalled]() {
        callbackCalled = true;
    });
    auto& saved = CollaborationManagerURLCasting::GetInstance().sendCollaborationOnStop_;
    OnStopUrlCasting(nullptr);
    EXPECT_NE(saved, nullptr);
    saved();
    EXPECT_TRUE(callbackCalled);
    SLOGI("SendCollaborationOnStop002, end");
}


/**
 * @tc.name: SendCollaborationOnStop003
 * @tc.desc: Test SendCollaborationOnStop with null callback.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationOnStop003, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationOnStop003, start");
    CollaborationManagerHiPlay::GetInstance().SendCollaborationOnStop(nullptr);
    auto& sendCallback = CollaborationManagerHiPlay::GetInstance().sendCollaborationOnStop_;
    OnStopHiPlay(nullptr);
    EXPECT_EQ(sendCallback, nullptr);
    SLOGI("SendCollaborationOnStop003, end");
}

/**
 * @tc.name: SendCollaborationOnStop004
 * @tc.desc: Test SendCollaborationOnStop with valid callback and OnStop invocation.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationOnStop004, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationOnStop004, start");
    bool callbackCalled = false;
    CollaborationManagerHiPlay::GetInstance().SendCollaborationOnStop([&callbackCalled]() {
        callbackCalled = true;
    });
    auto& saved = CollaborationManagerHiPlay::GetInstance().sendCollaborationOnStop_;
    OnStopHiPlay(nullptr);
    EXPECT_NE(saved, nullptr);
    saved();
    EXPECT_TRUE(callbackCalled);
    SLOGI("SendCollaborationOnStop003, end");
}

/**
 * @tc.name: SendCollaborationApplyResult001
 * @tc.desc: Test SendCollaborationApplyResult with null callback.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationApplyResult001, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationApplyResult001, start");
    CollaborationManagerURLCasting::GetInstance().SendCollaborationApplyResult(nullptr);
    auto& callback = CollaborationManagerURLCasting::GetInstance().sendCollaborationApplyResult_;
    ApplyResultUrlCasting(0, ServiceCollaborationManagerResultCode::REJECT, "REJECT");
    ApplyResultUrlCasting(0, ServiceCollaborationManagerResultCode::PASS, "PASS");
    EXPECT_EQ(callback, nullptr);
    SLOGI("SendCollaborationApplyResult001, end");
}

/**
 * @tc.name: SendCollaborationApplyResult002
 * @tc.desc: Test SendCollaborationApplyResult with valid callback.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationApplyResult002, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationApplyResult002, start");
    auto& callbackRef = CollaborationManagerURLCasting::GetInstance().sendCollaborationApplyResult_;
    auto originalCallback = callbackRef;

    bool callbackCalled = false;
    int32_t receivedCode = -1;
    auto mockCallback = [&callbackCalled, &receivedCode](const int32_t code) {
        SLOGI("Mock SendCollaborationApplyResult callback invoked with code: %{public}d", code);
        callbackCalled = true;
        receivedCode = code;
    };
    callbackRef = mockCallback;
    CollaborationManagerURLCasting::GetInstance().SendCollaborationApplyResult(mockCallback);
    if (callbackRef) {
        callbackRef(AVSESSION_SUCCESS);
    }
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedCode, AVSESSION_SUCCESS);
    callbackRef = originalCallback;
    ApplyResultUrlCasting(0, ServiceCollaborationManagerResultCode::REJECT, "REJECT");
    ApplyResultUrlCasting(0, ServiceCollaborationManagerResultCode::PASS, "PASS");
    SLOGI("SendCollaborationApplyResult002, end");
}


/**
 * @tc.name: SendCollaborationApplyResult003
 * @tc.desc: Test SendCollaborationApplyResult with null callback.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationApplyResult003, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationApplyResult003, start");
    CollaborationManagerHiPlay::GetInstance().SendCollaborationApplyResult(nullptr);
    auto& callback = CollaborationManagerHiPlay::GetInstance().sendCollaborationApplyResult_;
    ApplyResultHiPlay(0, ServiceCollaborationManagerResultCode::REJECT, "REJECT");
    ApplyResultHiPlay(0, ServiceCollaborationManagerResultCode::PASS, "PASS");
    EXPECT_EQ(callback, nullptr);
    SLOGI("SendCollaborationApplyResult003, end");
}

/**
 * @tc.name: SendCollaborationApplyResult004
 * @tc.desc: Test SendCollaborationApplyResult with valid callback.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationApplyResult004, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationApplyResult004, start");
    auto& callbackRef = CollaborationManagerHiPlay::GetInstance().sendCollaborationApplyResult_;
    auto originalCallback = callbackRef;

    bool callbackCalled = false;
    int32_t receivedCode = -1;
    auto mockCallback = [&callbackCalled, &receivedCode](const int32_t code) {
        SLOGI("Mock SendCollaborationApplyResult004 callback invoked with code: %{public}d", code);
        callbackCalled = true;
        receivedCode = code;
    };
    callbackRef = mockCallback;
    CollaborationManagerHiPlay::GetInstance().SendCollaborationApplyResult(mockCallback);
    if (callbackRef) {
        callbackRef(AVSESSION_SUCCESS);
    }
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedCode, AVSESSION_SUCCESS);
    callbackRef = originalCallback;
    ApplyResultHiPlay(0, ServiceCollaborationManagerResultCode::REJECT, "REJECT");
    ApplyResultHiPlay(0, ServiceCollaborationManagerResultCode::PASS, "PASS");
    SLOGI("SendCollaborationApplyResult004, end");
}

/**
 * @tc.name: ListenCollaborationApplyResult001
 * @tc.desc: Test ListenCollaborationApplyResult with PASS result code.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ListenCollaborationApplyResult001, testing::ext::TestSize.Level1)
{
    SLOGI("ListenCollaborationApplyResult001, start");
    auto& instance = CollaborationManagerURLCasting::GetInstance();
    
    // Reset flags before test
    instance.applyResultFlag_ = false;
    instance.applyUserResultFlag_ = false;
    instance.collaborationRejectFlag_ = false;
    instance.waitUserDecisionFlag_ = false;
    
    // Call ListenCollaborationApplyResult to set up the callback
    instance.ListenCollaborationApplyResult();
    
    // Simulate callback with PASS result code
    ASSERT_NE(instance.sendCollaborationApplyResult_, nullptr);
    instance.sendCollaborationApplyResult_(ServiceCollaborationManagerResultCode::PASS);
    
    // Verify flags are set correctly for PASS
    EXPECT_TRUE(instance.applyResultFlag_);
    EXPECT_TRUE(instance.applyUserResultFlag_);
    EXPECT_FALSE(instance.collaborationRejectFlag_);
    SLOGI("ListenCollaborationApplyResult001, end");
}

/**
 * @tc.name: ListenCollaborationApplyResult002
 * @tc.desc: Test ListenCollaborationApplyResult with REJECT result code.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ListenCollaborationApplyResult002, testing::ext::TestSize.Level1)
{
    SLOGI("ListenCollaborationApplyResult002, start");
    auto& instance = CollaborationManagerURLCasting::GetInstance();
    
    // Reset flags before test
    instance.applyResultFlag_ = false;
    instance.applyUserResultFlag_ = false;
    instance.collaborationRejectFlag_ = false;
    instance.waitUserDecisionFlag_ = false;
    
    // Call ListenCollaborationApplyResult to set up the callback
    instance.ListenCollaborationApplyResult();
    
    // Simulate callback with REJECT result code
    ASSERT_NE(instance.sendCollaborationApplyResult_, nullptr);
    instance.sendCollaborationApplyResult_(ServiceCollaborationManagerResultCode::REJECT);
    
    // Verify flags are set correctly for REJECT
    EXPECT_TRUE(instance.collaborationRejectFlag_);
    EXPECT_TRUE(instance.applyResultFlag_);
    EXPECT_TRUE(instance.applyUserResultFlag_);
    SLOGI("ListenCollaborationApplyResult002, end");
}

/**
 * @tc.name: ListenCollaborationApplyResult003
 * @tc.desc: Test ListenCollaborationApplyResult with WAIT_SELECT result code.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ListenCollaborationApplyResult003, testing::ext::TestSize.Level1)
{
    SLOGI("ListenCollaborationApplyResult003, start");
    auto& instance = CollaborationManagerURLCasting::GetInstance();
    
    // Reset flags before test
    instance.applyResultFlag_ = false;
    instance.applyUserResultFlag_ = false;
    instance.collaborationRejectFlag_ = false;
    instance.waitUserDecisionFlag_ = false;
    
    // Call ListenCollaborationApplyResult to set up the callback
    instance.ListenCollaborationApplyResult();
    
    // Simulate callback with WAIT_SELECT result code
    ASSERT_NE(instance.sendCollaborationApplyResult_, nullptr);
    instance.sendCollaborationApplyResult_(ServiceCollaborationManagerResultCode::WAIT_SELECT);
    
    // Verify flags are set correctly for WAIT_SELECT
    EXPECT_TRUE(instance.applyResultFlag_);
    EXPECT_TRUE(instance.waitUserDecisionFlag_);
    EXPECT_FALSE(instance.collaborationRejectFlag_);
    SLOGI("ListenCollaborationApplyResult003, end");
}

/**
 * @tc.name: ListenCollaborationApplyResult004
 * @tc.desc: Test ListenCollaborationApplyResult with USER_AGREE result code.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, ListenCollaborationApplyResult004, testing::ext::TestSize.Level1)
{
    SLOGI("ListenCollaborationApplyResult004, start");
    auto& instance = CollaborationManagerURLCasting::GetInstance();
    
    // Reset flags before test
    instance.applyResultFlag_ = false;
    instance.applyUserResultFlag_ = false;
    instance.collaborationRejectFlag_ = false;
    instance.waitUserDecisionFlag_ = false;
    
    // Call ListenCollaborationApplyResult to set up the callback
    instance.ListenCollaborationApplyResult();
    
    // Simulate callback with USER_AGREE result code
    ASSERT_NE(instance.sendCollaborationApplyResult_, nullptr);
    // USER_AGREE branch only logs, flags should remain unchanged
    instance.sendCollaborationApplyResult_(ServiceCollaborationManagerResultCode::USER_AGREE);
    
    // Verify flags remain unchanged for USER_AGREE (only logs)
    EXPECT_FALSE(instance.applyResultFlag_);
    EXPECT_FALSE(instance.applyUserResultFlag_);
    EXPECT_FALSE(instance.collaborationRejectFlag_);
    EXPECT_FALSE(instance.waitUserDecisionFlag_);
    SLOGI("ListenCollaborationApplyResult004, end");
}