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
#include "collaboration_manager.h"

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
    int32_t ret = CollaborationManager::GetInstance().RegisterLifecycleCallback();
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
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback
        = registerLifecycleCallback;
    int32_t ret = CollaborationManager::GetInstance().RegisterLifecycleCallback();
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
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback
        = registerLifecycleCallback;
    int32_t ret = CollaborationManager::GetInstance().RegisterLifecycleCallback();
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
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback
        = nullptr;
    int32_t ret = CollaborationManager::GetInstance().RegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("RegisterLifecycleCallback004, end");
}

/**
 * @tc.name: UnRegisterLifecycleCallback001
 * @tc.desc: Test UnRegisterLifecycleCallback
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, UnRegisterLifecycleCallback001, testing::ext::TestSize.Level1)
{
    SLOGI("UnRegisterLifecycleCallback001, start");
    int32_t ret = CollaborationManager::GetInstance().UnRegisterLifecycleCallback();
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
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_UnRegisterLifecycleCallback
        = unRegisterLifecycleCallback;
    int32_t ret = CollaborationManager::GetInstance().UnRegisterLifecycleCallback();
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
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_UnRegisterLifecycleCallback
        = unRegisterLifecycleCallback;
    int32_t ret = CollaborationManager::GetInstance().UnRegisterLifecycleCallback();
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("UnRegisterLifecycleCallback003, end");
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
    int32_t ret = CollaborationManager::GetInstance().PublishServiceState(peerNetworkId, state);
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
    auto publishServiceState = [](const char* peerNetworkId, const char* serviceName,
        const char* extraInfo, ServiceCollaborationManagerBussinessStatus state) {
            return static_cast<int32_t>(0);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_PublishServiceState
        = publishServiceState;
    int32_t ret = CollaborationManager::GetInstance().PublishServiceState(peerNetworkId, state);
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
    auto publishServiceState = [](const char* peerNetworkId, const char* serviceName,
        const char* extraInfo, ServiceCollaborationManagerBussinessStatus state) {
            return static_cast<int32_t>(1);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_PublishServiceState
        = publishServiceState;
    int32_t ret = CollaborationManager::GetInstance().PublishServiceState(peerNetworkId, state);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("PublishServiceState003, end");
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
    int32_t ret = CollaborationManager::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_ERROR);
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
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(0);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManager::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
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
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(1);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManager::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_ERROR);
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
    auto& instance = CollaborationManager::GetInstance();
    auto originalResourceRequest = instance.resourceRequest_;
    const char* peerNetworkId = "";
    DeviceInfo deviceInfo;
    auto applyAdvancedResource = [](const char* networkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(1);
    };
    instance.exportapi_.ServiceCollaborationManager_ApplyAdvancedResource = applyAdvancedResource;
    instance.resourceRequest_ = nullptr;
    int32_t ret = CollaborationManager::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
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
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest,
        ServiceCollaborationManager_Callback* callback) {
            EXPECT_EQ(resourceRequest->linkType, ServiceCollaborationManagerLinkType::NATIVE_P2P);
            return static_cast<int32_t>(0);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManager::GetInstance().ApplyAdvancedResource(peerNetworkId, deviceInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("ApplyAdvancedResource005, end");
}

/**
 * @tc.name: SendCollaborationOnStop001
 * @tc.desc: Test SendCollaborationOnStop with null callback.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationOnStop001, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationOnStop001, start");
    CollaborationManager::GetInstance().SendCollaborationOnStop(nullptr);
    auto& sendCallback = CollaborationManager::GetInstance().sendCollaborationOnStop_;
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
    CollaborationManager::GetInstance().SendCollaborationOnStop([&callbackCalled]() {
        callbackCalled = true;
    });
    auto& saved = CollaborationManager::GetInstance().sendCollaborationOnStop_;
    EXPECT_NE(saved, nullptr);
    saved();
    EXPECT_TRUE(callbackCalled);
    SLOGI("SendCollaborationOnStop002, end");
}

/**
 * @tc.name: SendCollaborationApplyResult001
 * @tc.desc: Test SendCollaborationApplyResult with null callback.
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationApplyResult001, testing::ext::TestSize.Level4)
{
    SLOGI("SendCollaborationApplyResult001, start");
    CollaborationManager::GetInstance().SendCollaborationApplyResult(nullptr);
    auto& callback = CollaborationManager::GetInstance().sendCollaborationApplyResult_;
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
    auto& callbackRef = CollaborationManager::GetInstance().sendCollaborationApplyResult_;
    auto originalCallback = callbackRef;

    bool callbackCalled = false;
    int32_t receivedCode = -1;
    auto mockCallback = [&callbackCalled, &receivedCode](const int32_t code) {
        SLOGI("Mock SendCollaborationApplyResult callback invoked with code: %{public}d", code);
        callbackCalled = true;
        receivedCode = code;
    };
    callbackRef = mockCallback;
    CollaborationManager::GetInstance().SendCollaborationApplyResult(mockCallback);
    if (callbackRef) {
        callbackRef(AVSESSION_SUCCESS);
    }
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedCode, AVSESSION_SUCCESS);
    callbackRef = originalCallback;
    SLOGI("SendCollaborationApplyResult002, end");
}