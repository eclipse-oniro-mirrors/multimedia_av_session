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
    int32_t ret = CollaborationManager::GetInstance().ApplyAdvancedResource(peerNetworkId);
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
    auto applyAdvancedResource = [](const char* peerNetworkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(0);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManager::GetInstance().ApplyAdvancedResource(peerNetworkId);
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
    auto applyAdvancedResource = [](const char* peerNetworkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest,
        ServiceCollaborationManager_Callback* callback) {
            return static_cast<int32_t>(1);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_ApplyAdvancedResource
        = applyAdvancedResource;
    int32_t ret = CollaborationManager::GetInstance().ApplyAdvancedResource(peerNetworkId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("ApplyAdvancedResource003, end");
}

/**
 * @tc.name: SendCollaborationOnStop001
 * @tc.desc: Test ApplyAdvancedResource
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationOnStop001, testing::ext::TestSize.Level1)
{
    SLOGI("SendCollaborationOnStop001, start");
    auto applyAdvancedResource = [](void) {
        SLOGI("SendCollaborationOnStop001 do with callback");
    };
    CollaborationManager::GetInstance().SendCollaborationOnStop(applyAdvancedResource);
    EXPECT_EQ(applyAdvancedResource != nullptr, true);
    SLOGI("SendCollaborationOnStop001, end");
}

/**
 * @tc.name: SendCollaborationOnStop002
 * @tc.desc: Test ApplyAdvancedResource
 * @tc.type: FUNC
 */
static HWTEST_F(CollaborationManagerTest, SendCollaborationOnStop002, testing::ext::TestSize.Level1)
{
    SLOGI("SendCollaborationOnStop002, start");
    auto applyAdvancedResource = nullptr;
    CollaborationManager::GetInstance().SendCollaborationOnStop(applyAdvancedResource);
    EXPECT_EQ(applyAdvancedResource, nullptr);
    SLOGI("SendCollaborationOnStop002, end");
}
