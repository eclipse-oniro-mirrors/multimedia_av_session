/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <chrono>
#include <thread>

#include "accesstoken_kit.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_log.h"
#include "avsession_service.h"
#include "migrate_avsession_constant.h"
#include "migrate_avsession_manager.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};
static std::shared_ptr<MigrateAVSessionProxy> g_MigrateAVSessionProxy {nullptr};

class MigrateAVSessionManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MigrateAVSessionManagerTest::SetUpTestCase()
{
    SLOGI("MigrateAVSessionManagerTest SetUpTestCase");
    g_AVSessionService =  std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
    g_MigrateAVSessionProxy = std::make_shared<MigrateAVSessionProxy>(g_AVSessionService.get());
}

void MigrateAVSessionManagerTest::TearDownTestCase()
{
    SLOGI("MigrateAVSessionManagerTest TearDownTestCase");
}

void MigrateAVSessionManagerTest::SetUp()
{
    SLOGI("MigrateAVSessionManagerTest SetUp");
}

void MigrateAVSessionManagerTest::TearDown()
{
    SLOGI("MigrateAVSessionManagerTest TearDown");
}

/**
* @tc.name: CreateRemoteSessionProxy001
* @tc.desc: fail to create
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, CreateRemoteSessionProxy001, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::shared_ptr<MigrateAVSessionProxy> proxy {nullptr};
    std::string networkId = "";
    std::string scene = "";
    MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId, scene, proxy);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: CreateRemoteSessionProxy002
* @tc.desc: fail to create
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, CreateRemoteSessionProxy002, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "";
    std::string scene = "";
    MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId, scene, g_MigrateAVSessionProxy);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: CreateRemoteSessionProxy003
* @tc.desc: fail to create
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, CreateRemoteSessionProxy003, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = std::string();
    std::string scene;
    MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId, scene, g_MigrateAVSessionProxy);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: CreateRemoteSessionProxy004
* @tc.desc: fail to create
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, CreateRemoteSessionProxy004, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "test";
    MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId, scene, g_MigrateAVSessionProxy);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: CreateRemoteSessionProxy005
* @tc.desc: fail to create
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, CreateRemoteSessionProxy005, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "SuperLauncher-Dual";
    MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId, scene, g_MigrateAVSessionProxy);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 1);
}

/**
* @tc.name: CreateRemoteSessionProxy006
* @tc.desc: fail to create
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, CreateRemoteSessionProxy006, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "MigrateWithNext";
    MigrateAVSessionManager::GetInstance().proxyMap_.insert({scene, g_MigrateAVSessionProxy});
    MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId, scene, g_MigrateAVSessionProxy);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: ReleaseRemoteSessionProxy001
* @tc.desc: fail to release
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, ReleaseRemoteSessionProxy001, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "";
    MigrateAVSessionManager::GetInstance().ReleaseRemoteSessionProxy(networkId, scene);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: ReleaseRemoteSessionProxy002
* @tc.desc: fail to release
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, ReleaseRemoteSessionProxy002, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "";
    MigrateAVSessionManager::GetInstance().ReleaseRemoteSessionProxy(networkId, scene);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: ReleaseRemoteSessionProxy003
* @tc.desc: fail to release
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, ReleaseRemoteSessionProxy003, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "test";
    MigrateAVSessionManager::GetInstance().ReleaseRemoteSessionProxy(networkId, scene);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: ReleaseRemoteSessionProxy004
* @tc.desc: fail to release
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, ReleaseRemoteSessionProxy004, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "MigrateWithNext";
    MigrateAVSessionManager::GetInstance().ReleaseRemoteSessionProxy(networkId, scene);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}

/**
* @tc.name: ReleaseRemoteSessionProxy005
* @tc.desc: fail to release
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, ReleaseRemoteSessionProxy005, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "SuperLauncher-Dual";
    MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId, scene, g_MigrateAVSessionProxy);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
    MigrateAVSessionManager::GetInstance().ReleaseRemoteSessionProxy(networkId, scene);
}

/**
* @tc.name: ReleaseRemoteSessionProxy006
* @tc.desc: fail to release
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(MigrateAVSessionManagerTest, ReleaseRemoteSessionProxy006, TestSize.Level0)
{
    MigrateAVSessionManager::GetInstance().refs_.store(0);
    std::string networkId = "test";
    std::string scene = "test";
    MigrateAVSessionManager::GetInstance().ReleaseRemoteSessionProxy(networkId, scene);
    EXPECT_EQ(MigrateAVSessionManager::GetInstance().refs_.load(memory_order_relaxed), 0);
}
