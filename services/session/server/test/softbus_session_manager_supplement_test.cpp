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
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_service.h"
#include "migrate_avsession_constant.h"
#include "migrate_avsession_proxy.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "softbus_distributed_data_manager.h"
#include "softbus_session_manager.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

namespace OHOS {
namespace AVSession {

std::shared_ptr<SoftbusDistributedDataManager> g_SoftbusDistributedDataManager {nullptr};
std::shared_ptr<MigrateAVSessionProxy> g_MigrateAVSessionProxy {nullptr};
std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};

class SoftbusSessionManagerSupplementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SoftbusSessionManagerSupplementTest::SetUpTestCase()
{
    g_SoftbusDistributedDataManager = std::make_shared<SoftbusDistributedDataManager>();
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
    g_MigrateAVSessionProxy = std::make_shared<MigrateAVSessionProxy>(g_AVSessionService.get());
}

void SoftbusSessionManagerSupplementTest::TearDownTestCase()
{
    g_SoftbusDistributedDataManager = nullptr;
    g_MigrateAVSessionProxy = nullptr;
    g_AVSessionService = nullptr;
}

void SoftbusSessionManagerSupplementTest::SetUp() {}

void SoftbusSessionManagerSupplementTest::TearDown() {}

/**
 * @tc.name: CreateProxy001
 * @tc.desc: fail to create
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, CreateProxy001, TestSize.Level0)
{
    std::string peerNetworkId = "";
    std::string packageName = "";
    bool ret = g_SoftbusDistributedDataManager->CreateProxy(nullptr, peerNetworkId, packageName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CreateProxy002
 * @tc.desc: fail to create
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, CreateProxy002, TestSize.Level0)
{
    std::string peerNetworkId = "";
    std::string packageName = "";
    bool ret = g_SoftbusDistributedDataManager->CreateProxy(g_MigrateAVSessionProxy, peerNetworkId, packageName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CreateProxy003
 * @tc.desc: fail to create
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, CreateProxy003, TestSize.Level0)
{
    std::string peerNetworkId = "";
    std::string packageName = "test";
    bool ret = g_SoftbusDistributedDataManager->CreateProxy(g_MigrateAVSessionProxy, peerNetworkId, packageName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CreateProxy004
 * @tc.desc: fail to create
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, CreateProxy004, TestSize.Level0)
{
    std::string peerNetworkId = "test";
    std::string packageName = "";
    bool ret = g_SoftbusDistributedDataManager->CreateProxy(g_MigrateAVSessionProxy, peerNetworkId, packageName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CreateProxy005
 * @tc.desc: fail to create
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, CreateProxy005, TestSize.Level0)
{
    std::string peerNetworkId = "0.0.0.0";
    std::string packageName = "packageName";
    std::map<int32_t, std::shared_ptr<SoftbusSessionProxy>> proxyMap;
    proxyMap.insert({0, g_MigrateAVSessionProxy});
    g_SoftbusDistributedDataManager->mDeviceToProxyMap_.insert({peerNetworkId, proxyMap});
    g_SoftbusDistributedDataManager->mProxySocketMap_.insert({peerNetworkId, 0});
    bool ret = g_SoftbusDistributedDataManager->CreateProxy(g_MigrateAVSessionProxy, peerNetworkId, packageName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CreateProxy006
 * @tc.desc: have proxy in map
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, CreateProxy006, TestSize.Level0)
{
    std::string peerNetworkId = "0.0.0.0";
    std::string packageName = "packageName";
    int32_t socketId = 100;
    std::map<int32_t, std::shared_ptr<SoftbusSessionProxy>> proxyMap;
    proxyMap.insert({socketId, g_MigrateAVSessionProxy});
    g_SoftbusDistributedDataManager->mDeviceToProxyMap_.insert({peerNetworkId, proxyMap});
    g_SoftbusDistributedDataManager->mProxySocketMap_.insert({peerNetworkId, socketId});
    bool ret = g_SoftbusDistributedDataManager->CreateProxy(g_MigrateAVSessionProxy, peerNetworkId, packageName);
    EXPECT_EQ(ret, false);
}


/**
 * @tc.name: ReleaseProxy001
 * @tc.desc: proxy is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, ReleaseProxy001, TestSize.Level0)
{
    std::string peerNetworkId = "0.0.0.0";
    bool ret = g_SoftbusDistributedDataManager->ReleaseProxy(nullptr, peerNetworkId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ReleaseProxy002
 * @tc.desc: fail to release proxy
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, ReleaseProxy002, TestSize.Level0)
{
    std::string peerNetworkId = "";
    bool ret = g_SoftbusDistributedDataManager->ReleaseProxy(g_MigrateAVSessionProxy, peerNetworkId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ReleaseProxy003
 * @tc.desc: ReleaseProxy fail fo proxyMap is null
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, ReleaseProxy003, TestSize.Level0)
{
    std::string peerNetworkId = "0.0.0.0";
    bool ret = g_SoftbusDistributedDataManager->ReleaseProxy(g_MigrateAVSessionProxy, peerNetworkId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ReleaseProxy004
 * @tc.desc: fail to release proxy
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, ReleaseProxy004, TestSize.Level0)
{
    std::string peerNetworkId = "0.0.0.0";
    int32_t socketId = 1;
    std::map<int32_t, std::shared_ptr<SoftbusSessionProxy>> proxyMap;
    proxyMap.insert({socketId, g_MigrateAVSessionProxy});
    g_SoftbusDistributedDataManager->mDeviceToProxyMap_.insert({peerNetworkId, proxyMap});
    bool ret = g_SoftbusDistributedDataManager->ReleaseProxy(g_MigrateAVSessionProxy, peerNetworkId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ReleaseProxy005
 * @tc.desc: success to release proxy
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, ReleaseProxy005, TestSize.Level0)
{
    std::string peerNetworkId = "0.0.0.0";
    int32_t characteristic = g_MigrateAVSessionProxy->GetCharacteristic();
    std::map<int32_t, std::shared_ptr<SoftbusSessionProxy>> proxyMap;
    proxyMap.insert({characteristic, g_MigrateAVSessionProxy});
    g_SoftbusDistributedDataManager->mDeviceToProxyMap_.insert({peerNetworkId, proxyMap});
    bool ret = g_SoftbusDistributedDataManager->ReleaseProxy(g_MigrateAVSessionProxy, peerNetworkId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: BytesReceived001
 * @tc.desc: proxy to received
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(SoftbusSessionManagerSupplementTest, BytesReceived001, TestSize.Level0)
{
    int32_t socket = 1;
    std::string data = "test";
    g_SoftbusDistributedDataManager->isServer_ = false;
    g_SoftbusDistributedDataManager->BytesReceived(socket, data);
    EXPECT_EQ(g_SoftbusDistributedDataManager->isServer_, false);
}
} //AVSession
} //OHOS