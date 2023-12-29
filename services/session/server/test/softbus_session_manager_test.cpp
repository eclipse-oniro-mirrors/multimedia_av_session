/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "migrate_avsession_constant.h"
#include "migrate_avsession_server.h"
#define private public
#define protected public
#include "softbus_distributed_data_manager.h"
#include "softbus_session_manager.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::AVSession;

static const char* g_perms[] = {"ohos.permission.DISTRIBUTED_SOFTBUS_CENTER", "ohos.permission.DISTRIBUTED_DATASYNC",
    "ohos.permission.ACCESS_SERVICE_DM"};
static const int SIZE = 3;
class SoftbusSessionManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void NativeTokenGet(const char *perms[], int size);

    std::shared_ptr<SoftbusSessionManager> manager_;
    std::shared_ptr<SoftbusDistributedDataManager> distributed_;
};

void SoftbusSessionManagerTest::SetUpTestCase() {}

void SoftbusSessionManagerTest::TearDownTestCase() {}

void SoftbusSessionManagerTest::SetUp()
{
    manager_ = std::make_shared<SoftbusSessionManager>();
    distributed_ = std::make_shared<SoftbusDistributedDataManager>();
    NativeTokenGet(g_perms, SIZE);
}

void SoftbusSessionManagerTest::TearDown()
{
    manager_ = nullptr;
    distributed_ = nullptr;
    NativeTokenGet(nullptr, 0);
}

void SoftbusSessionManagerTest::NativeTokenGet(const char *perms[], int size)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = size,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = "softbus_session_manager_test";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/**
* @tc.name: SoftbusDistributedTest001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SoftbusDistributedTest001, TestSize.Level1)
{
    SLOGI("SoftbusDistributedTest001 begin");
    distributed_->Init();
    std::string pkg = "AVSESSION";
    distributed_->InitSessionServer(pkg);
    
    std::shared_ptr<MigrateAVSessionServer> server = std::make_shared<MigrateAVSessionServer>();
    distributed_->CreateServer(server);
    EXPECT_EQ(distributed_->serverMap_.size() > 0, true);

    int32_t sessionId = 1;
    distributed_->SessionOpened(sessionId);
    distributed_->SessionClosed(sessionId);
    std::string data = "111";
    distributed_->MessageReceived(sessionId, data);
    distributed_->BytesReceived(sessionId, data);
    distributed_->OnSessionServerOpened(sessionId);
    std::string deviceId = "1";
    distributed_->OnSessionServerClosed(sessionId, deviceId);
    distributed_->OnMessageHandleReceived(sessionId, data);
    distributed_->OnBytesServerReceived(sessionId, data);

    distributed_->ReleaseServer(server);
    EXPECT_EQ(distributed_->serverMap_.size() == 0, true);

    distributed_->DestroySessionServer(pkg);
    SLOGI("SoftbusDistributedTest001 end");
}

/**
* @tc.name: CreateSessionServer001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, CreateSessionServer001, TestSize.Level1)
{
    SLOGI("CreateSessionServer001 begin");
    std::string pkg = "111";
    int32_t ret = manager_->CreateSessionServer(pkg);
    EXPECT_EQ(ret, -1);
    SLOGI("CreateSessionServer001 end");
}

/**
* @tc.name: RemoveSessionServer001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, RemoveSessionServer001, TestSize.Level1)
{
    SLOGI("RemoveSessionServer001 begin");
    std::string pkg = "111";
    int32_t ret = manager_->RemoveSessionServer(pkg);
    EXPECT_EQ(ret, -1);
    SLOGI("RemoveSessionServer001 end");
}

/**
* @tc.name: OpenSession001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OpenSession001, TestSize.Level1)
{
    SLOGI("OpenSession001 begin");
    int32_t ret = manager_->OpenSession("aaa", CONFIG_SOFTBUS_SESSION_TAG);
    EXPECT_EQ(ret, -1);
    SLOGI("OpenSession001 end");
}

/**
* @tc.name: CreateSessionServer001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, CloseSession001, TestSize.Level1)
{
    SLOGI("CloseSession001 begin");
    int32_t sessionId = 123;
    std::string pkg = "123";
    manager_->RemoveSessionServer(pkg);
    int32_t ret = manager_->CloseSession(sessionId);
    EXPECT_EQ(ret, -1);
    SLOGI("CloseSession001 end");
}

/**
* @tc.name: SendMessage001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SendMessage001, TestSize.Level1)
{
    SLOGI("SendMessage001 begin");
    int32_t sessionId = 123;
    std::string data = "";
    int32_t ret = manager_->SendMessage(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendMessage001 end");
}

/**
* @tc.name: SendByte001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SendByte001, TestSize.Level1)
{
    SLOGI("SendByte001 begin");
    int32_t sessionId = 123;
    std::string data = "";
    int32_t ret = manager_->SendBytes(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendByte001 end");
}

/**
* @tc.name: ObtainPeerDeviceId001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, ObtainPeerDeviceId001, TestSize.Level1)
{
    SLOGI("ObtainPeerDeviceId001 begin");
    int32_t sessionId = 0;
    std::string deviceId;
    int32_t ret = manager_->ObtainPeerDeviceId(sessionId, deviceId);
    EXPECT_EQ(ret, -1);
    SLOGI("ObtainPeerDeviceId001 end");
}

/**
* @tc.name: GetPeerSessionName001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, GetPeerSessionName001, TestSize.Level1)
{
    SLOGI("GetPeerSessionName001 begin");
    int32_t sessionId = 0;
    std::string sessionName;
    int32_t ret = manager_->GetPeerSessionName(sessionId, sessionName);
    EXPECT_EQ(ret, -1);
    SLOGI("GetPeerSessionName001 end");
}

/**
* @tc.name: IsServerSide001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, IsServerSide001, TestSize.Level1)
{
    SLOGI("IsServerSide001 begin");
    int32_t sessionId = 123;
    int32_t ret = manager_->IsServerSide(sessionId);
    EXPECT_EQ(ret, false);
    SLOGI("IsServerSide001 end");
}

/**
* @tc.name: OnSessionOpened001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OnSessionOpened001, TestSize.Level1)
{
    SLOGI("OnSessionOpened001 begin");
    int32_t sessionId = 123;
    int32_t ret = manager_->OnSessionOpened(sessionId, AVSESSION_ERROR);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("OnSessionOpened001 end");
}

/**
* @tc.name: OnSessionOpened002
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OnSessionOpened002, TestSize.Level1)
{
    SLOGI("OnSessionOpened002 begin");
    int32_t sessionId = 456;
    int32_t ret = manager_->OnSessionOpened(sessionId, AVSESSION_SUCCESS);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("OnSessionOpened002 end");
}