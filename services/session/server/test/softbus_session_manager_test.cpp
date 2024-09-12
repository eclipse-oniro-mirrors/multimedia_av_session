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
    char infoName[] = "testInfoName";
    char infoNetworkId[] = "testInfoNetworkId";
    char infoPkgName[] = "testInfoPkgName";
    PeerSocketInfo info = {
        .name = infoName,
        .networkId = infoNetworkId,
        .pkgName = infoPkgName,
        .dataType = DATA_TYPE_BYTES,
    };
    distributed_->SessionOpened(sessionId, info);
    distributed_->SessionClosed(sessionId);
    std::string data = "111";
    distributed_->MessageReceived(sessionId, data);
    distributed_->BytesReceived(sessionId, data);
    distributed_->OnSessionServerOpened();
    distributed_->OnSessionServerClosed(sessionId);
    distributed_->OnMessageHandleReceived(sessionId, data);
    distributed_->OnBytesServerReceived(data);

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
    int32_t ret = manager_->Socket(pkg);
    EXPECT_EQ(ret <= 0, true);
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
    int32_t sessionId = 123;
    manager_->Shutdown(sessionId);
    SLOGI("RemoveSessionServer001 end");
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
* @tc.name: OnSessionOpened001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OnSessionOpened001, TestSize.Level1)
{
    SLOGI("OnSessionOpened001 begin");
    int32_t sessionId = 123;
    char infoName[] = "testInfoName";
    char infoNetworkId[] = "testInfoNetworkId";
    char infoPkgName[] = "testInfoPkgName";
    PeerSocketInfo info = {
        .name = infoName,
        .networkId = infoNetworkId,
        .pkgName = infoPkgName,
        .dataType = DATA_TYPE_BYTES,
    };
    manager_->OnBind(sessionId, info);
    SLOGI("OnSessionOpened001 end");
}


/**
* @tc.name: SendMessage002
* @tc.desc: test SendMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SendMessage002, TestSize.Level1)
{
    SLOGI("SendMessage002 begin");
    int32_t sessionId = -1;
    std::string data = "";
    int32_t ret = manager_->SendMessage(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendMessage002 end");
}

/**
* @tc.name: SendMessage003
* @tc.desc: test SendMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SendMessage003, TestSize.Level1)
{
    SLOGI("SendMessage003 begin");
    int32_t sessionId = -1;
    std::string data = "123";
    int32_t ret = manager_->SendMessage(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendMessage003 end");
}

/**
* @tc.name: SendMessage004
* @tc.desc: test SendMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SendMessage004, TestSize.Level1)
{
    SLOGI("SendMessage004 begin");
    int32_t sessionId = 100;
    std::string data = "123";
    int32_t ret = manager_->SendMessage(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendMessage004 end");
}

/**
* @tc.name: SendByte002
* @tc.desc: test SendBytes
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SendByte002, TestSize.Level1)
{
    SLOGI("SendByte002 begin");
    int32_t sessionId = -1;
    std::string data = "";
    int32_t ret = manager_->SendBytes(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendByte002 end");
}

/**
* @tc.name: SendByte003
* @tc.desc: test SendBytes
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SendByte003, TestSize.Level1)
{
    SLOGI("SendByte003 begin");
    int32_t sessionId = -1;
    std::string data = "123";
    int32_t ret = manager_->SendBytes(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendByte003 end");
}

/**
* @tc.name: SendByte004
* @tc.desc: test SendBytes
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, SendByte004, TestSize.Level1)
{
    SLOGI("SendByte004 begin");
    int32_t sessionId = 100;
    std::string data = "123";
    int32_t ret = manager_->SendBytes(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendByte004 end");
}

/**
* @tc.name: ObtainPeerDeviceId002
* @tc.desc: test ObtainPeerDeviceId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, ObtainPeerDeviceId002, TestSize.Level1)
{
    SLOGI("ObtainPeerDeviceId002 begin");
    int32_t sessionId = 1230;
    std::string deviceId;
    int32_t ret = manager_->ObtainPeerDeviceId(sessionId, deviceId);
    EXPECT_EQ(ret, -1);
    SLOGI("ObtainPeerDeviceId002 end");
}

/**
* @tc.name: AddSessionListener001
* @tc.desc: test AddSessionListener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, AddSessionListener001, TestSize.Level1)
{
    SLOGI("AddSessionListener001 begin");
    std::shared_ptr<SoftbusSessionListener> softbusSessionListener;
    manager_->AddSessionListener(softbusSessionListener);
    SLOGI("AddSessionListener001 end");
}

/**
* @tc.name: OnBind001
* @tc.desc: test OnBind
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OnBind001, TestSize.Level1)
{
    SLOGI("OnBind001 begin");
    int32_t socket = 1231;
    PeerSocketInfo info;
    manager_->OnBind(socket, info);
    SLOGI("OnBind001 end");
}

/**
* @tc.name: OnMessage001
* @tc.desc: test OnMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OnMessage001, TestSize.Level1)
{
    SLOGI("OnMessage001 begin");
    int32_t socket = 1231;
    void *data = nullptr;
    int32_t dataLen = 10;
    manager_->OnMessage(socket, data, dataLen);
    SLOGI("OnMessage001 end");
}

/**
* @tc.name: OnMessage002
* @tc.desc: test OnMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OnMessage002, TestSize.Level1)
{
    SLOGI("OnMessage002 begin");
    int32_t socket = 1231;
    int *ptr = &socket;
    void *data = static_cast<void*>(ptr);
    int32_t dataLen = 10;
    manager_->OnMessage(socket, data, dataLen);
    SLOGI("OnMessage002 end");
}

/**
* @tc.name: OnBytes001
* @tc.desc: test OnMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OnBytes001, TestSize.Level1)
{
    SLOGI("OnBytes001 begin");
    int32_t socket = 1231;
    void *data = nullptr;
    int32_t dataLen = 10;
    manager_->OnMessage(socket, data, dataLen);
    SLOGI("OnBytes001 end");
}

/**
* @tc.name: OnMessage002
* @tc.desc: test OnMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, OnBytes002, TestSize.Level1)
{
    SLOGI("OnBytes002 begin");
    int32_t socket = 1231;
    int *ptr = &socket;
    void *data = static_cast<void*>(ptr);
    int32_t dataLen = 10;
    manager_->OnMessage(socket, data, dataLen);
    SLOGI("OnBytes002 end");
}

/**
* @tc.name: CreateServer001
* @tc.desc: test CreateServer
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, CreateServer001, TestSize.Level1)
{
    SLOGI("CreateServer001 begin");
    distributed_->Init();
    std::string pkg = "AVSESSION";
    distributed_->InitSessionServer(pkg);

    std::shared_ptr<MigrateAVSessionServer> server;
    distributed_->CreateServer(server);
    SLOGI("CreateServer001 end");
}

/**
* @tc.name: ReleaseServer001
* @tc.desc: test ReleaseServer
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusSessionManagerTest, ReleaseServer001, TestSize.Level1)
{
    SLOGI("ReleaseServer001 begin");
    distributed_->Init();
    std::string pkg = "AVSESSION";
    distributed_->InitSessionServer(pkg);
    std::shared_ptr<MigrateAVSessionServer> server = std::make_shared<MigrateAVSessionServer>();
    distributed_->ReleaseServer(server);
    SLOGI("ReleaseServer001 end");
}