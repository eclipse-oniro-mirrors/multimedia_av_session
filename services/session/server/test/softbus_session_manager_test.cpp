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
static HWTEST_F(SoftbusSessionManagerTest, SoftbusDistributedTest001, TestSize.Level0)
{
    SLOGI("SoftbusDistributedTest001 begin");
    distributed_->Init();
    std::string pkg = "AVSESSION";
    distributed_->InitSessionServer(pkg);

    std::shared_ptr<MigrateAVSessionServer> server = std::make_shared<MigrateAVSessionServer>();
    distributed_->CreateServer(server);
    EXPECT_EQ(distributed_->serverMap_.size() > 0, true);

    int32_t sessionId = 1;
#ifdef DSOFTBUS_ENABLE
    char infoName[] = "Media_Session_RemoteCtrl";
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
#endif
    std::string data = "111";
    int32_t socket = 1;
    distributed_->MessageReceived(sessionId, data);
    distributed_->BytesReceived(sessionId, data);
    distributed_->OnSessionServerOpened();
    distributed_->OnSessionServerClosed(sessionId);
    distributed_->OnMessageHandleReceived(sessionId, data);
    distributed_->OnBytesServerReceived(socket, data);

    distributed_->ReleaseServer(server);
    EXPECT_EQ(distributed_->serverMap_.size() == 0, true);

    distributed_->DestroySessionServer(pkg);
    SLOGI("SoftbusDistributedTest001 end");
}

#ifdef DSOFTBUS_ENABLE
/**
* @tc.name: CreateSessionServer001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, CreateSessionServer001, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, RemoveSessionServer001, TestSize.Level0)
{
    SLOGI("RemoveSessionServer001 begin");
    int32_t sessionId = 123;
    std::string data = "";
    int32_t ret = manager_->SendMessage(sessionId, data);
    EXPECT_EQ(ret, -1);
    manager_->Shutdown(sessionId);
    SLOGI("RemoveSessionServer001 end");
}

/**
* @tc.name: SendMessage001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, SendMessage001, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, SendByte001, TestSize.Level0)
{
    SLOGI("SendByte001 begin");
    int32_t sessionId = 123;
    std::string data = "";
    int32_t ret = manager_->SendBytes(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendByte001 end");
}
#endif

/**
* @tc.name: ObtainPeerDeviceId001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, ObtainPeerDeviceId001, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, OnSessionOpened001, TestSize.Level0)
{
    SLOGI("OnSessionOpened001 begin");
#ifdef DSOFTBUS_ENABLE
    int32_t sessionId = 123;
    char infoName[] = "Media_Session_RemoteCtrl";
    char infoNetworkId[] = "testInfoNetworkId";
    char infoPkgName[] = "testInfoPkgName";
    PeerSocketInfo info = {
        .name = infoName,
        .networkId = infoNetworkId,
        .pkgName = infoPkgName,
        .dataType = DATA_TYPE_BYTES,
    };
    EXPECT_TRUE(manager_ != nullptr);
    manager_->OnBind(sessionId, info);
#endif
    SLOGI("OnSessionOpened001 end");
}

#ifdef DSOFTBUS_ENABLE
/**
* @tc.name: SendMessage002
* @tc.desc: test SendMessage
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, SendMessage002, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, SendMessage003, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, SendMessage004, TestSize.Level0)
{
    SLOGI("SendMessage004 begin");
    int32_t sessionId = 100;
    std::string data = "123";
    int32_t ret = manager_->SendMessage(sessionId, data);
    EXPECT_EQ(ret, -1);
    SLOGI("SendMessage004 end");
}
#endif

/**
* @tc.name: SendByte002
* @tc.desc: test SendBytes
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, SendByte002, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, SendByte003, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, SendByte004, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, ObtainPeerDeviceId002, TestSize.Level0)
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
static HWTEST_F(SoftbusSessionManagerTest, AddSessionListener001, TestSize.Level0)
{
    SLOGI("AddSessionListener001 begin");
    std::shared_ptr<SoftbusSessionListener> softbusSessionListener;
    manager_->AddSessionListener(softbusSessionListener);
    EXPECT_EQ(softbusSessionListener, nullptr);
    SLOGI("AddSessionListener001 end");
}

#ifdef DSOFTBUS_ENABLE
/**
* @tc.name: OnBind001
* @tc.desc: test OnBind
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, OnBind001, TestSize.Level0)
{
    SLOGI("OnBind001 begin");
    int32_t socket = 1231;
    PeerSocketInfo info;
    EXPECT_TRUE(manager_ != nullptr);
    manager_->OnBind(socket, info);
    SLOGI("OnBind001 end");
}

/**
* @tc.name: OnMessage001
* @tc.desc: test OnMessage
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, OnMessage001, TestSize.Level0)
{
    SLOGI("OnMessage001 begin");
    int32_t socket = 1231;
    void *data = nullptr;
    int32_t dataLen = 10;
    EXPECT_TRUE(manager_ != nullptr);
    manager_->OnMessage(socket, data, dataLen);
    SLOGI("OnMessage001 end");
}

/**
* @tc.name: OnMessage002
* @tc.desc: test OnMessage
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, OnMessage002, TestSize.Level0)
{
    SLOGI("OnMessage002 begin");
    int32_t socket = 1231;
    int *ptr = &socket;
    void *data = static_cast<void*>(ptr);
    int32_t dataLen = 10;
    EXPECT_TRUE(manager_ != nullptr);
    manager_->OnMessage(socket, data, dataLen);
    SLOGI("OnMessage002 end");
}
#endif

/**
* @tc.name: CreateServer001
* @tc.desc: test CreateServer
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, CreateServer001, TestSize.Level0)
{
    SLOGI("CreateServer001 begin");
    EXPECT_TRUE(distributed_ != nullptr);
    distributed_->Init();
    std::string pkg = "AVSESSION";
    distributed_->InitSessionServer(pkg);

    std::shared_ptr<MigrateAVSessionServer> server;
    distributed_->CreateServer(server);
    EXPECT_EQ(server, nullptr);
    SLOGI("CreateServer001 end");
}

/**
* @tc.name: ReleaseServer001
* @tc.desc: test ReleaseServer
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, ReleaseServer001, TestSize.Level0)
{
    SLOGI("ReleaseServer001 begin");
    EXPECT_TRUE(distributed_ != nullptr);
    distributed_->Init();
    std::string pkg = "AVSESSION";
    distributed_->InitSessionServer(pkg);
    std::shared_ptr<MigrateAVSessionServer> server = std::make_shared<MigrateAVSessionServer>();
    distributed_->ReleaseServer(server);
    EXPECT_TRUE(server != nullptr);
    SLOGI("ReleaseServer001 end");
}

#ifdef DSOFTBUS_ENABLE
/**
* @tc.name: OnBytes001
* @tc.desc: set data to nullptr
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, OnBytes001, TestSize.Level0)
{
    SLOGI("OnBytes001 begin");
    int32_t socket = 1001;
    void *data = nullptr;
    int32_t dataLen = 10;
    manager_->OnBytes(socket, data, dataLen);
    EXPECT_TRUE(data == nullptr);
    SLOGI("OnBytes001 end");
}

/**
* @tc.name: OnBytes002
* @tc.desc: set data to not nullptr
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, OnBytes002, TestSize.Level0)
{
    SLOGI("OnBytes002 begin");
    int32_t socket = 1001;
    int32_t dataArr[] = {1, 0, 1, 0};
    void *data = static_cast<void*>(dataArr);
    int32_t dataLen = 10;
    manager_->OnBytes(socket, data, dataLen);
    EXPECT_TRUE(data != nullptr);
    SLOGI("OnBytes002 end");
}

/**
* @tc.name: Bind001
* @tc.desc: the size of peerNetworkId is zero
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, Bind001, TestSize.Level0)
{
    SLOGI("Bind001 begin");
    std::string peerNetworkId = "";
    std::string pkgName = "";
    int32_t ret = manager_->Bind(peerNetworkId, pkgName);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("Bind001 end");
}

/**
* @tc.name: Bind002
* @tc.desc: the size of peerNetworkId bigger than zero
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SoftbusSessionManagerTest, Bind002, TestSize.Level0)
{
    SLOGI("Bind002 begin");
    std::string peerNetworkId = "0.0.0.0";
    std::string pkgName = "test";
    int32_t ret = manager_->Bind(peerNetworkId, pkgName);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("Bind002 end");
}

static HWTEST_F(SoftbusSessionManagerTest, SendBytesForNext001, TestSize.Level0)
{
    SLOGI("SendBytesForNext001 begin");
    int32_t sessionid = -1;
    std::string data = "123";
    int32_t ret = manager_->SendBytesForNext(sessionid, data);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SendBytesForNext001 end");
}

static HWTEST_F(SoftbusSessionManagerTest, SendBytesForNext002, TestSize.Level0)
{
    SLOGI("SendBytesForNext002 begin");
    int32_t sessionid = 100;
    std::string data = "";
    int32_t ret = manager_->SendBytesForNext(sessionid, data);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SendBytesForNext002 end");
}

static HWTEST_F(SoftbusSessionManagerTest, SendBytesForNext003, TestSize.Level0)
{
    SLOGI("SendBytesForNext003 begin");
    int32_t sessionid = -1;
    std::string data = "";
    int32_t ret = manager_->SendBytesForNext(sessionid, data);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SendBytesForNext003 end");
}
#endif