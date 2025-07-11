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
#include "session_listener_proxy.h"

using namespace OHOS::AVSession;

static std::string g_errLog;

static void MyLogCallback(const LogType type, const LogLevel level,
    const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}

class SessionListenerProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<SessionListenerProxy> sessionListenerProxy;
};

void SessionListenerProxyTest::SetUpTestCase()
{
}

void SessionListenerProxyTest::TearDownTestCase()
{
}

void SessionListenerProxyTest::SetUp()
{
    OHOS::sptr<IRemoteObject> iRemoteObject;
    sessionListenerProxy = std::make_shared<SessionListenerProxy>(iRemoteObject);
}

void SessionListenerProxyTest::TearDown()
{
}

/**
 * @tc.name: OnSessionCreate001
 * @tc.desc: Test OnSessionCreate
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerProxyTest, OnSessionCreate001, testing::ext::TestSize.Level0)
{
    SLOGI("OnSessionCreate001, start");
    LOG_SetCallback(MyLogCallback);
    AVSessionDescriptor descriptor;
    sessionListenerProxy->OnSessionCreate(descriptor);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("OnSessionCreate001, end");
}

/**
 * @tc.name: OnSessionRelease001
 * @tc.desc: Test OnSessionRelease
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerProxyTest, OnSessionRelease001, testing::ext::TestSize.Level0)
{
    SLOGI("OnSessionRelease001, start");
    LOG_SetCallback(MyLogCallback);
    AVSessionDescriptor descriptor;
    sessionListenerProxy->OnSessionRelease(descriptor);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("OnSessionRelease001, end");
}

/**
 * @tc.name: OnTopSessionChange001
 * @tc.desc: Test OnTopSessionChange
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerProxyTest, OnTopSessionChange001, testing::ext::TestSize.Level0)
{
    SLOGI("OnTopSessionChange001, start");
    LOG_SetCallback(MyLogCallback);
    AVSessionDescriptor descriptor;
    sessionListenerProxy->OnTopSessionChange(descriptor);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("OnTopSessionChange001, end");
}

/**
 * @tc.name: OnAudioSessionChecked001
 * @tc.desc: Test OnAudioSessionChecked
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerProxyTest, OnAudioSessionChecked001, testing::ext::TestSize.Level0)
{
    SLOGI("OnAudioSessionChecked001, start");
    LOG_SetCallback(MyLogCallback);
    int32_t uid = 0;
    sessionListenerProxy->OnAudioSessionChecked(uid);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("OnAudioSessionChecked001, end");
}

/**
 * @tc.name: OnDeviceAvailable001
 * @tc.desc: Test OnDeviceAvailable
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerProxyTest, OnDeviceAvailable001, testing::ext::TestSize.Level0)
{
    SLOGI("OnDeviceAvailable001, start");
    LOG_SetCallback(MyLogCallback);
    OutputDeviceInfo castOutputDeviceInfo;
    sessionListenerProxy->OnDeviceAvailable(castOutputDeviceInfo);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("OnDeviceAvailable001, end");
}

/**
 * @tc.name: OnDeviceOffline001
 * @tc.desc: Test OnDeviceOffline
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerProxyTest, OnDeviceOffline001, testing::ext::TestSize.Level0)
{
    SLOGI("OnDeviceOffline001, start");
    LOG_SetCallback(MyLogCallback);
    std::string deviceId = "deviceId";
    sessionListenerProxy->OnDeviceOffline(deviceId);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("OnDeviceOffline001, end");
}

/**
* @tc.name: OnDeviceStateChange001
* @tc.desc: test OnDeviceStateChange
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(SessionListenerProxyTest, OnDeviceStateChange001, testing::ext::TestSize.Level0)
{
    SLOGI("OnDeviceStateChange001, start");
    LOG_SetCallback(MyLogCallback);
    DeviceState deviceState;
    sessionListenerProxy->OnDeviceStateChange(deviceState);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("OnDeviceStateChange001, end");
}

/**
 * @tc.name: OnRemoteDistributedSessionChange001
 * @tc.desc: Test OnRemoteDistributedSessionChange
 * @tc.type: FUNC
 */
static HWTEST_F(SessionListenerProxyTest, OnRemoteDistributedSessionChange001, testing::ext::TestSize.Level0)
{
    SLOGI("OnRemoteDistributedSessionChange001, start");
    LOG_SetCallback(MyLogCallback);
    std::vector<OHOS::sptr<IRemoteObject>> sessionControllers;
    sessionListenerProxy->OnRemoteDistributedSessionChange(sessionControllers);
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("OnRemoteDistributedSessionChange001, end");
}
