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
#include "session_listener_client.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class SessionListenerClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void SessionListenerClientTest::SetUpTestCase()
{}

void SessionListenerClientTest::TearDownTestCase()
{}

void SessionListenerClientTest::SetUp()
{}

void SessionListenerClientTest::TearDown()
{}

class AVSessionListenerDemo : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override {}
    void OnSessionRelease(const AVSessionDescriptor& descriptor) override {}
    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override {}
    void OnAudioSessionChecked(const int32_t uid) override {}
    void OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override {}
    void OnDeviceOffline(const std::string& deviceId) override {}
    void OnRemoteDistributedSessionChange(
        const std::vector<sptr<IRemoteObject>>& sessionControllers) override {}
    void OnDeviceStateChange(const DeviceState& deviceState) override {}
    ~AVSessionListenerDemo() override {}
};

/**
* @tc.name: OnSessionCreate001
* @tc.desc: test OnSessionCreate
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnSessionCreate001, TestSize.Level1)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    AVSessionDescriptor descriptor;
    sessionListenerClient->OnSessionCreate(descriptor);
}

/**
* @tc.name: OnSessionCreate002
* @tc.desc: test OnSessionCreate
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnSessionCreate002, TestSize.Level1)
{
    std::shared_ptr<AVSessionListenerDemo> listener = nullptr;
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    AVSessionDescriptor descriptor;
    sessionListenerClient->OnSessionCreate(descriptor);
}

/**
* @tc.name: OnSessionRelease001
* @tc.desc: test OnSessionRelease
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnSessionRelease001, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    AVSessionDescriptor descriptor;
    sessionListenerClient->OnSessionRelease(descriptor);
}

/**
* @tc.name: OnSessionRelease002
* @tc.desc: test OnSessionRelease
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnSessionRelease002, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = nullptr;
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    AVSessionDescriptor descriptor;
    sessionListenerClient->OnSessionRelease(descriptor);
}

/**
* @tc.name: OnTopSessionChange001
* @tc.desc: test OnTopSessionChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnTopSessionChange001, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    AVSessionDescriptor descriptor;
    sessionListenerClient->OnTopSessionChange(descriptor);
}

/**
* @tc.name: OnTopSessionChange002
* @tc.desc: test OnTopSessionChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnTopSessionChange002, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = nullptr;
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    AVSessionDescriptor descriptor;
    sessionListenerClient->OnTopSessionChange(descriptor);
}

/**
* @tc.name: OnAudioSessionChecked001
* @tc.desc: test OnAudioSessionChecked
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnAudioSessionChecked001, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    sessionListenerClient->OnAudioSessionChecked(0);
}

/**
* @tc.name: OnAudioSessionChecked002
* @tc.desc: test OnAudioSessionChecked
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnAudioSessionChecked002, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = nullptr;
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    sessionListenerClient->OnAudioSessionChecked(0);
}

/**
* @tc.name: OnDeviceAvailable001
* @tc.desc: test OnDeviceAvailable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceAvailable001, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    OutputDeviceInfo castOutputDeviceInfo;
    sessionListenerClient->OnDeviceAvailable(castOutputDeviceInfo);
}

/**
* @tc.name: OnDeviceLogEvent001
* @tc.desc: test OnDeviceLogEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceLogEvent001, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = nullptr;
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    int32_t eventId = 1;
    int64_t param = 2;
    sessionListenerClient->OnDeviceLogEvent(eventId, param);
}

/**
* @tc.name: OnDeviceLogEvent002
* @tc.desc: test OnDeviceLogEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceLogEvent002, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    int32_t eventId = 1;
    int64_t param = 2;
    sessionListenerClient->OnDeviceLogEvent(eventId, param);
}

/**
* @tc.name: OnDeviceLogEvent003
* @tc.desc: test OnDeviceLogEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceLogEvent003, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    int32_t eventId = 0;
    int64_t param = 2;
    sessionListenerClient->OnDeviceLogEvent(eventId, param);
}

/**
* @tc.name: OnDeviceAvailable002
* @tc.desc: test OnDeviceAvailable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceAvailable002, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = nullptr;
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    OutputDeviceInfo castOutputDeviceInfo;
    sessionListenerClient->OnDeviceAvailable(castOutputDeviceInfo);
}

/**
* @tc.name: OnDeviceOffline001
* @tc.desc: test OnDeviceOffline
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceOffline001, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    std::string deviceId = "deviceId";
    sessionListenerClient->OnDeviceOffline(deviceId);
}

/**
* @tc.name: OnDeviceOffline002
* @tc.desc: test OnDeviceOffline
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceOffline002, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = nullptr;
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    std::string deviceId = "deviceId";
    sessionListenerClient->OnDeviceOffline(deviceId);
}

/**
* @tc.name: OnRemoteDistributedSessionChange001
* @tc.desc: test OnRemoteDistributedSessionChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnRemoteDistributedSessionChange001, TestSize.Level1)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    std::vector<sptr<IRemoteObject>> sessionControllers;
    sessionListenerClient->OnRemoteDistributedSessionChange(sessionControllers);
}

/**
* @tc.name: OnDeviceStateChange001
* @tc.desc: test OnDeviceStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceStateChange001, TestSize.Level0)
{
    std::shared_ptr<AVSessionListenerDemo> listener = std::make_shared<AVSessionListenerDemo>();
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    DeviceState deviceState;
    sessionListenerClient->OnDeviceStateChange(deviceState);
}

/**
* @tc.name: OnDeviceStateChange002
* @tc.desc: test OnDeviceStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SessionListenerClientTest, OnDeviceStateChange002, TestSize.Level1)
{
    std::shared_ptr<AVSessionListenerDemo> listener = nullptr;
    std::shared_ptr<SessionListenerClient> sessionListenerClient = std::make_shared<SessionListenerClient>(listener);
    EXPECT_NE(sessionListenerClient, nullptr);
    DeviceState deviceState;
    sessionListenerClient->OnDeviceStateChange(deviceState);
}
} // namespace AVSESSION
} // namespace OHOS