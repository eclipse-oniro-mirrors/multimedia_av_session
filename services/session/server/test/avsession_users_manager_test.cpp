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

#include "account_manager_adapter.h"
#include "avsession_users_manager.h"
#include "isession_listener.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class AVSessionUsersManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionUsersManagerTest::SetUpTestCase() {}

void AVSessionUsersManagerTest::TearDownTestCase() {}

void AVSessionUsersManagerTest::SetUp() {}

void AVSessionUsersManagerTest::TearDown() {}

class ISessionListenerMock : public ISessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override {};
    void OnSessionRelease(const AVSessionDescriptor& descriptor) override {};
    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override {};
    void OnAudioSessionChecked(const int32_t uid) override {};
    void OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override {};
    void OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) override {};
    void OnDeviceOffline(const std::string& deviceId) override {};
    void OnRemoteDistributedSessionChange(
        const std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers) override {};
    OHOS::sptr<IRemoteObject> AsObject() override { return nullptr; };
};

HWTEST_F(AVSessionUsersManagerTest, HandleUserRemoved001, TestSize.Level1)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    manager.HandleUserRemoved(userId);
    EXPECT_TRUE(manager.sessionStackMapByUserId_.size() == 0);
}

HWTEST_F(AVSessionUsersManagerTest, HandleUserRemoved002, TestSize.Level1)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    std::shared_ptr<SessionStack> stack = std::make_shared<SessionStack>();
    manager.sessionStackMapByUserId_.insert({userId, stack});
    manager.HandleUserRemoved(userId);
    EXPECT_TRUE(manager.sessionStackMapByUserId_.size() == 0);
}

HWTEST_F(AVSessionUsersManagerTest, HandleUserRemoved003, TestSize.Level1)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    std::shared_ptr<SessionStack> stack = std::make_shared<SessionStack>();
    manager.sessionStackMapByUserId_.insert({userId, stack});
    manager.frontSessionListMapByUserId_.insert({userId, std::make_shared<std::list<OHOS::sptr<AVSessionItem>>>()});
    manager.sessionListenersMapByUserId_.insert({userId, std::map<pid_t, OHOS::sptr<ISessionListener>>()});
    manager.topSessionsMapByUserId_.insert({userId, OHOS::sptr<AVSessionItem>(nullptr)});
    manager.HandleUserRemoved(userId);
    EXPECT_TRUE(manager.sessionStackMapByUserId_.size() == 0);
}

HWTEST_F(AVSessionUsersManagerTest, AddSessionListener001, TestSize.Level1)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid = 0;
    OHOS::sptr<ISessionListener> listener = new ISessionListenerMock();
    manager.sessionListenersMapByUserId_.clear();
    manager.AddSessionListener(pid, listener);
    auto iterForListenerMap = manager.sessionListenersMapByUserId_.find(manager.curUserId_);
    EXPECT_TRUE(iterForListenerMap != manager.sessionListenersMapByUserId_.end());
}

HWTEST_F(AVSessionUsersManagerTest, RemoveSessionListener001, TestSize.Level1)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid = 0;
    OHOS::sptr<ISessionListener> listener = new ISessionListenerMock();
    std::map<pid_t, OHOS::sptr<ISessionListener>> listenerMap;
    listenerMap.insert({pid, listener});
    int32_t userId = 0;
    manager.sessionListenersMapByUserId_.insert({userId, listenerMap});
    manager.sessionListenersMap_[pid] = listener;
    manager.RemoveSessionListener(pid);
    EXPECT_TRUE(manager.sessionListenersMapByUserId_.size() > 0);
}

HWTEST_F(AVSessionUsersManagerTest, GetContainerFromUser001, TestSize.Level1)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    manager.sessionStackMapByUserId_.insert({userId, nullptr});
    manager.GetContainerFromUser(userId);
    auto iter = manager.sessionStackMapByUserId_.find(userId);
    EXPECT_TRUE(iter != manager.sessionStackMapByUserId_.end());
}

HWTEST_F(AVSessionUsersManagerTest, GetDirForCurrentUser001, TestSize.Level1)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    manager.curUserId_ = -1;
    int32_t userId = 0;
    std::string ret = manager.GetDirForCurrentUser(userId);
    EXPECT_TRUE(ret == "/data/service/el2/public/av_session/");
}

HWTEST_F(AVSessionUsersManagerTest, Init001, TestSize.Level1)
{
    int32_t userId = 1;
    AVSessionUsersManager::GetInstance().Init();
    for (const auto& listener : AccountManagerAdapter::GetInstance().accountEventsListenerList_) {
        if (listener) {
            listener(AccountManagerAdapter::accountEventSwitched, userId);
        }
    }
    EXPECT_EQ(AVSessionUsersManager::GetInstance().curUserId_, userId);
}

HWTEST_F(AVSessionUsersManagerTest, Init002, TestSize.Level1)
{
    int32_t userId = 1;
    int32_t newUserId = 100;
    AVSessionUsersManager::GetInstance().Init();
    for (const auto& listener : AccountManagerAdapter::GetInstance().accountEventsListenerList_) {
        if (listener) {
            listener(AccountManagerAdapter::accountEventRemoved, userId);
        }
    }
    EXPECT_EQ(AVSessionUsersManager::GetInstance().curUserId_, newUserId);
}

HWTEST_F(AVSessionUsersManagerTest, Init003, TestSize.Level1)
{
    int32_t userId = 100;
    AVSessionUsersManager::GetInstance().Init();
    for (const auto& listener : AccountManagerAdapter::GetInstance().accountEventsListenerList_) {
        if (listener) {
            listener("other", 1);
        }
    }
    EXPECT_EQ(AVSessionUsersManager::GetInstance().curUserId_, userId);
}

HWTEST_F(AVSessionUsersManagerTest, Init004, TestSize.Level1)
{
    int32_t userId = 1;
    AVSessionUsersManager::GetInstance().Init();
    AVSessionUsersManager::GetInstance().aliveUsers_.push_back(userId);
    for (const auto& listener : AccountManagerAdapter::GetInstance().accountEventsListenerList_) {
        if (listener) {
            listener(AccountManagerAdapter::accountEventSwitched, userId);
        }
    }
    EXPECT_EQ(AVSessionUsersManager::GetInstance().curUserId_, userId);
}

HWTEST_F(AVSessionUsersManagerTest, GetCurSessionListForKeyEvent001, TestSize.Level1)
{
    int32_t userId = 1;
    AVSessionUsersManager::GetInstance().GetCurSessionListForKeyEvent(userId);
    EXPECT_EQ(AVSessionUsersManager::GetInstance().curUserId_, userId);
}
