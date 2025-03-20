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
#include "avsession_errors.h"
#include "avsession_log.h"
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

/**
 * @tc.name: HandleUserRemoved001
 * @tc.desc: the sessionStackMapByUserId_ is empty
 * @tc.type: FUNC
 */
static HWTEST(AVSessionUsersManagerTest, HandleUserRemoved001, TestSize.Level1)
{
    SLOGD("HandleUserRemoved001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    manager.HandleUserRemoved(userId);
    EXPECT_TRUE(manager.sessionStackMapByUserId_.size() == 0);
}

/**
 * @tc.name: HandleUserRemoved002
 * @tc.desc: the sessionStackMapByUserId_ is not empty and other maps are empty
 * @tc.type: FUNC
 */
static HWTEST(AVSessionUsersManagerTest, HandleUserRemoved002, TestSize.Level1)
{
    SLOGD("HandleUserRemoved002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    std::shared_ptr<SessionStack> stack = std::make_shared<SessionStack>();
    manager.sessionStackMapByUserId_.insert({userId, stack});
    manager.HandleUserRemoved(userId);
    EXPECT_TRUE(manager.sessionStackMapByUserId_.size() == 0);
}

/**
 * @tc.name: HandleUserRemoved003
 * @tc.desc: the sessionStackMapByUserId_ and other maps are not empty
 * @tc.type: FUNC
 */
static HWTEST(AVSessionUsersManagerTest, HandleUserRemoved003, TestSize.Level1)
{
    SLOGD("HandleUserRemoved003 begin!");
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

/**
 * @tc.name: AddSessionListener001
 * @tc.desc: have no find id
 * @tc.type: FUNC
 */
static HWTEST(AVSessionUsersManagerTest, AddSessionListener001, TestSize.Level1)
{
    SLOGD("AddSessionListener001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid = 0;
    OHOS::sptr<ISessionListener> listener = new ISessionListenerMock();
    manager.sessionListenersMapByUserId_.clear();
    manager.AddSessionListener(pid, listener);
    auto iterForListenerMap = manager.sessionListenersMapByUserId_.find(manager.curUserId_);
    EXPECT_TRUE(iterForListenerMap != manager.sessionListenersMapByUserId_.end());
}

/**
 * @tc.name: RemoveSessionListener001
 * @tc.desc: find id and remove it
 * @tc.type: FUNC
 */
static HWTEST(AVSessionUsersManagerTest, RemoveSessionListener001, TestSize.Level1)
{
    SLOGD("RemoveSessionListener001 begin!");
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

/**
 * @tc.name: GetContainerFromUser001
 * @tc.desc: find the id
 * @tc.type: FUNC
 */
static HWTEST(AVSessionUsersManagerTest, GetContainerFromUser001, TestSize.Level1)
{
    SLOGD("GetContainerFromUser001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    manager.sessionStackMapByUserId_.insert({userId, nullptr});
    manager.GetContainerFromUser(userId);
    auto iter = manager.sessionStackMapByUserId_.find(userId);
    EXPECT_TRUE(iter != manager.sessionStackMapByUserId_.end());
}

/**
 * @tc.name: GetDirForCurrentUser001
 * @tc.desc: set the invalid id
 * @tc.type: FUNC
 */
static HWTEST(AVSessionUsersManagerTest, GetDirForCurrentUser001, TestSize.Level1)
{
    SLOGD("GetDirForCurrentUser001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    manager.curUserId_ = -1;
    int32_t userId = 0;
    std::string ret = manager.GetDirForCurrentUser(userId);
    EXPECT_TRUE(ret == "/data/service/el2/public/av_session/");
}