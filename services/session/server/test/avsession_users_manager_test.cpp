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
#include "avsession_service.h"
#include "avsession_utils.h"
#include "file_ex.h"
#include "isession_listener.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

namespace OHOS {
namespace AVSession {

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
    ErrCode OnSessionCreate(const AVSessionDescriptor& descriptor) override{ return AVSESSION_SUCCESS; };
    ErrCode OnSessionRelease(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; };
    ErrCode OnTopSessionChange(const AVSessionDescriptor& descriptor) override { return AVSESSION_SUCCESS; };
    ErrCode OnAudioSessionChecked(const int32_t uid) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceLogEvent(
        const int32_t eventId, const int64_t param) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceOffline(const std::string& deviceId) override { return AVSESSION_SUCCESS; };
    ErrCode OnDeviceStateChange(const DeviceState& deviceState) override { return AVSESSION_SUCCESS; };
    ErrCode OnSystemCommonEvent(
        const std::string& commonEvent, const std::string& args) override { return AVSESSION_SUCCESS; };
    ErrCode OnRemoteDistributedSessionChange(
        const std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers) override { return AVSESSION_SUCCESS; };
    ErrCode OnActiveSessionChanged(
        const std::vector<AVSessionDescriptor> &descriptors) override { return AVSESSION_SUCCESS; };
    OHOS::sptr<IRemoteObject> AsObject() override { return nullptr; };
};

HWTEST_F(AVSessionUsersManagerTest, HandleUserRemoved001, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    manager.HandleUserRemoved(userId);
    EXPECT_TRUE(manager.sessionStackMapByUserId_.size() == 0);
}

HWTEST_F(AVSessionUsersManagerTest, HandleUserRemoved002, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    std::shared_ptr<SessionStack> stack = std::make_shared<SessionStack>();
    manager.sessionStackMapByUserId_.insert({userId, stack});
    manager.HandleUserRemoved(userId);
    EXPECT_TRUE(manager.sessionStackMapByUserId_.size() == 0);
}

HWTEST_F(AVSessionUsersManagerTest, HandleUserRemoved003, TestSize.Level0)
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

HWTEST_F(AVSessionUsersManagerTest, AddSessionListener001, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid = 0;
    OHOS::sptr<ISessionListener> listener = new ISessionListenerMock();
    manager.sessionListenersMapByUserId_.clear();
    manager.AddSessionListener(pid, listener);
    auto iterForListenerMap = manager.sessionListenersMapByUserId_.find(manager.curUserId_);
    EXPECT_TRUE(iterForListenerMap != manager.sessionListenersMapByUserId_.end());
}

HWTEST_F(AVSessionUsersManagerTest, RemoveSessionListener001, TestSize.Level0)
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

HWTEST_F(AVSessionUsersManagerTest, GetContainerFromUser001, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 0;
    manager.sessionStackMapByUserId_.insert({userId, nullptr});
    manager.GetContainerFromUser(userId);
    auto iter = manager.sessionStackMapByUserId_.find(userId);
    EXPECT_TRUE(iter != manager.sessionStackMapByUserId_.end());
}

HWTEST_F(AVSessionUsersManagerTest, GetDirForCurrentUser001, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    manager.curUserId_ = -1;
    int32_t userId = 0;
    std::string ret = manager.GetDirForCurrentUser(userId);
    EXPECT_TRUE(ret == "/data/service/el2/public/av_session/");
}

HWTEST_F(AVSessionUsersManagerTest, Init001, TestSize.Level0)
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

HWTEST_F(AVSessionUsersManagerTest, Init002, TestSize.Level0)
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

HWTEST_F(AVSessionUsersManagerTest, Init003, TestSize.Level0)
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

HWTEST_F(AVSessionUsersManagerTest, Init004, TestSize.Level0)
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

HWTEST_F(AVSessionUsersManagerTest, GetCurSessionListForKeyEvent001, TestSize.Level0)
{
    int32_t userId = 1;
    AVSessionUsersManager::GetInstance().GetCurSessionListForKeyEvent(userId);
    EXPECT_EQ(AVSessionUsersManager::GetInstance().curUserId_, userId);
}

/**
 * @tc.name: CleanupCacheOnUnlock_001
 * @tc.desc: delete stale files, keep alive session local/cast image files
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CleanupCacheOnUnlock_001, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession.cleanup");
    elementName.SetAbilityName("test.ability.cleanup");
    AVSessionService* avSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService != nullptr);
    OHOS::sptr<AVSessionItem> item =
        avSessionService->CreateSessionInner("cleanup", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);
    item->SetPid(getpid());
    item->SetUid(manager.GetCurrentUserId());
    std::string sessionId = item->GetDescriptor().sessionId_;
    int32_t userId = item->GetUserId();
    if (userId <= 0) {
        userId = manager.GetCurrentUserId();
    }

    std::shared_ptr<SessionStack> stack = std::make_shared<SessionStack>();
    stack->AddSession(getpid(), elementName.GetAbilityName(), item);
    manager.sessionStackMapByUserId_[userId] = stack;

    std::string cacheDir = AVSessionUtils::GetCachePathName(userId);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(cacheDir));
    std::string keepLocal = cacheDir + sessionId + AVSessionUtils::GetFileSuffix();
    std::string keepCast = cacheDir + "cast_" + sessionId + AVSessionUtils::GetFileSuffix();
    std::string stale = cacheDir + "stalefile123456.image.dat";
    ASSERT_TRUE(OHOS::SaveStringToFile(keepLocal, "keep"));
    ASSERT_TRUE(OHOS::SaveStringToFile(keepCast, "keep"));
    ASSERT_TRUE(OHOS::SaveStringToFile(stale, "stale"));

    manager.CleanupCacheOnUnlock(userId);

    EXPECT_TRUE(OHOS::FileExists(keepLocal));
    EXPECT_TRUE(OHOS::FileExists(keepCast));
    EXPECT_FALSE(OHOS::FileExists(stale));

    AVSessionUtils::DeleteFile(keepLocal);
    AVSessionUtils::DeleteFile(keepCast);
    EXPECT_FALSE(OHOS::FileExists(keepLocal));
    EXPECT_FALSE(OHOS::FileExists(keepCast));
    avSessionService->HandleSessionRelease(sessionId);
    manager.sessionStackMapByUserId_.erase(userId);
    delete avSessionService;
}

/**
 * @tc.name: CleanupCacheOnUnlock_002
 * @tc.desc: user absent from session map -> no alive session, all cache files deleted
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CleanupCacheOnUnlock_002, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 1357; // a user with no entry in sessionStackMapByUserId_
    manager.sessionStackMapByUserId_.erase(userId);

    std::string cacheDir = AVSessionUtils::GetCachePathName(userId);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(cacheDir));
    std::string stale = cacheDir + "stalenosession123.image.dat";
    ASSERT_TRUE(OHOS::SaveStringToFile(stale, "stale"));

    manager.CleanupCacheOnUnlock(userId);

    EXPECT_FALSE(OHOS::FileExists(stale));
    EXPECT_TRUE(OHOS::ForceRemoveDirectory(cacheDir));
    SLOGI("CleanupCacheOnUnlock_002 end!");
}

/**
 * @tc.name: CleanupCacheOnUnlock_003
 * @tc.desc: user present but stack is nullptr -> treated as no alive session
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CleanupCacheOnUnlock_003, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 2468;
    // present in map but with a null session stack
    manager.sessionStackMapByUserId_[userId] = nullptr;

    std::string cacheDir = AVSessionUtils::GetCachePathName(userId);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(cacheDir));
    std::string stale = cacheDir + "stalenullstack123.image.dat";
    ASSERT_TRUE(OHOS::SaveStringToFile(stale, "stale"));

    manager.CleanupCacheOnUnlock(userId);

    EXPECT_FALSE(OHOS::FileExists(stale));
    EXPECT_TRUE(OHOS::ForceRemoveDirectory(cacheDir));
    manager.sessionStackMapByUserId_.erase(userId);
    SLOGI("CleanupCacheOnUnlock_003 end!");
}

/**
 * @tc.name: CleanupCacheOnUnlock_004
 * @tc.desc: userId <= 0 resolves to current user
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CleanupCacheOnUnlock_004, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t curUserId = manager.curUserId_;
    std::string cacheDir = AVSessionUtils::GetCachePathName(curUserId);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(cacheDir));
    std::string stale = cacheDir + "staleuserid0_12345.image.dat";
    ASSERT_TRUE(OHOS::SaveStringToFile(stale, "stale"));

    // userId <= 0 should fall back to curUserId_ and clean that user's cache
    manager.CleanupCacheOnUnlock(0);

    EXPECT_FALSE(OHOS::FileExists(stale));
    // restore parity: the cache dir is left clean, no stale residue
    EXPECT_TRUE(OHOS::ForceRemoveDirectory(cacheDir));
    SLOGI("CleanupCacheOnUnlock_004 end!");
}

/**
 * @tc.name: CleanupCacheOnUnlock_005
 * @tc.desc: a null session entry in the stack is skipped, its image file is not protected
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CleanupCacheOnUnlock_005, TestSize.Level0)
{
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 3579;
    std::shared_ptr<SessionStack> stack = std::make_shared<SessionStack>();
    // inject a null session directly into the stack list to exercise CHECK_AND_CONTINUE
    stack->stack_.push_back(OHOS::sptr<AVSessionItem>(nullptr));
    manager.sessionStackMapByUserId_[userId] = stack;

    std::string cacheDir = AVSessionUtils::GetCachePathName(userId);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(cacheDir));
    std::string stale = cacheDir + "stalenullsession123.image.dat";
    ASSERT_TRUE(OHOS::SaveStringToFile(stale, "stale"));

    // null session contributes no sessionId, so the file is treated as stale and deleted
    manager.CleanupCacheOnUnlock(userId);

    EXPECT_FALSE(OHOS::FileExists(stale));
    EXPECT_TRUE(OHOS::ForceRemoveDirectory(cacheDir));
    manager.sessionStackMapByUserId_.erase(userId);
    SLOGI("CleanupCacheOnUnlock_005 end!");
}
} //AVSession
} //OHOS