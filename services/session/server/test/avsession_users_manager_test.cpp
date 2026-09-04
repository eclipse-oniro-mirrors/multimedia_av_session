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

#ifdef CAR_FEATURE_ENABLE
#include "audio_zone_types.h"
#endif

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
    ErrCode OnSessionAddForAudioZone(int32_t userId, const AVSessionDescriptor &descriptor) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnSessionRemoveForAudioZone(int32_t userId, const AVSessionDescriptor &descriptor) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnTopSessionChangeForAudioZone(int32_t userId, const AVSessionDescriptor &descriptor) override
    {
        return AVSESSION_SUCCESS;
    };
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

/**
 * @tc.name: UpdateSessionForUserChange_001
 * @tc.desc: Test UpdateSessionForUserChange with nullptr item returns AVSESSION_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, UpdateSessionForUserChange_001, TestSize.Level0)
{
    SLOGI("UpdateSessionForUserChange_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t oldUserId = 100;
    int32_t newUserId = 101;
    sptr<AVSessionItem> item = nullptr;
    int32_t ret = manager.UpdateSessionForUserChange(oldUserId, newUserId, item);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("UpdateSessionForUserChange_001 end!");
}

/**
 * @tc.name: UpdateSessionForUserChange_002
 * @tc.desc: Test UpdateSessionForUserChange moves session from old user to new user successfully
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, UpdateSessionForUserChange_002, TestSize.Level0)
{
    SLOGI("UpdateSessionForUserChange_002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    AVSessionService* avSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.updateuserchange");
    elementName.SetAbilityName("test.ability.updateuserchange");
    OHOS::sptr<AVSessionItem> item =
        avSessionService->CreateSessionInner("updateUserChange", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);

    int32_t oldUserId = item->GetUserId();
    if (oldUserId <= 0) {
        oldUserId = manager.GetCurrentUserId();
    }
    int32_t newUserId = oldUserId + 1;

    int32_t ret = manager.UpdateSessionForUserChange(oldUserId, newUserId, item);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(item->GetUserId(), newUserId);

    avSessionService->HandleSessionRelease(item->GetSessionId());
    manager.sessionStackMapByUserId_.erase(oldUserId);
    manager.sessionStackMapByUserId_.erase(newUserId);
    SLOGI("UpdateSessionForUserChange_002 end!");
}

/**
 * @tc.name: UpdateSessionForUserChange_003
 * @tc.desc: Test UpdateSessionForUserChange with oldUserId equal to newUserId (no-op move)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, UpdateSessionForUserChange_003, TestSize.Level0)
{
    SLOGI("UpdateSessionForUserChange_003 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    AVSessionService* avSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.sameuser");
    elementName.SetAbilityName("test.ability.sameuser");
    OHOS::sptr<AVSessionItem> item =
        avSessionService->CreateSessionInner("sameUser", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);

    int32_t userId = item->GetUserId();
    if (userId <= 0) {
        userId = manager.GetCurrentUserId();
    }

    int32_t ret = manager.UpdateSessionForUserChange(userId, userId, item);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(item->GetUserId(), userId);

    avSessionService->HandleSessionRelease(item->GetSessionId());
    manager.sessionStackMapByUserId_.erase(userId);
    SLOGI("UpdateSessionForUserChange_003 end!");
}

#ifdef CAR_FEATURE_ENABLE
/**
 * @tc.name: AddSessionListenerForUser_001
 * @tc.desc: Test AddSessionListenerForUser with valid userId and listener
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, AddSessionListenerForUser_001, TestSize.Level0)
{
    SLOGI("AddSessionListenerForUser_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid = 1234;
    int32_t userId = 100;
    OHOS::sptr<ISessionListener> listener = new ISessionListenerMock();
    
    manager.AddSessionListenerForUser(pid, listener, userId);
    
    auto iter = manager.sessionListenersMapByUserIdForAudioZone_.find(userId);
    EXPECT_TRUE(iter != manager.sessionListenersMapByUserIdForAudioZone_.end());
    EXPECT_TRUE(iter->second.find(pid) != iter->second.end());
    SLOGI("AddSessionListenerForUser_001 end!");
}

/**
 * @tc.name: AddSessionListenerForUser_002
 * @tc.desc: Test AddSessionListenerForUser with nullptr listener
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, AddSessionListenerForUser_002, TestSize.Level0)
{
    SLOGI("AddSessionListenerForUser_002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid = 1235;
    int32_t userId = 101;
    
    manager.AddSessionListenerForUser(pid, nullptr, userId);
    
    auto iter = manager.sessionListenersMapByUserIdForAudioZone_.find(userId);
    EXPECT_TRUE(iter == manager.sessionListenersMapByUserIdForAudioZone_.end());
    SLOGI("AddSessionListenerForUser_002 end!");
}

/**
 * @tc.name: AddSessionListenerForUser_003
 * @tc.desc: Test AddSessionListenerForUser with userId <= 0
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, AddSessionListenerForUser_003, TestSize.Level0)
{
    SLOGI("AddSessionListenerForUser_003 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid = 1236;
    int32_t userId = 0;
    OHOS::sptr<ISessionListener> listener = new ISessionListenerMock();
    
    manager.AddSessionListenerForUser(pid, listener, userId);
    
    auto iter = manager.sessionListenersMapByUserIdForAudioZone_.find(userId);
    EXPECT_TRUE(iter == manager.sessionListenersMapByUserIdForAudioZone_.end());
    SLOGI("AddSessionListenerForUser_003 end!");
}

/**
 * @tc.name: AddSessionListenerForUser_004
 * @tc.desc: Test AddSessionListenerForUser updates existing userId
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, AddSessionListenerForUser_004, TestSize.Level0)
{
    SLOGI("AddSessionListenerForUser_004 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid = 1237;
    int32_t userId = 102;
    OHOS::sptr<ISessionListener> listener1 = new ISessionListenerMock();
    OHOS::sptr<ISessionListener> listener2 = new ISessionListenerMock();
    
    manager.AddSessionListenerForUser(pid, listener1, userId);
    manager.AddSessionListenerForUser(pid, listener2, userId);
    
    auto iter = manager.sessionListenersMapByUserIdForAudioZone_.find(userId);
    EXPECT_TRUE(iter != manager.sessionListenersMapByUserIdForAudioZone_.end());
    EXPECT_EQ(iter->second[pid], listener2);
    SLOGI("AddSessionListenerForUser_004 end!");
}

/**
 * @tc.name: AddSessionListenerForUser_005
 * @tc.desc: Test AddSessionListenerForUser with multiple pids same userId
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, AddSessionListenerForUser_005, TestSize.Level0)
{
    SLOGI("AddSessionListenerForUser_005 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    pid_t pid1 = 1238;
    pid_t pid2 = 1239;
    int32_t userId = 103;
    OHOS::sptr<ISessionListener> listener1 = new ISessionListenerMock();
    OHOS::sptr<ISessionListener> listener2 = new ISessionListenerMock();
    
    manager.AddSessionListenerForUser(pid1, listener1, userId);
    manager.AddSessionListenerForUser(pid2, listener2, userId);
    
    auto iter = manager.sessionListenersMapByUserIdForAudioZone_.find(userId);
    EXPECT_TRUE(iter != manager.sessionListenersMapByUserIdForAudioZone_.end());
    EXPECT_EQ(iter->second.size(), 2);
    SLOGI("AddSessionListenerForUser_005 end!");
}

/**
 * @tc.name: GetZoneIdForUser_001
 * @tc.desc: Test zoneToUserid_ mapping with valid zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, GetZoneIdForUser_001, TestSize.Level0)
{
    SLOGI("GetZoneIdForUser_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 100;
    int32_t zoneId = 1;
    
    manager.zoneToUserid_[zoneId].push_back(userId);
    
    auto iter = manager.zoneToUserid_.find(zoneId);
    EXPECT_TRUE(iter != manager.zoneToUserid_.end());
    EXPECT_TRUE(std::find(iter->second.begin(), iter->second.end(), userId) != iter->second.end());
    SLOGI("GetZoneIdForUser_001 end!");
}

/**
 * @tc.name: GetZoneIdForUser_002
 * @tc.desc: Test zoneToUserid_ with non-existent zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, GetZoneIdForUser_002, TestSize.Level0)
{
    SLOGI("GetZoneIdForUser_002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 999999;
    
    auto iter = manager.zoneToUserid_.find(zoneId);
    EXPECT_TRUE(iter == manager.zoneToUserid_.end());
    SLOGI("GetZoneIdForUser_002 end!");
}

/**
 * @tc.name: UpdateZoneToUseridMap_001
 * @tc.desc: Test UpdateZoneToUseridMap adds userId to zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, UpdateZoneToUseridMap_001, TestSize.Level0)
{
    SLOGI("UpdateZoneToUseridMap_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 100;
    int32_t zoneId = 1;
    
    manager.zoneToUserid_[zoneId].push_back(userId);
    
    auto iter = manager.zoneToUserid_.find(zoneId);
    EXPECT_TRUE(iter != manager.zoneToUserid_.end());
    EXPECT_TRUE(std::find(iter->second.begin(), iter->second.end(), userId) != iter->second.end());
    SLOGI("UpdateZoneToUseridMap_001 end!");
}

/**
 * @tc.name: CleanupZoneToUseridMap_001
 * @tc.desc: Test CleanupZoneToUseridMap removes userId from zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CleanupZoneToUseridMap_001, TestSize.Level0)
{
    SLOGI("CleanupZoneToUseridMap_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 100;
    int32_t zoneId = 1;
    
    manager.zoneToUserid_[zoneId].push_back(userId);
    manager.zoneToUserid_[zoneId].erase(
        std::remove(manager.zoneToUserid_[zoneId].begin(), manager.zoneToUserid_[zoneId].end(), userId),
        manager.zoneToUserid_[zoneId].end());
    if (manager.zoneToUserid_[zoneId].empty()) {
        manager.zoneToUserid_.erase(zoneId);
    }
    
    auto iter = manager.zoneToUserid_.find(zoneId);
    EXPECT_TRUE(iter == manager.zoneToUserid_.end() || iter->second.empty());
    SLOGI("CleanupZoneToUseridMap_001 end!");
}

/**
 * @tc.name: CleanupZoneToUseridMap_002
 * @tc.desc: Test CleanupZoneToUseridMap removes one userId from multi-user zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CleanupZoneToUseridMap_002, TestSize.Level0)
{
    SLOGI("CleanupZoneToUseridMap_002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId1 = 100;
    int32_t userId2 = 101;
    int32_t zoneId = 1;
    
    manager.zoneToUserid_[zoneId].push_back(userId1);
    manager.zoneToUserid_[zoneId].push_back(userId2);
    manager.zoneToUserid_[zoneId].erase(
        std::remove(manager.zoneToUserid_[zoneId].begin(), manager.zoneToUserid_[zoneId].end(), userId1),
        manager.zoneToUserid_[zoneId].end());
    
    auto iter = manager.zoneToUserid_.find(zoneId);
    EXPECT_TRUE(iter != manager.zoneToUserid_.end());
    EXPECT_EQ(iter->second.size(), 1);
    EXPECT_TRUE(std::find(iter->second.begin(), iter->second.end(), userId2) != iter->second.end());
    SLOGI("CleanupZoneToUseridMap_002 end!");
}

/**
 * @tc.name: GetUsersInSameAudioZone_001
 * @tc.desc: Test GetUsersInSameAudioZone returns users in same zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, GetUsersInSameAudioZone_001, TestSize.Level0)
{
    SLOGI("GetUsersInSameAudioZone_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId1 = 101;
    int32_t userId2 = 102;
    int32_t zoneId = 2;
    
    manager.zoneToUserid_[zoneId].push_back(userId1);
    manager.zoneToUserid_[zoneId].push_back(userId2);
    
    auto iter = manager.zoneToUserid_.find(zoneId);
    EXPECT_TRUE(iter != manager.zoneToUserid_.end());
    EXPECT_TRUE(std::find(iter->second.begin(), iter->second.end(), userId1) != iter->second.end());
    EXPECT_TRUE(std::find(iter->second.begin(), iter->second.end(), userId2) != iter->second.end());
    SLOGI("GetUsersInSameAudioZone_001 end!");
}

/**
 * @tc.name: GetUsersInSameAudioZone_002
 * @tc.desc: Test GetUsersInSameAudioZone with invalid zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, GetUsersInSameAudioZone_002, TestSize.Level0)
{
    SLOGI("GetUsersInSameAudioZone_002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 999999;
    
    auto iter = manager.zoneToUserid_.find(zoneId);
    EXPECT_TRUE(iter == manager.zoneToUserid_.end());
    SLOGI("GetUsersInSameAudioZone_002 end!");
}

/**
 * @tc.name: UpdateSessionStackForAudioZone_001
 * @tc.desc: Test UpdateSessionStackForAudioZone with valid userId
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, UpdateSessionStackForAudioZone_001, TestSize.Level0)
{
    SLOGI("UpdateSessionStackForAudioZone_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 1;
    
    manager.sessionStackMapForAudioZone_[zoneId] = std::vector<AVSessionDescriptor>();
    
    auto iter = manager.sessionStackMapForAudioZone_.find(zoneId);
    EXPECT_TRUE(iter != manager.sessionStackMapForAudioZone_.end());
    SLOGI("UpdateSessionStackForAudioZone_001 end!");
}

/**
 * @tc.name: UpdateSessionStackForAudioZone_002
 * @tc.desc: Test UpdateSessionStackForAudioZone updates existing zone stack
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, UpdateSessionStackForAudioZone_002, TestSize.Level0)
{
    SLOGI("UpdateSessionStackForAudioZone_002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 1;
    AVSessionDescriptor desc1;
    desc1.sessionId_ = "session1";
    AVSessionDescriptor desc2;
    desc2.sessionId_ = "session2";
    
    manager.sessionStackMapForAudioZone_[zoneId] = {desc1};
    manager.sessionStackMapForAudioZone_[zoneId] = {desc1, desc2};
    
    auto iter = manager.sessionStackMapForAudioZone_.find(zoneId);
    EXPECT_TRUE(iter != manager.sessionStackMapForAudioZone_.end());
    EXPECT_EQ(iter->second.size(), 2);
    EXPECT_EQ(iter->second[0].sessionId_, "session1");
    EXPECT_EQ(iter->second[1].sessionId_, "session2");
    SLOGI("UpdateSessionStackForAudioZone_002 end!");
}

/**
 * @tc.name: GetSessionStackForAudioZone_001
 * @tc.desc: Test GetSessionStackForAudioZone returns cached descriptors
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, GetSessionStackForAudioZone_001, TestSize.Level0)
{
    SLOGI("GetSessionStackForAudioZone_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 1;
    
    manager.sessionStackMapForAudioZone_[zoneId] = std::vector<AVSessionDescriptor>();
    
    auto iter = manager.sessionStackMapForAudioZone_.find(zoneId);
    EXPECT_TRUE(iter != manager.sessionStackMapForAudioZone_.end());
    SLOGI("GetSessionStackForAudioZone_001 end!");
}

/**
 * @tc.name: GetSessionStackForAudioZone_002
 * @tc.desc: Test GetSessionStackForAudioZone with non-existent zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, GetSessionStackForAudioZone_002, TestSize.Level0)
{
    SLOGI("GetSessionStackForAudioZone_002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 999999;
    
    auto iter = manager.sessionStackMapForAudioZone_.find(zoneId);
    EXPECT_TRUE(iter == manager.sessionStackMapForAudioZone_.end());
    SLOGI("GetSessionStackForAudioZone_002 end!");
}

/**
 * @tc.name: GetZoneIdForUser_003
 * @tc.desc: Test GetZoneIdForUser when AudioZoneManager is not available
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, GetZoneIdForUser_003, TestSize.Level0)
{
    SLOGI("GetZoneIdForUser_003 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t userId = 999999;
    int32_t zoneId = manager.GetZoneIdForUser(userId);
    EXPECT_EQ(zoneId, ERR_AUDIO_ZONE_NOT_FOUND);
    SLOGI("GetZoneIdForUser_003 end!");
}

/**
 * @tc.name: CollectLocalSessionsForAudioZone_002
 * @tc.desc: Test CollectLocalSessionsForAudioZone with non-existent zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CollectLocalSessionsForAudioZone_002, TestSize.Level0)
{
    SLOGI("CollectLocalSessionsForAudioZone_002 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 999999;
    std::vector<std::pair<AVSessionDescriptor, int64_t>> sessionWithTime;
    manager.CollectLocalSessionsForAudioZone(zoneId, sessionWithTime);
    EXPECT_TRUE(sessionWithTime.empty());
    SLOGI("CollectLocalSessionsForAudioZone_002 end!");
}

/**
 * @tc.name: CollectDistributedSessionsForAudioZone_001
 * @tc.desc: Test CollectDistributedSessionsForAudioZone with non-existent zone
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, CollectDistributedSessionsForAudioZone_001, TestSize.Level0)
{
    SLOGI("CollectDistributedSessionsForAudioZone_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 999999;
    std::vector<std::pair<AVSessionDescriptor, int64_t>> sessionWithTime;
    manager.CollectDistributedSessionsForAudioZone(zoneId, sessionWithTime);
    EXPECT_TRUE(sessionWithTime.empty());
    SLOGI("CollectDistributedSessionsForAudioZone_001 end!");
}

/**
 * @tc.name: SortAndCacheSessionStack_001
 * @tc.desc: Test SortAndCacheSessionStack sorts and caches descriptors
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, SortAndCacheSessionStack_001, TestSize.Level0)
{
    SLOGI("SortAndCacheSessionStack_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    int32_t zoneId = 1;
    std::vector<std::pair<AVSessionDescriptor, int64_t>> sessionWithTime;
    
    AVSessionDescriptor desc1;
    desc1.sessionId_ = "session1";
    AVSessionDescriptor desc2;
    desc2.sessionId_ = "session2";
    
    sessionWithTime.push_back({desc1, 100});
    sessionWithTime.push_back({desc2, 200});
    
    manager.SortAndCacheSessionStack(zoneId, sessionWithTime);
    
    auto iter = manager.sessionStackMapForAudioZone_.find(zoneId);
    EXPECT_TRUE(iter != manager.sessionStackMapForAudioZone_.end());
    EXPECT_EQ(iter->second.size(), 2);
    EXPECT_EQ(iter->second[0].sessionId_, "session2");
    EXPECT_EQ(iter->second[1].sessionId_, "session1");
    SLOGI("SortAndCacheSessionStack_001 end!");
}

/**
 * @tc.name: IsCastSessionValid_001
 * @tc.desc: Test IsCastSessionValid with nullptr session
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUsersManagerTest, IsCastSessionValid_001, TestSize.Level0)
{
    SLOGI("IsCastSessionValid_001 begin!");
    auto& manager = AVSessionUsersManager::GetInstance();
    sptr<AVSessionItem> session = nullptr;
    int32_t zoneId = 1;
    bool result = manager.IsCastSessionValid(session, zoneId);
    EXPECT_FALSE(result);
    SLOGI("IsCastSessionValid_001 end!");
}
#endif
} //AVSession
} //OHOS