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

#include "avsession_users_manager.h"
#include "account_manager_adapter.h"
#include "avsession_utils.h"

namespace OHOS::AVSession {
AVSessionUsersManager& AVSessionUsersManager::GetInstance()
{
    static AVSessionUsersManager usersManager;
    return usersManager;
}

void AVSessionUsersManager::Init()
{
    std::lock_guard lockGuard(userLock_);
    AccountManagerAdapter::GetInstance().Init();
    AccountManagerAdapter::GetInstance().AddAccountEventsListener([this] (const std::string &type, const int &userId) {
        SLOGI("get event for %{public}d with type %{public}s, curUser: %{public}d", userId, type.c_str(), curUserId_);
        if (type == AccountManagerAdapter::accountEventSwitched) {
            curUserId_ = userId;
            auto it = std::find(aliveUsers_.begin(), aliveUsers_.end(), curUserId_);
            if (it == aliveUsers_.end()) {
                aliveUsers_.push_back(curUserId_);
            }
        } else if (type == AccountManagerAdapter::accountEventRemoved) {
            HandleUserRemoved(userId);
        }
    });
    curUserId_ = AccountManagerAdapter::GetInstance().GetCurrentAccountUserId();
    aliveUsers_.push_back(curUserId_);
}

void AVSessionUsersManager::HandleUserRemoved(int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    SLOGI("HandleUserRemoved for user %{public}d", userId);
    auto iterForStack = sessionStackMapByUserId_.find(userId);
    if (iterForStack != sessionStackMapByUserId_.end()) {
        std::shared_ptr<SessionStack> stackPtr = iterForStack->second;
        CHECK_AND_RETURN_LOG(stackPtr != nullptr, "HandleUserRemoved with nullptr stack error");
        std::vector<sptr<AVSessionItem>> allSession = stackPtr->GetAllSessions();
        for (auto& sessionItem : allSession) {
            CHECK_AND_RETURN_LOG(sessionItem != nullptr, "HandleUserRemoved session null");
            std::string sessionId = sessionItem->GetSessionId();
            stackPtr->RemoveSession(sessionId);
            GetContainerFromAll().RemoveSession(sessionId);
        }
        sessionStackMapByUserId_.erase(iterForStack);
    }
    auto iterForFrontList = frontSessionListMapByUserId_.find(userId);
    if (iterForFrontList != frontSessionListMapByUserId_.end()) {
        frontSessionListMapByUserId_.erase(iterForFrontList);
    }
    auto iter = keyEventListMapByUserId_.find(userId);
    if (iter != keyEventListMapByUserId_.end()) {
        keyEventListMapByUserId_.erase(iter);
    }
    auto iterForListenerMap = sessionListenersMapByUserId_.find(userId);
    if (iterForListenerMap != sessionListenersMapByUserId_.end()) {
        sessionListenersMapByUserId_.erase(iterForListenerMap);
    }
    auto iterForTop = topSessionsMapByUserId_.find(userId);
    if (iterForTop != topSessionsMapByUserId_.end()) {
        topSessionsMapByUserId_.erase(iterForTop);
    }
    aliveUsers_.remove_if([userId](int32_t element) { return element == userId; });
}


SessionStack& AVSessionUsersManager::GetContainer()
{
    return GetContainerFromUser(curUserId_);
}

SessionStack& AVSessionUsersManager::GetContainerFromUser(int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    std::shared_ptr<SessionStack> stackPtr = nullptr;
    auto iter = sessionStackMapByUserId_.find(userId);
    if (iter != sessionStackMapByUserId_.end()) {
        stackPtr = iter->second;
    } else {
        SLOGI("create new stack for user %{public}d", userId);
        stackPtr = std::make_shared<SessionStack>();
        sessionStackMapByUserId_[userId] = stackPtr;
    }
    if (stackPtr == nullptr) {
        SLOGE("error finding sessionStack ptr null, return default!");
        static SessionStack sessionStack;
        return sessionStack;
    }
    return *stackPtr;
}

SessionStack& AVSessionUsersManager::GetContainerFromAll()
{
    if (sessionStackForAll_ == nullptr) {
        sessionStackForAll_ = std::make_shared<SessionStack>();
    }
    return *sessionStackForAll_;
}

std::shared_ptr<std::list<sptr<AVSessionItem>>> AVSessionUsersManager::GetCurSessionListForFront(int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    if (userId <= 0) {
        userId = curUserId_;
    }
    std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront = nullptr;
    auto iterForFrontList = frontSessionListMapByUserId_.find(userId);
    if (iterForFrontList != frontSessionListMapByUserId_.end()) {
        sessionListForFront = iterForFrontList->second;
    } else {
        SLOGI("GetCurSessionListForFront without targetUser: %{public}d, create new", userId);
        sessionListForFront = std::make_shared<std::list<sptr<AVSessionItem>>>();
        frontSessionListMapByUserId_[userId] = sessionListForFront;
    }
    return sessionListForFront;
}

std::shared_ptr<std::list<sptr<AVSessionItem>>> AVSessionUsersManager::GetCurSessionListForKeyEvent(int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    if (userId <= 0) {
        userId = curUserId_;
    }
    std::shared_ptr<std::list<sptr<AVSessionItem>>> keyEventSessionList = nullptr;
    auto it = keyEventListMapByUserId_.find(userId);
    if (it != keyEventListMapByUserId_.end()) {
        keyEventSessionList = it->second;
    } else {
        SLOGI("GetCurSessionListForKeyEvent without targetUser: %{public}d, create new", userId);
        keyEventSessionList = std::make_shared<std::list<sptr<AVSessionItem>>>();
        keyEventListMapByUserId_[userId] = keyEventSessionList;
    }
    return keyEventSessionList;
}

int32_t AVSessionUsersManager::GetCurrentUserId()
{
    std::lock_guard lockGuard(userLock_);
    return curUserId_;
}

std::string AVSessionUsersManager::GetDirForCurrentUser(int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    if (curUserId_ < 0) {
        return AVSESSION_FILE_PUBLIC_DIR;
    } else if (userId <= 0) {
        return AVSESSION_FILE_DIR_HEAD + std::to_string(curUserId_) + AVSESSION_FILE_DIR_TAIL;
    } else {
        SLOGI("GetDirForCurrentUser with specific userId:%{public}d", userId);
        return AVSESSION_FILE_DIR_HEAD + std::to_string(userId) + AVSESSION_FILE_DIR_TAIL;
    }
}

int32_t AVSessionUsersManager::AddSessionForCurrentUser(pid_t pid,
    const std::string& abilityName, sptr<AVSessionItem>& item)
{
    std::lock_guard lockGuard(userLock_);
    SLOGI("add session for user %{public}d", curUserId_);
    int32_t ret = AVSESSION_ERROR;
    ret = GetContainerFromAll().AddSession(pid, abilityName, item);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "error when add session for all");
    ret = GetContainerFromUser(curUserId_).AddSession(pid, abilityName, item);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "error when add session for user");
    return ret;
}

sptr<AVSessionItem> AVSessionUsersManager::RemoveSessionForAllUser(pid_t pid, const std::string& abilityName)
{
    std::lock_guard lockGuard(userLock_);
    sptr<AVSessionItem> result;
    SLOGI("remove session for pid %{public}d,abilityName %{public}s", static_cast<int>(pid), abilityName.c_str());
    result = GetContainerFromAll().RemoveSession(pid, abilityName);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, result, "remove session from all get nullptr");
    std::string sessionId = result->GetSessionId();
    int32_t userId = result->GetUserId();
    GetContainerFromUser(userId).RemoveSession(pid, abilityName);
    std::string fileName = AVSessionUtils::GetCachePathName(userId) + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileName);
    return result;
}

sptr<AVSessionItem> AVSessionUsersManager::RemoveSessionForAllUser(const std::string& sessionId)
{
    std::lock_guard lockGuard(userLock_);
    sptr<AVSessionItem> result;
    SLOGI("remove session for sessionId %{public}s", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    result = GetContainerFromAll().RemoveSession(sessionId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, result, "remove session from all get nullptr");
    int32_t userId = result->GetUserId();
    GetContainerFromUser(userId).RemoveSession(sessionId);
    std::string fileName = AVSessionUtils::GetCachePathName(userId) + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileName);
    return result;
}

std::vector<sptr<AVSessionItem>> AVSessionUsersManager::RemoveSessionForAllUser(pid_t pid)
{
    std::lock_guard lockGuard(userLock_);
    SLOGI("remove session for only pid %{public}d", static_cast<int>(pid));
    std::vector<sptr<AVSessionItem>> result;
    result = GetContainerFromAll().GetSessionsByPid(pid);
    for (auto& sessionItem : result) {
        CHECK_AND_RETURN_RET_LOG(sessionItem != nullptr, result, "RemoveSessionForAllUser session null");
        std::string sessionId = sessionItem->GetSessionId();
        int32_t userId = sessionItem->GetUserId();
        GetContainerFromUser(userId).RemoveSession(sessionId);
        GetContainerFromAll().RemoveSession(sessionId);
    }
    return result;
}

void AVSessionUsersManager::AddSessionListener(pid_t pid, const sptr<ISessionListener>& listener)
{
    std::lock_guard lockGuard(userLock_);
    SLOGI("add sessionListener for pid %{public}d, curUser %{public}d", static_cast<int>(pid), curUserId_);
    auto iterForListenerMap = sessionListenersMapByUserId_.find(curUserId_);
    if (iterForListenerMap != sessionListenersMapByUserId_.end()) {
        (iterForListenerMap->second)[pid] = listener;
    } else {
        std::map<pid_t, sptr<ISessionListener>> listenerMap;
        listenerMap[pid] = listener;
        sessionListenersMapByUserId_[curUserId_] = listenerMap;
    }
}

void AVSessionUsersManager::AddSessionListenerForAllUsers(pid_t pid, const sptr<ISessionListener>& listener)
{
    std::lock_guard lockGuard(userLock_);
    SLOGI("add sessionListener for pid %{public}d, for all users", static_cast<int>(pid));
    sessionListenersMap_[pid] = listener;
}

void AVSessionUsersManager::RemoveSessionListener(pid_t pid)
{
    std::lock_guard lockGuard(userLock_);
    for (auto& listenersMapByUserIdPair : sessionListenersMapByUserId_) {
        int32_t userId = listenersMapByUserIdPair.first;
        auto iterForListenersMapByUserId = (listenersMapByUserIdPair.second).find(pid);
        if (iterForListenersMapByUserId != (listenersMapByUserIdPair.second).end()) {
            SLOGI("remove sessionListener for pid:%{public}d, targetUser:%{public}d", static_cast<int>(pid), userId);
            (listenersMapByUserIdPair.second).erase(iterForListenersMapByUserId);
        }
    }
    sessionListenersMap_.erase(pid);
    SLOGI("remove sessionListener for pid %{public}d, curUser %{public}d", static_cast<int>(pid), curUserId_);
}

std::map<pid_t, sptr<ISessionListener>>& AVSessionUsersManager::GetSessionListener()
{
    return GetSessionListenerForCurUser();
}

std::map<pid_t, sptr<ISessionListener>>& AVSessionUsersManager::GetSessionListenerForCurUser()
{
    std::lock_guard lockGuard(userLock_);
    auto iterForListenerMap = sessionListenersMapByUserId_.find(curUserId_);
    if (iterForListenerMap != sessionListenersMapByUserId_.end()) {
        return iterForListenerMap->second;
    } else {
        std::map<pid_t, sptr<ISessionListener>> listenerMap;
        sessionListenersMapByUserId_[curUserId_] = listenerMap;
        SLOGI("get session listener map with null, create new map and return for user %{public}d", curUserId_);
        return sessionListenersMapByUserId_[curUserId_];
    }
}

std::map<pid_t, sptr<ISessionListener>>& AVSessionUsersManager::GetSessionListenerForAllUsers()
{
    return sessionListenersMap_;
}

void AVSessionUsersManager::NotifyAccountsEvent(const std::string &type, const int &userId)
{
    std::lock_guard lockGuard(userLock_);
    // lock for AccountEventsListener callback
    AccountManagerAdapter::GetInstance().HandleAccountsEvent(type, userId);
}

void AVSessionUsersManager::SetTopSession(sptr<AVSessionItem> session)
{
    SetTopSession(session, curUserId_);
}

void AVSessionUsersManager::SetTopSession(sptr<AVSessionItem> session, int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    topSessionsMapByUserId_[userId] = session;
}

sptr<AVSessionItem> AVSessionUsersManager::GetTopSession()
{
    return GetTopSession(curUserId_);
}

sptr<AVSessionItem> AVSessionUsersManager::GetTopSession(int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    auto iterForTop = topSessionsMapByUserId_.find(userId);
    if (iterForTop != topSessionsMapByUserId_.end()) {
        return iterForTop->second;
    }
    return nullptr;
}

void AVSessionUsersManager::ClearCache()
{
    std::lock_guard lockGuard(userLock_);
    for (const auto& userId : aliveUsers_) {
        std::string cachePath(AVSessionUtils::GetCachePathName(userId));
        AVSessionUtils::DeleteCacheFiles(cachePath);
    }
}
}
