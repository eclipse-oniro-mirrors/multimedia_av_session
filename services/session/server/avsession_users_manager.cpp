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
#include "avsession_storage_event.h"
#include "avsession_utils.h"

#ifdef CAR_FEATURE_ENABLE
#include "audio_zone_manager.h"
#include "avsession_service.h"
#include "migrate_avsession_proxy.h"
#include "avcontroller_item.h"
#include <algorithm>
#endif

#include <set>

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

std::list<int32_t> AVSessionUsersManager::GetAliveUserList()
{
    std::lock_guard lockGuard(userLock_);
    return aliveUsers_;
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

std::shared_ptr<SessionStack> AVSessionUsersManager::GetContainerPtrFromUser(int32_t userId)
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
    return stackPtr;
}

SessionStack& AVSessionUsersManager::GetContainerFromAll()
{
    std::lock_guard lockGuard(userLock_);
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
        SLOGD("GetDirForCurrentUser with specific userId:%{public}d", userId);
        return AVSESSION_FILE_DIR_HEAD + std::to_string(userId) + AVSESSION_FILE_DIR_TAIL;
    }
}

int32_t AVSessionUsersManager::AddSessionForCurrentUser(pid_t pid,
    const std::string& abilityName, sptr<AVSessionItem>& item, int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    userId = (userId <= 0) ? curUserId_ : userId;
    SLOGI("add session for user %{public}d", userId);
    int32_t ret = AVSESSION_ERROR;
    ret = GetContainerFromAll().AddSession(pid, abilityName, item);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "error when add session for all");
    ret = GetContainerFromUser(userId).AddSession(pid, abilityName, item);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "error when add session for user");
    return ret;
}

int32_t AVSessionUsersManager::UpdateSessionForCurrentUser(pid_t pid, const std::string& oldAbilityName,
    const std::string& newAbilityName, sptr<AVSessionItem>& item)
{
    SLOGI("update session %{public}s for user %{public}d", oldAbilityName.c_str(), curUserId_);
    sptr<AVSessionItem> result = RemoveSessionForAllUser(pid, oldAbilityName);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, AVSESSION_ERROR, "error when remove session for user");
    int32_t ret = AddSessionForCurrentUser(pid, newAbilityName, item);
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
    STORAGE_EVENT_REMOVE_SESSION(sessionId);
    std::string fileNameLocal = AVSessionUtils::GetCachePathName(userId) + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileNameLocal);
    STORAGE_EVENT_RECORD_FILE_DELETE(fileNameLocal, userId);
    std::string fileNameCast =
        AVSessionUtils::GetCachePathNameForCast(userId) + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileNameCast);
    STORAGE_EVENT_RECORD_FILE_DELETE(fileNameCast, userId);
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
    STORAGE_EVENT_REMOVE_SESSION(sessionId);
    std::string fileNameLocal = AVSessionUtils::GetCachePathName(userId) + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileNameLocal);
    STORAGE_EVENT_RECORD_FILE_DELETE(fileNameLocal, userId);
    std::string fileNameCast =
        AVSessionUtils::GetCachePathNameForCast(userId) + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileNameCast);
    STORAGE_EVENT_RECORD_FILE_DELETE(fileNameCast, userId);
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
        STORAGE_EVENT_REMOVE_SESSION(sessionId);
    }
    return result;
}

void AVSessionUsersManager::AddSessionListener(pid_t pid, const sptr<ISessionListener>& listener, int32_t userId)
{
    CHECK_AND_RETURN_LOG(listener != nullptr, "listener is nullptr");
    std::lock_guard lockGuard(userLock_);
    userId = (userId <= 0) ? curUserId_ : userId;
    SLOGI("add sessionListener for pid %{public}d, targetUser %{public}d", static_cast<int>(pid), userId);
    auto iterForListenerMap = sessionListenersMapByUserId_.find(userId);
    if (iterForListenerMap != sessionListenersMapByUserId_.end()) {
        (iterForListenerMap->second)[pid] = listener;
    } else {
        std::map<pid_t, sptr<ISessionListener>> listenerMap;
        listenerMap[pid] = listener;
        sessionListenersMapByUserId_[userId] = listenerMap;
    }
}

void AVSessionUsersManager::AddSessionListenerForAllUsers(pid_t pid, const sptr<ISessionListener>& listener)
{
    CHECK_AND_RETURN_LOG(listener != nullptr, "listener is nullptr");
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

std::map<pid_t, sptr<ISessionListener>> AVSessionUsersManager::GetSessionListener(int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    userId = userId <= 0 ? curUserId_ : userId;
    auto iterForListenerMap = sessionListenersMapByUserId_.find(userId);
    if (iterForListenerMap != sessionListenersMapByUserId_.end()) {
        return iterForListenerMap->second;
    } else {
        std::map<pid_t, sptr<ISessionListener>> listenerMap;
        sessionListenersMapByUserId_[userId] = listenerMap;
        SLOGI("get sessionListenerMap null, create new for user %{public}d", userId);
        return sessionListenersMapByUserId_[userId];
    }
}

std::map<pid_t, sptr<ISessionListener>> AVSessionUsersManager::GetSessionListenerForAllUsers()
{
    std::lock_guard lockGuard(userLock_);
    return sessionListenersMap_;
}

#ifdef CAR_FEATURE_ENABLE
void AVSessionUsersManager::AddSessionListenerForUser(pid_t pid, const sptr<ISessionListener>& listener, int32_t userId)
{
    CHECK_AND_RETURN_LOG(listener != nullptr, "listener is nullptr");
    if (userId <= 0) {
        SLOGE("AddSessionListenerForUser invalid userId=%{public}d", userId);
        return;
    }

    auto iterForListenerMap = sessionListenersMapByUserIdForAudioZone_.find(userId);
    if (iterForListenerMap != sessionListenersMapByUserIdForAudioZone_.end()) {
        (iterForListenerMap->second)[pid] = listener;
    } else {
        std::map<pid_t, sptr<ISessionListener>> listenerMap;
        listenerMap[pid] = listener;
        sessionListenersMapByUserIdForAudioZone_[userId] = listenerMap;
    }
}

std::map<int32_t, std::map<pid_t, sptr<ISessionListener>>>& AVSessionUsersManager::GetSessionListenersMapForAudioZone()
{
    return sessionListenersMapByUserIdForAudioZone_;
}
#endif

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

void AVSessionUsersManager::CleanupCacheOnUnlock(int32_t userId)
{
    std::lock_guard lockGuard(userLock_);
    userId = (userId <= 0) ? curUserId_ : userId;
    SLOGI("CleanupCacheOnUnlock for user %{public}d", userId);
    auto iter = sessionStackMapByUserId_.find(userId);
    std::set<std::string> aliveSessionIds;
    if (iter != sessionStackMapByUserId_.end() && iter->second != nullptr) {
        for (auto& session : iter->second->GetAllSessions()) {
            CHECK_AND_CONTINUE(session != nullptr);
            aliveSessionIds.insert(session->GetSessionId());
        }
    }
    SLOGI("CleanupCacheOnUnlock keep %{public}zu alive session image files", aliveSessionIds.size());
    // Local files live in the cache dir, cast files in the cache/cast_ subdir; clean both.
    std::string cachePath(AVSessionUtils::GetCachePathName(userId));
    AVSessionUtils::DeleteCacheFilesExcluding(cachePath, aliveSessionIds);
    std::string castCachePath(AVSessionUtils::GetCachePathNameForCast(userId));
    AVSessionUtils::DeleteCacheFilesExcluding(castCachePath, aliveSessionIds);
}

#ifdef CAR_FEATURE_ENABLE
int32_t AVSessionUsersManager::GetZoneIdForUser(int32_t userId)
{
    auto audioZoneManager = AudioStandard::AudioZoneManager::GetInstance();
    if (audioZoneManager == nullptr) {
        SLOGE("GetZoneIdForUser failed to get AudioZoneManager");
        return -1;
    }

    std::vector<int32_t> queryUserIds = {userId};
    std::vector<int32_t> retUserIds;
    auto ret = audioZoneManager->GetAudioZoneForApp(queryUserIds, retUserIds);
    if (ret != 0 || retUserIds.empty()) {
        return -1;
    }

    int32_t zoneId = retUserIds[0];
    return zoneId;
}

void AVSessionUsersManager::UpdateZoneToUseridMap(int32_t userId)
{
    int32_t zoneId = GetZoneIdForUser(userId);
    if (zoneId > 0) {
        auto& userIdList = zoneToUserid_[zoneId];
        if (std::find(userIdList.begin(), userIdList.end(), userId) == userIdList.end()) {
            userIdList.push_back(userId);
        }
    }
}

void AVSessionUsersManager::CleanupZoneToUseridMap(int32_t userId)
{
    int32_t zoneId = GetZoneIdForUser(userId);
    if (zoneId > 0) {
        auto zoneIter = zoneToUserid_.find(zoneId);
        if (zoneIter != zoneToUserid_.end()) {
            zoneIter->second.erase(
                std::remove(zoneIter->second.begin(), zoneIter->second.end(), userId),
                zoneIter->second.end()
            );
            if (zoneIter->second.empty()) {
                zoneToUserid_.erase(zoneIter);
            }
        }
    }
}

std::vector<int32_t> AVSessionUsersManager::GetUsersInSameAudioZone(int32_t userId)
{
    int32_t zoneId = GetZoneIdForUser(userId);
    if (zoneId <= 0) {
        return {};
    }
    
    std::vector<int32_t> result;
    auto zoneIter = zoneToUserid_.find(zoneId);
    if (zoneIter != zoneToUserid_.end()) {
        result = zoneIter->second;
    }

    return result;
}

void AVSessionUsersManager::UpdateSessionStackForAudioZone(int32_t userId)
{
    int32_t zoneId = GetZoneIdForUser(userId);
    if (zoneId <= 0) {
        return;
    }
    
    std::vector<std::pair<AVSessionDescriptor, int64_t>> sessionWithTime;
    
    CollectLocalSessionsForAudioZone(zoneId, sessionWithTime);
    CollectDistributedSessionsForAudioZone(zoneId, sessionWithTime);
    SortAndCacheSessionStack(zoneId, sessionWithTime);
}

void AVSessionUsersManager::AddSessionToVector(const sptr<AVSessionItem>& session,
    std::vector<std::pair<AVSessionDescriptor, int64_t>>& sessionWithTime)
{
    AVSessionDescriptor desc = session->GetDescriptor();
    int64_t playingTime = session->GetPlayingTime();
    sessionWithTime.push_back({desc, playingTime});
}

void AVSessionUsersManager::CollectLocalSessionsForAudioZone(int32_t zoneId,
    std::vector<std::pair<AVSessionDescriptor, int64_t>>& sessionWithTime)
{
    std::lock_guard lockGuard(userLock_);
    
    auto zoneIter = zoneToUserid_.find(zoneId);
    if (zoneIter == zoneToUserid_.end()) {
        return;
    }
    
    const std::vector<int32_t>& userIds = zoneIter->second;
    
    for (int32_t userId : userIds) {
        auto userIter = frontSessionListMapByUserId_.find(userId);
        if (userIter == frontSessionListMapByUserId_.end()) {
            continue;
        }
        
        for (auto& session : *(userIter->second)) {
            if (!IsCastSessionValid(session, zoneId)) {
                continue;
            }
            AddSessionToVector(session, sessionWithTime);
        }
    }
}

bool AVSessionUsersManager::IsCastSessionValid(const sptr<AVSessionItem>& session, int32_t zoneId)
{
    if (session == nullptr) {
        return false;
    }
    
    AVSessionDescriptor desc = session->GetDescriptor();
    if (desc.sessionTag_ != "RemoteCast") {
        return true;
    }
    
    int32_t castUserId = session->GetCastScreenUserId();
    int32_t castZoneId = GetZoneIdForUser(castUserId);
    return castZoneId == zoneId;
}

void AVSessionUsersManager::AddControllerToVector(
    const sptr<AVControllerItem>& controller,
    std::vector<std::pair<AVSessionDescriptor, int64_t>>& sessionWithTime)
{
    AVSessionDescriptor desc = controller->GetSessionDescriptor();
    int64_t createTime = controller->GetCreateTime();
    sessionWithTime.push_back({desc, createTime});
}

void AVSessionUsersManager::CollectDistributedSessionsForAudioZone(int32_t zoneId,
    std::vector<std::pair<AVSessionDescriptor, int64_t>>& sessionWithTime)
{
    auto service = AVSessionService::GetInstance();
    if (!service) {
        return;
    }
    std::vector<sptr<IRemoteObject>> controllers;
    int32_t ret = service->GetDistributedSessionControllersForAudioZone(controllers);
    if (ret != AVSESSION_SUCCESS || controllers.empty()) {
        SLOGI("No migrate-in distributed sessions, ret=%{public}d", ret);
        return;
    }
    std::lock_guard lockGuard(userLock_);
    auto zoneIter = zoneToUserid_.find(zoneId);
    if (zoneIter == zoneToUserid_.end()) {
        return;
    }
    const std::vector<int32_t>& targetUserIds = zoneIter->second;
    for (auto& controllerObj : controllers) {
        sptr<AVControllerItem> controller = iface_cast<AVControllerItem>(controllerObj);
        if (!controller) {
            continue;
        }
        AVSessionDescriptor desc = controller->GetSessionDescriptor();
        int32_t controllerUserId = desc.userId_;
        bool isTargetZone = std::find(targetUserIds.begin(), targetUserIds.end(),
            controllerUserId) != targetUserIds.end();
        if (isTargetZone) {
            AddControllerToVector(controller, sessionWithTime);
        }
    }
}

void AVSessionUsersManager::SortAndCacheSessionStack(int32_t zoneId,
    std::vector<std::pair<AVSessionDescriptor, int64_t>>& sessionWithTime)
{
    std::sort(sessionWithTime.begin(), sessionWithTime.end(),
        [](const std::pair<AVSessionDescriptor, int64_t>& a,
           const std::pair<AVSessionDescriptor, int64_t>& b) {
            return a.second > b.second;
        });
    
    std::vector<AVSessionDescriptor> descriptors;
    for (auto& item : sessionWithTime) {
        descriptors.push_back(item.first);
    }
    
    sessionStackMapForAudioZone_[zoneId] = descriptors;
}

std::vector<AVSessionDescriptor> AVSessionUsersManager::GetSessionStackForAudioZone(int32_t userId)
{
    int32_t zoneId = GetZoneIdForUser(userId);
    if (zoneId <= 0) {
        return {};
    }

    auto iter = sessionStackMapForAudioZone_.find(zoneId);
    if (iter != sessionStackMapForAudioZone_.end()) {
        return iter->second;
    }
    return {};
}
#endif
}
