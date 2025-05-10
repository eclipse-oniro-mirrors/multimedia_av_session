/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "session_stack.h"
#include "avsession_errors.h"
#include "avsession_sysevent.h"

namespace OHOS::AVSession {
int32_t SessionStack::AddSession(pid_t pid, const std::string& abilityName, sptr<AVSessionItem>& item)
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    if (sessions_.size() >= SessionContainer::SESSION_NUM_MAX) {
        return ERR_SESSION_EXCEED_MAX;
    }
    sessions_.insert(std::make_pair(std::make_pair(pid, abilityName), item));
    stack_.push_front(item);
    HISYSEVENT_ADD_OPERATION_COUNT(Operation::OPT_CREATE_SESSION);
    return AVSESSION_SUCCESS;
}

void SessionStack::UpdateSessionSort(sptr<AVSessionItem>& item)
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    auto it = sessions_.find(std::make_pair(item->GetPid(), item->GetAbilityName()));
    if (it == sessions_.end()) {
        return;
    }
    stack_.remove(it->second);
    sessions_.erase(it);
    // change order by reinsert
    sessions_.insert(std::make_pair(std::make_pair(item->GetPid(), item->GetAbilityName()), item));
    stack_.push_front(item);
}

std::vector<sptr<AVSessionItem>> SessionStack::RemoveSession(pid_t pid)
{
    std::vector<sptr<AVSessionItem>> result;
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->first.first == pid) {
            std::string sessionId = it->second->GetSessionId();
            result.push_back(it->second);
            stack_.remove(it->second);
            it = sessions_.erase(it);
            HISYSEVENT_ADD_OPERATION_COUNT(Operation::OPT_DELETE_SESSION);
        } else {
            it++;
        }
    }
    return result;
}

sptr<AVSessionItem> SessionStack::RemoveSession(const std::string& sessionId)
{
    sptr<AVSessionItem> result;
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second->GetSessionId() == sessionId) {
            result = it->second;
            stack_.remove(it->second);
            it = sessions_.erase(it);
            HISYSEVENT_ADD_OPERATION_COUNT(Operation::OPT_DELETE_SESSION);
        } else {
            it++;
        }
    }
    return result;
}

sptr<AVSessionItem> SessionStack::RemoveSession(pid_t pid, const std::string& abilityName)
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    auto it = sessions_.find(std::make_pair(pid, abilityName));
    if (it == sessions_.end()) {
        return nullptr;
    }
    HISYSEVENT_ADD_OPERATION_COUNT(Operation::OPT_DELETE_SESSION);
    auto result = it->second;
    sessions_.erase(it);
    stack_.remove(result);
    return result;
}

sptr<AVSessionItem> SessionStack::GetSession(pid_t pid, const std::string& abilityName)
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    auto it = sessions_.find(std::make_pair(pid, abilityName));
    if (it == sessions_.end()) {
        return nullptr;
    }
    return it->second;
}

std::vector<sptr<AVSessionItem>> SessionStack::GetSessionsByPid(pid_t pid)
{
    std::vector<sptr<AVSessionItem>> result;
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    for (auto it = sessions_.begin(); it != sessions_.end(); it++) {
        if (it->first.first == pid) {
            result.push_back(it->second);
        }
    }
    return result;
}

bool SessionStack::PidHasSession(pid_t pid)
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    std::map<std::pair<pid_t, std::string>, sptr<AVSessionItem>>::iterator iter = sessions_.begin();
    while (iter != sessions_.end()) {
        if (iter->first.first == pid) {
            return true;
        }
        ++iter;
    }
    return false;
}

bool SessionStack::UidHasSession(int32_t uid)
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    for (const auto& session : stack_) {
        if (session->GetUid() == uid) {
            return true;
        }
    }
    return false;
}

sptr<AVSessionItem> SessionStack::GetSessionById(const std::string& sessionId)
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    for (const auto& session : stack_) {
        if (session->GetSessionId() == sessionId) {
            return session;
        }
    }
    return nullptr;
}

sptr<AVSessionItem> SessionStack::GetSessionByUid(const int32_t uid)
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    for (const auto& session : stack_) {
        if (session->GetUid() == uid) {
            return session;
        }
    }
    return nullptr;
}

std::vector<sptr<AVSessionItem>> SessionStack::GetAllSessions()
{
    std::vector<sptr<AVSessionItem>> result;
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    for (const auto& session : stack_) {
        result.push_back(session);
    }
    return result;
}

bool SessionStack::IsEmpty()
{
    std::lock_guard sessionStackLockGuard(sessionStackLock_);
    return stack_.empty();
}

int32_t SessionStack::getAllSessionNum()
{
    return static_cast<int32_t>(stack_.size());
}
} // namespace OHOS::AVSession
