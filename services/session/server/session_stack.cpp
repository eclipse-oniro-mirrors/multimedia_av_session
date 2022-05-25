/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

namespace OHOS::AVSession {
int32_t SessionStack::AddSession(pid_t pid, sptr<AVSessionItem>& item)
{
    if (sessions_.size() > SessionContainer::SESSION_NUM_MAX) {
        return ERR_SESSION_EXCEED_MAX;
    }
    sessions_[pid] = item;
    stack_.push_front(item);
    return AVSESSION_SUCCESS;
}

sptr<AVSessionItem> SessionStack::RemoveSession(pid_t pid)
{
    auto it = sessions_.find(pid);
    if (it == sessions_.end()) {
        return nullptr;
    }
    auto result = it->second;
    sessions_.erase(it);
    stack_.remove(result);
    return result;
}

sptr<AVSessionItem> SessionStack::GetSession(pid_t pid)
{
    auto it = sessions_.find(pid);
    if (it == sessions_.end()) {
        return nullptr;
    }
    return it->second;
}

sptr<AVSessionItem> SessionStack::GetSessionById(int32_t sessionId)
{
    for (const auto& session : stack_) {
        if (session->GetSessionId() == sessionId) {
            return session;
        }
    }
    return nullptr;
}

std::vector<sptr<AVSessionItem>> SessionStack::GetAllSessions()
{
    std::vector<sptr<AVSessionItem>> result;
    for (const auto& session : stack_) {
        result.push_back(session);
    }
    return result;
}
} // namespace OHOS::AVSession