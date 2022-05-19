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
#include "avsession_log.h"

namespace OHOS::AVSession {
void SessionStack::AddSession(pid_t pid, sptr<AVSessionItem>& item)
{
    {
        std::lock_guard<std::mutex> lockGuard(lock_);
        sessions_[pid] = item;
        stack_.push_front(item);
    }
}

sptr<AVSessionItem> SessionStack::RemoveSession(pid_t pid)
{
    sptr<AVSessionItem> pAVSessionItem = nullptr;
    return pAVSessionItem;
}

sptr<AVSessionItem> SessionStack::GetSession(pid_t pid)
{
    return nullptr; // sessions_.at(pid);
}

std::vector<sptr<AVSessionItem>> SessionStack::GetAllSessions()
{
    std::vector<sptr<AVSessionItem>> avSessions;
    return avSessions;
}
} // namespace OHOS::AVSession