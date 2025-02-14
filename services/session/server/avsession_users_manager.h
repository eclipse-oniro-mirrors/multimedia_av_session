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

#ifndef OHOS_AVSESSION_USERS_MANAGER_H
#define OHOS_AVSESSION_USERS_MANAGER_H

#include <map>
#include <mutex>
#include <list>

#include "session_stack.h"
#include "avsession_log.h"
#include "isession_listener.h"

namespace OHOS::AVSession {
class AVSessionUsersManager {
public:
    static AVSessionUsersManager& GetInstance();

    void Init();

    SessionStack& GetContainer();

    SessionStack& GetContainerFromUser(int32_t userId);

    SessionStack& GetContainerFromAll();

    std::shared_ptr<std::list<sptr<AVSessionItem>>> GetCurSessionListForFront(int32_t userId);

    int32_t GetCurrentUserId();

    std::string GetDirForCurrentUser(int32_t userId = 0);

    int32_t AddSessionForCurrentUser(pid_t pid, const std::string& abilityName, sptr<AVSessionItem>& item);

    sptr<AVSessionItem> RemoveSessionForAllUser(pid_t pid, const std::string& abilityName);

    sptr<AVSessionItem> RemoveSessionForAllUser(const std::string& sessionId);

    std::vector<sptr<AVSessionItem>> RemoveSessionForAllUser(pid_t pid);

    void AddSessionListener(pid_t pid, const sptr<ISessionListener>& listener);

    void AddSessionListenerForAllUsers(pid_t pid, const sptr<ISessionListener>& listener);

    void RemoveSessionListener(pid_t pid);

    std::map<pid_t, sptr<ISessionListener>>& GetSessionListener(int32_t userId = 0);

    std::map<pid_t, sptr<ISessionListener>>& GetSessionListenerForAllUsers();

    void NotifyAccountsEvent(const std::string &type, const int &userId);

    void SetTopSession(sptr<AVSessionItem> session);

    void SetTopSession(sptr<AVSessionItem> session, int32_t userId);

    sptr<AVSessionItem> GetTopSession();

    sptr<AVSessionItem> GetTopSession(int32_t userId);

    void ClearCache();

    static constexpr const char* accountEventSwitched = "SWITCHED";
    static constexpr const char* accountEventRemoved = "REMOVED";

private:
    void HandleUserRemoved(int32_t userId);

    std::map<int32_t, std::shared_ptr<SessionStack>> sessionStackMapByUserId_;
    std::shared_ptr<SessionStack> sessionStackForAll_;
    std::map<int32_t, std::shared_ptr<std::list<sptr<AVSessionItem>>>> frontSessionListMapByUserId_;
    std::map<int32_t, std::map<pid_t, sptr<ISessionListener>>> sessionListenersMapByUserId_;
    std::map<pid_t, sptr<ISessionListener>> sessionListenersMap_;
    std::map<pid_t, sptr<AVSessionItem>> topSessionsMapByUserId_;

    const std::string AVSESSION_FILE_PUBLIC_DIR = "/data/service/el2/public/av_session/";
    const std::string AVSESSION_FILE_DIR_HEAD = "/data/service/el2/";
    const std::string AVSESSION_FILE_DIR_TAIL = "/av_session/";

    int32_t curUserId_ = 100;
    std::list<int32_t> aliveUsers_;
    std::recursive_mutex userLock_;
};
}
#endif // OHOS_AVSESSION_USERS_MANAGER_H
