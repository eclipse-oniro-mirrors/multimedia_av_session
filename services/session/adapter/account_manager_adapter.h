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

#ifndef AV_SESSION_ACCOUNT_MANAGER_ADAPTER_H
#define AV_SESSION_ACCOUNT_MANAGER_ADAPTER_H

#include <functional>
#include <mutex>
#include <list>

namespace OHOS::AVSession {
class AccountManagerAdapter {
public:
    using AccountSwitchListener = std::function<void(const std::string &type, const int &userId)>;

    static AccountManagerAdapter& GetInstance();

    ~AccountManagerAdapter();

    void Init();

    int32_t GetCurrentAccountUserId();

    void HandleAccountsEvent(const std::string &type, const int &userId);

    void AddAccountEventsListener(const AccountSwitchListener& callback);

    static constexpr const char* accountEventSwitched = "SWITCHED";
    static constexpr const char* accountEventRemoved = "REMOVED";

private:
    AccountManagerAdapter();

    std::list<AccountSwitchListener> accountEventsListenerList_;
    std::mutex listenerListMutex_;
    const int32_t defaultUserId = 100;
};
}
#endif // AV_SESSION_ACCOUNT_MANAGER_ADAPTER_H
