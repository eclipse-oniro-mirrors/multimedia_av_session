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

#include <chrono>
#include <algorithm>

#include "avsession_log.h"
#include "avsession_errors.h"
#include "account_manager_adapter.h"
#include "os_account_manager.h"

namespace OHOS::AVSession {
AccountManagerAdapter::AccountManagerAdapter()
{
    SLOGI("construct");
}

AccountManagerAdapter::~AccountManagerAdapter()
{
    SLOGI("AccountManagerAdapter destroy");
    std::lock_guard<std::mutex> listLockGuard(listenerListMutex_);
    accountEventsListenerList_.clear();
}

bool AccountManagerAdapter::IsOsAccountActive(int32_t userId)
{
    std::vector<int32_t> activeIds;
    auto result = AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeIds);
    if (result != 0 || activeIds.empty()) {
        // fail-open: keep legacy behaviour when the account service is unavailable
        SLOGW("query active os accounts failed, result:%{public}d, accept userId:%{public}d", result, userId);
        return true;
    }
    return std::find(activeIds.begin(), activeIds.end(), userId) != activeIds.end();
}

AccountManagerAdapter& AccountManagerAdapter::GetInstance()
{
    static AccountManagerAdapter accountManagerAdapter;
    return accountManagerAdapter;
}

void AccountManagerAdapter::Init()
{
    // no OsAccountSubscriber register as os_account_manager.h dependency will be removed
    SLOGI("init AccountManagerAdapter from default user: %{public}d", GetCurrentAccountUserId());
}

int32_t AccountManagerAdapter::GetCurrentAccountUserId()
{
    int32_t userId = defaultUserId;
    // temp use userId : defaultUserId as os_account_manager.h dependency will be removed
    return userId;
}

void AccountManagerAdapter::HandleAccountsEvent(const std::string &type, const int &userId)
{
    std::lock_guard<std::mutex> listLockGuard(listenerListMutex_);
    SLOGI("HandleAccountsEvent for %{public}d with event %{public}s", userId, type.c_str());
    for (const auto& listener : accountEventsListenerList_) {
        if (listener) {
            listener(type, userId);
        }
    }
}

void AccountManagerAdapter::AddAccountEventsListener(const AccountSwitchListener& callback)
{
    std::lock_guard<std::mutex> listLockGuard(listenerListMutex_);
    accountEventsListenerList_.push_back(callback);
}
}
