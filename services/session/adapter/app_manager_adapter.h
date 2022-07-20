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

#ifndef AV_SESSION_APP_MANAGER_ADAPTER_H
#define AV_SESSION_APP_MANAGER_ADAPTER_H

#include <functional>
#include <mutex>
#include <set>
#include "app_mgr_client.h"
#include "app_state_callback_host.h"

namespace OHOS::AVSession {
class AppManagerAdapter {
public:
    static AppManagerAdapter& GetInstance();

    ~AppManagerAdapter();

    void Init();

    bool IsAppBackground(int32_t uid);

    void SetAppBackgroundStateObserver(const std::function<void(int32_t)>& observer);

    void AddObservedApp(int32_t uid);

    void RemoveObservedApp(int32_t uid);

    void HandleAppStateChanged(const AppExecFwk::AppProcessData& appProcessData);

private:
    AppManagerAdapter();

    AppExecFwk::AppMgrClient appManager_;
    sptr<AppExecFwk::IAppStateCallback> appStateCallback_;
    std::function<void(int32_t)> backgroundObserver_;
    std::recursive_mutex uidLock_;
    std::set<int32_t> observedAppUIDs_;
};

class AVSessionAppStateCallback : public AppExecFwk::AppStateCallbackHost {
public:
    void OnAppStateChanged(const AppExecFwk::AppProcessData &) override;
};
}
#endif // AV_SESSION_APP_MANAGER_ADAPTER_H