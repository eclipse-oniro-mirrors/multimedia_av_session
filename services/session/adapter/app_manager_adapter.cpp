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

#include "app_manager_adapter.h"
#include "avsession_log.h"
#include "app_mgr_constants.h"

namespace OHOS::AVSession {
using AppExecFwk::AppProcessData;
using AppExecFwk::AppProcessState;
using AppExecFwk::AppMgrResultCode;
using AppExecFwk::RunningProcessInfo;
using AppExecFwk::ApplicationState;

AppManagerAdapter::AppManagerAdapter()
{
    SLOGI("construct");
}

AppManagerAdapter::~AppManagerAdapter()
{
    SLOGI("destroy");
}

AppManagerAdapter& AppManagerAdapter::GetInstance()
{
    static AppManagerAdapter appManagerAdapter;
    return appManagerAdapter;
}

void AppManagerAdapter::Init()
{
    appStateCallback_ = new(std::nothrow) AVSessionAppStateCallback();
    if (appStateCallback_ == nullptr) {
        SLOGE("no memory");
        return;
    }
    if (appManager_.RegisterAppStateCallback(appStateCallback_) != AppMgrResultCode::RESULT_OK) {
        SLOGE("register app state callback failed");
    }
}

bool AppManagerAdapter::IsAppBackground(int32_t uid)
{
    std::vector<RunningProcessInfo> infos;
    if (appManager_.GetAllRunningProcesses(infos) != AppMgrResultCode::RESULT_OK) {
        SLOGE("get all running processes info failed");
        return false;
    }
    for (const auto& info : infos) {
        if (info.uid_ == uid && info.state_ == AppProcessState::APP_STATE_BACKGROUND) {
            SLOGI("uid=%{public}d is background", uid);
            return true;
        }
    }
    SLOGI("uid=%{public}d is not background", uid);
    return false;
}

void AppManagerAdapter::SetAppBackgroundStateObserver(const std::function<void(int32_t)> &observer)
{
    backgroundObserver_ = observer;
}

void AppManagerAdapter::AddObservedApp(int32_t uid)
{
    std::lock_guard lockGuard(uidLock_);
    observedAppUIDs_.insert(uid);
}

void AppManagerAdapter::RemoveObservedApp(int32_t uid)
{
    std::lock_guard lockGuard(uidLock_);
    observedAppUIDs_.erase(uid);
}

void AppManagerAdapter::HandleAppStateChanged(const AppProcessData &appProcessData)
{
    if (appProcessData.appState == ApplicationState::APP_STATE_TERMINATED) {
        for (const auto& appData : appProcessData.appDatas) {
            RemoveObservedApp(appData.uid);
        }
    }

    if (appProcessData.appState != ApplicationState::APP_STATE_BACKGROUND) {
        return;
    }

    std::set<int32_t> backgroundUIDs;
    {
        std::lock_guard lockGuard(uidLock_);
        for (const auto& appData : appProcessData.appDatas) {
            SLOGI("bundleName=%{public}s uid=%{public}d state=%{public}d",
                  appData.appName.c_str(), appData.uid, appProcessData.appState);
            auto it = observedAppUIDs_.find(appData.uid);
            if (it != observedAppUIDs_.end()) {
                backgroundUIDs.insert(appData.uid);
            }
        }
    }

    if (backgroundObserver_) {
        for (const auto uid : backgroundUIDs) {
            backgroundObserver_(uid);
        }
    }
}

void AVSessionAppStateCallback::OnAppStateChanged(const AppExecFwk::AppProcessData &appProcessData)
{
    AppManagerAdapter::GetInstance().HandleAppStateChanged(appProcessData);
}
}