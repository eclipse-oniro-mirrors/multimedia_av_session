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

#include <thread>
#include <chrono>
#include <utility>

#include "avsession_log.h"
#include "app_mgr_constants.h"
#include "app_manager_adapter.h"

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
    int retryCount = 0;
    while (retryCount < RETRY_COUNT_MAX) {
        if (appManager_.RegisterAppStateCallback(appStateCallback_) != AppMgrResultCode::RESULT_OK) {
            SLOGE("register app state callback failed");
            retryCount++;
            std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_INTERVAL_TIME));
            continue;
        }
        break;
    }
}

bool AppManagerAdapter::IsAppBackground(int32_t uid, int32_t pid)
{
    std::vector<RunningProcessInfo> infos;
    if (appManager_.GetAllRunningProcesses(infos) != AppMgrResultCode::RESULT_OK) {
        SLOGE("get all running processes info failed");
        return false;
    }
    for (const auto& info : infos) {
        if (info.uid_ == uid && info.pid_ == pid && info.state_ == AppProcessState::APP_STATE_BACKGROUND) {
            SLOGI("uid=%{public}d pid=%{public}d is background", uid, pid);
            return true;
        }
    }
    SLOGD("uid=%{public}d pid=%{public}d is not background", uid, pid);
    return false;
}

void AppManagerAdapter::SetAppStateChangeObserver(const std::function<void(int32_t, int32_t, bool)>& observer)
{
    appStateChangeObserver_ = observer;
}

// LCOV_EXCL_START
void AppManagerAdapter::AddObservedApp(int32_t uid)
{
    std::lock_guard lockGuard(uidLock_);
    SLOGD("add for uid=%{public}d", uid);
    observedAppUIDs_.insert(uid);
}
// LCOV_EXCL_STOP

void AppManagerAdapter::RemoveObservedApp(int32_t uid)
{
    std::lock_guard lockGuard(uidLock_);
    SLOGD("RemoveObservedApp for uid=%{public}d", uid);
    observedAppUIDs_.erase(uid);
}

void AppManagerAdapter::SetServiceCallbackForAppStateChange(const std::function<void(int uid, int state)>& callback)
{
    serviceCallbackForAppStateChange_ = callback;
    SLOGI("appStateChangeCallback set done");
}

// LCOV_EXCL_START
void AppManagerAdapter::HandleAppStateChanged(const AppProcessData& appProcessData)
{
    {
        std::lock_guard lockGuard(uidLock_);
        if (appProcessData.appState == ApplicationState::APP_STATE_FOREGROUND ||
            appProcessData.appState == ApplicationState::APP_STATE_BACKGROUND) {
            for (const auto& appData : appProcessData.appDatas) {
                CHECK_AND_CONTINUE(serviceCallbackForAppStateChange_ != nullptr);
                serviceCallbackForAppStateChange_(appData.uid, static_cast<int>(appProcessData.appState));
            }
        }
    }
    if (appProcessData.appState == ApplicationState::APP_STATE_TERMINATED) {
        for (const auto& appData : appProcessData.appDatas) {
            SLOGI("HandleAppStateChanged remove for uid=%{public}d", static_cast<int>(appData.uid));
            RemoveObservedApp(appData.uid);
        }
    }

    std::set<std::pair<int32_t, int32_t>> appNeedHandleMap;
    {
        std::lock_guard lockGuard(uidLock_);
        for (const auto& appData : appProcessData.appDatas) {
            SLOGI("uid=%{public}d|pid=%{public}d|state=%{public}d",
                appData.uid, appProcessData.pid, appProcessData.appState);
            auto it = observedAppUIDs_.find(appData.uid);
            if (it == observedAppUIDs_.end()) {
                continue;
            }
            appNeedHandleMap.insert(std::make_pair(appData.uid, appProcessData.pid));
        }
    }

    if (appProcessData.appState == ApplicationState::APP_STATE_BACKGROUND) {
        if (appStateChangeObserver_) {
            for (const auto& pair : appNeedHandleMap) {
                appStateChangeObserver_(pair.first, pair.second, true);
            }
        }
    } else {
        if (appStateChangeObserver_) {
            for (const auto& pair : appNeedHandleMap) {
                appStateChangeObserver_(pair.first, pair.second, false);
            }
        }
    }
}
// LCOV_EXCL_STOP

void AVSessionAppStateCallback::OnAppStateChanged(const AppExecFwk::AppProcessData& appProcessData)
{
    AppManagerAdapter::GetInstance().HandleAppStateChanged(appProcessData);
}
}
