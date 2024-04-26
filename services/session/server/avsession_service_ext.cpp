/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "avsession_service.h"

#include "migrate_avsession_manager.h"

namespace OHOS::AVSession {
void AVSessionService::SuperLauncher(std::string deviceId, std::string serviceName,
    std::string extraInfo, const std::string& state)
{
    SLOGI("SuperLauncher serviceName: %{public}s, state: %{public}s",
        serviceName.c_str(), state.c_str());

    if (state == "IDLE") {
        MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(serviceName);
        if (migrateAVSession_ != nullptr) {
            RemoveInnerSessionListener(migrateAVSession_.get());
        }
    } else if (state == "CONNECTING") {
        if (migrateAVSession_ == nullptr) {
            migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
        }
        migrateAVSession_->Init(this);
        MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(serviceName, migrateAVSession_);
        AddInnerSessionListener(migrateAVSession_.get());
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    castServiceNameMapState_[serviceName] = state;
    NotifyMirrorToStreamCast();
#endif
}

void AVSessionService::AddInnerSessionListener(SessionListener *listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    innerSessionListeners_.push_back(listener);
}

void AVSessionService::RemoveInnerSessionListener(SessionListener *listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (auto it = innerSessionListeners_.begin(); it != innerSessionListeners_.end();) {
        if (*it == listener) {
            SLOGI("RemoveInnerSessionListener");
            innerSessionListeners_.erase(it++);
        } else {
            it++;
        }
    }
}
}