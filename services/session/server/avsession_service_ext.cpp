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
#ifdef COLLABORATIONFWK_ENABLE
void AVSessionService::InitAllConnect()
{
    SLOGI("start register allconnect...");
    int32_t ret = CollaborationFwk::AllConnectManager::GetInstance()
        .SubscribeServiceState(new CSImpl(this));
    CHECK_AND_RETURN_LOG(ret == 0, "InitAllConnect error, ret is %{public}d", ret);
}

void AVSessionService::SuperLauncher(std::string deviceId, std::string serviceName,
    std::string extraInfo, int32_t state)
{
    SLOGI("SuperLauncher deviceId: %{public}s, serviceName: %{public}s, state: %{public}d",
        deviceId.c_str(), serviceName.c_str(), state);
    switch (state) {
        case CollaborationFwk::BussinessStatus::IDLE:
            MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(serviceName);
            if (migrateAVSession_ != nullptr) {
                RemoveInnerSessionListener(migrateAVSession_.get());
            }
            break;
        case CollaborationFwk::BussinessStatus::CONNECTING:
            if (migrateAVSession_ == nullptr) {
                migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
            }
            migrateAVSession_->Init(this);
            MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(serviceName, migrateAVSession_);
            AddInnerSessionListener(migrateAVSession_.get());
            break;
        default:
            break;
    }
}
#endif

void AVSessionService::AddInnerSessionListener(SessionListener* listener)
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