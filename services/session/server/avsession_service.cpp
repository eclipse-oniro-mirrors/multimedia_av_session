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

#include "avsession_service.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS::AVSession {
REGISTER_SYSTEM_ABILITY_BY_ID(AVSessionService, AVSESSION_SERVICE_ID, true);

AVSessionService::AVSessionService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
    SLOGD("construct");
}

AVSessionService::~AVSessionService()
{
    SLOGD("destroy");
    if (sessionContainer_ != nullptr) {
    }
    {
        std::lock_guard<std::mutex> lockGuard(sessionListenersLock_);
        sessionListeners_.erase(sessionListeners_.begin(), sessionListeners_.end());
    {
        std::lock_guard<std::mutex> lockGuard(controllersLock_);
        controllers_.erase(controllers_.begin(), controllers_.end());
    }
    {
        std::lock_guard<std::mutex> lockGuard(clientDeathObserversLock_);
        clientDeathObservers_.erase(clientDeathObservers_.begin(), clientDeathObservers_.end());
    }
}

void AVSessionService::OnStart()
{
    if (!Publish(this)) {
        SLOGE("publish avsession service failed");
    }
}

void AVSessionService::OnDump()
{
}

void AVSessionService::OnStop()
{
}

int32_t AVSessionService::AllocSessionId()
{
    return 0;
}

sptr<IRemoteObject>  AVSessionService::CreateSessionInner(const std::string& tag, const std::string& type,
    const std::string& bundleName, const std::string& abilityName)
{
    auto id = AllocSessionId();
    return nullptr;
}

sptr<AVSession> AVSessionService::GetSessionInner()
{
    return nullptr;
}

sptr<IRemoteObject> AVSessionService::CreateControllerInner(int32_t sessionId)
{
    auto id = sessionId;
    {
        std::lock_guard<std::mutex> lockGuard(controllersLock_);
    }
    return nullptr;
}

sptr<IRemoteObject> AVSessionService::GetControllerInner(int32_t sessionId)
{
    return nullptr;
}

std::vector<sptr<IRemoteObject>> AVSessionService::GetAllControllersInner()
{

}

int32_t AVSessionService::RegisterSessionListenerInner(sptr<IRemoteObject>& listener)
{
    return 0;
}
int32_t AVSessionService::SendSystemMediaKeyEvent(MMI::KeyEvent& keyEvent)
{
    return 0;
}

int32_t AVSessionService::SetSystemMediaVolume(int32_t volume)
{
    return 0;
}
int32_t AVSessionService::RegisterClientDeathObserver(sptr<IRemoteObject>& observer)
{
    return 0;
}
void AVSessionService::OnStart()
{

}
void AVSessionService::OnClientDied(pid_t pid)
{

}
} // namespace OHOS::AVSession