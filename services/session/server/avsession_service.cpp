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
#include "session_stack.h"

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
    delete sessionContainer_;
}

void AVSessionService::OnStart()
{
    sessionContainer_ = new(std::nothrow) SessionStack();
    if (sessionContainer_ == nullptr) {
        SLOGE("malloc session container failed");
        return;
    }

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
    std::lock_guard lockGuard(sessionIdsLock_);
    while (true) {
        auto it = std::find_if(sessionIds_.begin(), sessionIds_.end(),
                               [this](const auto id) { return id == sessionSeqNum_; });
        if (it == sessionIds_.end()) {
            sessionIds_.push_back(sessionSeqNum_);
            return sessionSeqNum_;
        }
        if (++sessionSeqNum_ < 0) {
            sessionSeqNum_ = 0;
        }
    }
}

sptr<IRemoteObject>  AVSessionService::CreateSessionInner(const std::string& tag, int32_t type,
    const std::string& bundleName, const std::string& abilityName)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = AllocSessionId();
    descriptor.sessionTag_ = tag;
    descriptor.sessionType_ = type;
    descriptor.bundleName_ = bundleName;
    descriptor.abilityName_ = abilityName;

    sptr<AVSessionItem> session = new(std::nothrow) AVSessionItem(descriptor);
    if (session == nullptr) {
        return nullptr;
    }
    session->SetPid(GetCallingPid());
    session->SetUid(GetCallingUid());
    if (sessionContainer_ != nullptr) {
        if (sessionContainer_->AddSession(session->GetPid(), session) != AVSESSION_SUCCESS) {
            return nullptr;
        }
    }

    return session;
}

sptr<IRemoteObject> AVSessionService::GetSessionInner()
{
    return {};
}

std::vector<AVSessionDescriptor> AVSessionService::GetAllSessionDescriptors()
{
    return {};
}

sptr<IRemoteObject> AVSessionService::CreateControllerInner(int32_t sessionId)
{
    return nullptr;
}

sptr<IRemoteObject> AVSessionService::GetControllerInner(int32_t sessionId)
{
    return nullptr;
}

std::vector<sptr<IRemoteObject>> AVSessionService::GetAllControllersInner()
{
    return {};
}

int32_t AVSessionService::RegisterSessionListener(const sptr<ISessionListener>& listener)
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

int32_t AVSessionService::RegisterClientDeathObserver(const sptr<IClientDeath>& observer)
{
    return 0;
}

void AVSessionService::OnClientDied(pid_t pid)
{
}
} // namespace OHOS::AVSession