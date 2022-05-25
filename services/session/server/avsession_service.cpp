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

sptr<AVControllerItem> AVSessionService::GetPresentController(pid_t pid, int32_t sessionId)
{
    std::lock_guard lockGuard(lock_);
    auto it = controllers_.find(pid);
    if (it == controllers_.end()) {
        return nullptr;
    }

    for (const auto& controller: it->second) {
        if (controller->HasSession(sessionId)) {
            return controller;
        }
    }
    return nullptr;
}

void AVSessionService::NotifySessionCreate(const AVSessionDescriptor &descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& [pid, listener] : sessionListeners_) {
        listener->OnSessionCreate(descriptor);
    }
}

void AVSessionService::NotifySessionRelease(const AVSessionDescriptor &descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& [pid, listener] : sessionListeners_) {
        listener->OnSessionRelease(descriptor);
    }
}

sptr<IRemoteObject>  AVSessionService::CreateSessionInner(const std::string& tag, int32_t type,
    const std::string& bundleName, const std::string& abilityName)
{
    if (sessionContainer_ == nullptr) {
        return nullptr;
    }

    auto pid = GetCallingPid();
    std::lock_guard lockGuard(lock_);
    if (sessionContainer_->GetSession(pid) != nullptr) {
        SLOGE("%{public}d already has a session", pid);
        return nullptr;
    }

    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = AllocSessionId();
    descriptor.sessionTag_ = tag;
    descriptor.sessionType_ = type;
    descriptor.bundleName_ = bundleName;
    descriptor.abilityName_ = abilityName;

    sptr<AVSessionItem> result = new(std::nothrow) AVSessionItem(descriptor);
    if (result == nullptr) {
        return nullptr;
    }
    result->SetPid(pid);
    result->SetUid(GetCallingUid());
    result->SetServiceCallbackForRelease([this](AVSessionItem& session) { SessionRelease(session); });

    if (sessionContainer_->AddSession(pid, result) != AVSESSION_SUCCESS) {
        SLOGE("session num exceed max");
        return nullptr;
    }

    NotifySessionCreate(descriptor);
    SLOGI("success");
    return result;
}

sptr<IRemoteObject> AVSessionService::GetSessionInner()
{
    return {};
}

std::vector<AVSessionDescriptor> AVSessionService::GetAllSessionDescriptors()
{
    if (sessionContainer_ == nullptr) {
        return {};
    }

    std::vector<AVSessionDescriptor> result;
    std::lock_guard lockGuard(lock_);
    for (const auto& session: sessionContainer_->GetAllSessions()) {
        result.push_back(session->GetDescriptor());
    }
    return result;
}

sptr<IRemoteObject> AVSessionService::CreateControllerInner(int32_t sessionId)
{
    if (sessionContainer_ == nullptr) {
        return nullptr;
    }

    auto pid = GetCallingPid();
    std::lock_guard lockGuard(lock_);
    if (GetPresentController(pid, sessionId) != nullptr) {
        SLOGI("controller already exist");
        return nullptr;
    }

    auto session = sessionContainer_->GetSessionById(sessionId);
    if (session == nullptr) {
        SLOGE("not find session %{public}d", sessionId);
        return nullptr;
    }

    sptr<AVControllerItem> result = new(std::nothrow) AVControllerItem(pid, session);
    if (result == nullptr) {
        SLOGE("malloc controller failed");
        return nullptr;
    }
    result->SetServiceCallbackForRelease([this](AVControllerItem& controller) { ControllerRelease(controller); });

    if (controllers_.find(pid) != controllers_.end()) {
        controllers_[pid].push_back(result);
    } else {
        std::list<sptr<AVControllerItem>> list( {result} );
        controllers_[pid] = std::move(list);
    }
    session->AddController(pid, result);
    SLOGI("success");
    return result;
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
    if (!sessionContainer_) {
        return;
    }
    {
        std::lock_guard lockGuard(sessionListenersLock_);
        sessionListeners_.erase(pid);
    }

    std::lock_guard lockGuard(lock_);
    auto session = sessionContainer_->RemoveSession(pid);
    std::list<sptr<AVControllerItem>> controllers;
    auto it = controllers_.find(pid);
    if (it != controllers_.end()) {
        controllers = std::move(it->second);
        controllers_.erase(it);
    }

    if (session != nullptr) {
        NotifySessionRelease(session->GetDescriptor());
        session->BeKilled();
    }
    if (!controllers.empty()) {
        for (const auto& controller : controllers) {
            controller->BeKilled();
        }
    }
}

void AVSessionService::SessionRelease(AVSessionItem &session)
{
    NotifySessionRelease(session.GetDescriptor());
    std::lock_guard lockGuard(lock_);
    sessionContainer_->RemoveSession(session.GetPid());
}

void AVSessionService::ControllerRelease(AVControllerItem &controller)
{
    auto pid = controller.GetPid();
    std::lock_guard lockGuard(lock_);
    auto list = controllers_[pid];
    list.remove(&controller);
    if (list.empty()) {
        controllers_.erase(pid);
    }
}
} // namespace OHOS::AVSession