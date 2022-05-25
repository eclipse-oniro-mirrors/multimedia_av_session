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

#include <utility>
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

sptr<AVSessionItem> AVSessionService::CreateNewSession(const std::string &tag, int32_t type,
                                                       const std::string &bundleName, const std::string &abilityName)
{
    SLOGI("%{public}s", tag.c_str());
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
    result->SetPid(GetCallingPid());
    result->SetUid(GetCallingUid());
    result->SetServiceCallbackForRelease([this](AVSessionItem& session) { SessionRelease(session); });
    return result;
}

sptr<IRemoteObject> AVSessionService::CreateSessionInner(const std::string& tag, int32_t type,
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

    auto result = CreateNewSession(tag, type, bundleName, abilityName);
    if (result == nullptr) {
        SLOGE("create new session failed");
        return nullptr;
    }
    if (sessionContainer_->AddSession(pid, result) != AVSESSION_SUCCESS) {
        SLOGE("session num exceed max");
        return nullptr;
    }

    NotifySessionCreate(result->GetDescriptor());
    SLOGI("success");
    return result;
}

sptr<IRemoteObject> AVSessionService::GetSessionInner()
{
    if (sessionContainer_ == nullptr) {
        return nullptr;
    }

    std::lock_guard lockGuard(lock_);
    return sessionContainer_->GetSession(GetCallingPid());
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

sptr<AVControllerItem> AVSessionService::CreateNewControllerForSession(pid_t pid, sptr<AVSessionItem> &session)
{
    SLOGI("pid=%{public}d sessionId=%{public}d", pid, session->GetSessionId());
    sptr<AVControllerItem> result = new(std::nothrow) AVControllerItem(pid, session);
    if (result == nullptr) {
        SLOGE("malloc controller failed");
        return nullptr;
    }
    result->SetServiceCallbackForRelease([this](AVControllerItem& controller) { ControllerRelease(controller); });
    session->AddController(pid, result);
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
        SLOGE("no session id %{public}d", sessionId);
        return nullptr;
    }

    auto result = CreateNewControllerForSession(pid, session);
    if (result == nullptr) {
        SLOGE("create new controller failed");
        return nullptr;
    }

    controllers_[pid].push_back(result);
    SLOGI("success");
    return result;
}

sptr<IRemoteObject> AVSessionService::GetControllerInner(int32_t sessionId)
{
    std::lock_guard lockGuard(lock_);
    auto it = controllers_.find(GetCallingPid());
    if (it == controllers_.end()) {
        SLOGE("not find");
        return nullptr;
    }
    for (const auto& controller : it->second) {
        if (controller->HasSession(sessionId)) {
            return controller;
        }
    }
    SLOGE("not find");
    return nullptr;
}

std::vector<sptr<IRemoteObject>> AVSessionService::GetAllControllersInner()
{
    std::vector<sptr<IRemoteObject>> result;
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, list]: controllers_) {
        for (const auto& controller : list) {
            result.emplace_back(controller);
        }
    }
    return result;
}

void AVSessionService::AddSessionListener(pid_t pid, const sptr<ISessionListener> &listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    sessionListeners_[pid] = listener;
}

void AVSessionService::RemoveSessionListener(pid_t pid)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    sessionListeners_.erase(pid);
}

int32_t AVSessionService::RegisterSessionListener(const sptr<ISessionListener>& listener)
{
    AddSessionListener(GetCallingPid(), listener);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::SendSystemMediaKeyEvent(MMI::KeyEvent& keyEvent)
{
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::SetSystemMediaVolume(int32_t volume)
{
    return 0;
}

void AVSessionService::AddClientDeathObserver(pid_t pid, const sptr<IClientDeath> &observer)
{
    std::lock_guard lockGuard(clientDeathObserversLock_);
    clientDeathObservers_[pid] = observer;
}

void AVSessionService::RemoveClientDeathObserver(pid_t pid)
{
    std::lock_guard lockGuard(clientDeathObserversLock_);
    clientDeathObservers_.erase(pid);
}

int32_t AVSessionService::RegisterClientDeathObserver(const sptr<IClientDeath>& observer)
{
    auto pid = GetCallingPid();
    auto* recipient = new(std::nothrow) ClientDeathRecipient([this, pid]() { OnClientDied(pid); });
    if (recipient == nullptr) {
        SLOGE("malloc failed");
        return AVSESSION_ERROR;
    }

    if (!observer->AsObject()->AddDeathRecipient(recipient)) {
        SLOGE("add death recipient for %{public}d failed", pid);
        return AVSESSION_ERROR;
    }

    AddClientDeathObserver(pid, observer);
    return AVSESSION_SUCCESS;
}

void AVSessionService::OnClientDied(pid_t pid)
{
    SLOGI("client die %{public}d", pid);
    RemoveSessionListener(pid);
    RemoveClientDeathObserver(pid);
    if (!sessionContainer_) {
        return;
    }

    std::lock_guard lockGuard(lock_);
    auto session = sessionContainer_->RemoveSession(pid);
    if (session != nullptr) {
        session->Release();
    }

    auto it = controllers_.find(pid);
    if (it != controllers_.end()) {
        auto controllers = std::move(it->second);
        controllers_.erase(it);
        if (!controllers.empty()) {
            for (const auto& controller : controllers) {
                controller->Release();
            }
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

ClientDeathRecipient::ClientDeathRecipient(const std::function<void()>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    if (callback_) {
        callback_();
    }
}
} // namespace OHOS::AVSession