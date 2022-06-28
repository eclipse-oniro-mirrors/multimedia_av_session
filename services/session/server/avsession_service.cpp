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

#include "avsession_service.h"

#include <utility>
#include "avsession_errors.h"
#include "avsession_log.h"
#include "iservice_registry.h"
#include "key_event_adapter.h"
#include "system_ability_definition.h"
#include "session_stack.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
REGISTER_SYSTEM_ABILITY_BY_ID(AVSessionService, AVSESSION_SERVICE_ID, true);

AVSessionService::AVSessionService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
    SLOGD("construct");
    dumpHelper_ = std::make_unique<AVSessionDumper>();
}

AVSessionService::~AVSessionService()
{
    SLOGD("destroy");
}

void AVSessionService::OnStart()
{
    if (!Publish(this)) {
        SLOGE("publish avsession service failed");
    }

    AddSystemAbilityListener(MULTIMODAL_INPUT_SERVICE_ID);
    AddSystemAbilityListener(AUDIO_POLICY_SERVICE_ID);
}

void AVSessionService::OnDump()
{
}

void AVSessionService::OnStop()
{
}

void AVSessionService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    switch (systemAbilityId) {
        case MULTIMODAL_INPUT_SERVICE_ID:
            InitKeyEvent();
            break;
        case AUDIO_POLICY_SERVICE_ID:
            InitFocusSessionStrategy();
            break;
        default:
            SLOGE("undefined system ability %{public}d", systemAbilityId);
    }
}

void AVSessionService::InitKeyEvent()
{
    SLOGI("enter");
    std::vector<int32_t> keyCodes = {
        MMI::KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE,
        MMI::KeyEvent::KEYCODE_MEDIA_STOP,
        MMI::KeyEvent::KEYCODE_MEDIA_NEXT,
        MMI::KeyEvent::KEYCODE_MEDIA_PREVIOUS,
        MMI::KeyEvent::KEYCODE_MEDIA_REWIND,
        MMI::KeyEvent::KEYCODE_MEDIA_FAST_FORWARD,
    };

    KeyEventAdapter::GetInstance().SubscribeKeyEvent(
        keyCodes, [this](const auto& keyEvent) { SendSystemAVKeyEvent(*keyEvent); });
}

void AVSessionService::HandleTopSessionChanged(const FocusSessionStrategy::FocusSessionChangeInfo &info)
{
    bool found {};
    {
        std::lock_guard lockGuard(sessionAndControllerLock_);
        for (const auto& session : GetContainer().GetAllSessions()) {
            if (session->GetUid() == info.uid) {
                topSession_ = session;
                found = true;
                break;
            }
        }
    }
    if (found) {
        SLOGI("sessionTag=%{public}s sessionId=%{public}d", topSession_->GetDescriptor().sessionTag_.c_str(),
              topSession_->GetDescriptor().sessionId_);
        NotifyTopSessionChanged(topSession_->GetDescriptor());
    }
}

void AVSessionService::InitFocusSessionStrategy()
{
    SLOGI("enter");
    focusSessionStrategy_.Init();
    focusSessionStrategy_.RegisterFocusSessionChangeCallback([this] (const auto &info) {
        HandleTopSessionChanged(info);
    });
}

SessionContainer& AVSessionService::GetContainer()
{
    static SessionStack sessionStack;
    return sessionStack;
}

int32_t AVSessionService::AllocSessionId()
{
    std::lock_guard lockGuard(sessionIdsLock_);
    while (true) {
        auto it = std::find_if(sessionIds_.begin(), sessionIds_.end(),
                               [this](const auto id) { return id == sessionSeqNum_; });
        if (it == sessionIds_.end()) {
            sessionIds_.push_back(sessionSeqNum_);
            SLOGI("sessionId=%{public}d", sessionSeqNum_);
            return sessionSeqNum_;
        }
        if (++sessionSeqNum_ < 0) {
            sessionSeqNum_ = 0;
        }
    }
}

bool AVSessionService::ClientHasSession(pid_t pid)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    return GetContainer().GetSession(pid) != nullptr;
}

sptr<AVControllerItem> AVSessionService::GetPresentController(pid_t pid, int32_t sessionId)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    auto it = controllers_.find(pid);
    if (it != controllers_.end()) {
        for (const auto &controller: it->second) {
            if (controller->HasSession(sessionId)) {
                return controller;
            }
        }
    }
    SLOGE("not found");
    return nullptr;
}

void AVSessionService::NotifySessionCreate(const AVSessionDescriptor &descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& [pid, listener] : sessionListeners_) {
        AVSessionTrace::TraceBegin("SessionListener_OnSessionCreate", ON_SESSION_CREATE_TASK_ID);
        listener->OnSessionCreate(descriptor);
    }
}

void AVSessionService::NotifySessionRelease(const AVSessionDescriptor &descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& [pid, listener] : sessionListeners_) {
        AVSessionTrace::TraceBegin("SessionListener_OnSessionRelease", ON_SESSION_RELEASE_TASK_ID);
        listener->OnSessionRelease(descriptor);
    }
}

void AVSessionService::NotifyTopSessionChanged(const AVSessionDescriptor &descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& [pid, listener] : sessionListeners_) {
        AVSessionTrace::TraceBegin("SessionListener_OnTopSessionChanged", ON_SESSION_RELEASE_TASK_ID);
        listener->OnTopSessionChanged(descriptor);
    }
}

sptr<AVSessionItem> AVSessionService::CreateNewSession(const std::string &tag, int32_t type,
                                                       const AppExecFwk::ElementName& elementName)
{
    SLOGI("%{public}s %{public}d %{public}s %{public}s", tag.c_str(), type,
          elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = AllocSessionId();
    descriptor.sessionTag_ = tag;
    descriptor.sessionType_ = type;
    descriptor.elementName_ = elementName;

    sptr<AVSessionItem> result = new(std::nothrow) AVSessionItem(descriptor);
    if (result == nullptr) {
        return nullptr;
    }
    result->SetPid(GetCallingPid());
    result->SetUid(GetCallingUid());
    result->SetServiceCallbackForRelease([this](AVSessionItem& session) { HandleSessionRelease(session); });
    SLOGI("success sessionId=%{public}d", result->GetSessionId());
    return result;
}

sptr<IRemoteObject> AVSessionService::CreateSessionInner(const std::string& tag, int32_t type,
                                                         const AppExecFwk::ElementName& elementName)
{
    AVSessionTrace mAVSessionTrace("AVSessionService::CreateSessionInner");
    SLOGI("enter");
    auto pid = GetCallingPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (ClientHasSession(pid)) {
        SLOGE("%{public}d already has a session", pid);
        return nullptr;
    }

    auto result = CreateNewSession(tag, type, elementName);
    if (result == nullptr) {
        SLOGE("create new session failed");
        return nullptr;
    }
    if (GetContainer().AddSession(pid, result) != AVSESSION_SUCCESS) {
        SLOGE("session num exceed max");
        return nullptr;
    }

    NotifySessionCreate(result->GetDescriptor());
    SLOGI("success");
    return result;
}

std::vector<AVSessionDescriptor> AVSessionService::GetAllSessionDescriptors()
{
    AVSessionTrace mAVSessionTrace("AVSessionService::GetAllSessionDescriptors");
    std::vector<AVSessionDescriptor> result;
    std::lock_guard lockGuard(sessionAndControllerLock_);
    for (const auto& session: GetContainer().GetAllSessions()) {
        result.push_back(session->GetDescriptor());
    }
    SLOGI("size=%{public}d", static_cast<int>(result.size()));
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
    result->SetServiceCallbackForRelease([this](AVControllerItem& controller) { HandleControllerRelease(controller); });
    session->AddController(pid, result);
    return result;
}

sptr<IRemoteObject> AVSessionService::CreateControllerInner(int32_t sessionId)
{
    AVSessionTrace mAVSessionTrace("AVSessionService::CreateControllerInner");
    auto pid = GetCallingPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (GetPresentController(pid, sessionId) != nullptr) {
        SLOGI("controller already exist");
        return nullptr;
    }

    auto session = GetContainer().GetSessionById(sessionId);
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
    SLOGI("enter");
    AddSessionListener(GetCallingPid(), listener);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSessionTrace mAVSessionTrace("AVSessionService::SendSystemAVKeyEvent");
    SLOGI("key=%{public}d", keyEvent.GetKeyCode());
    if (topSession_) {
        topSession_->HandleMediaKeyEvent(keyEvent);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::SendSystemControlCommand(const AVControlCommand &command)
{
    AVSessionTrace mAVSessionTrace("AVSessionService::SendSystemControlCommand");
    SLOGI("cmd=%{public}d", command.GetCommand());
    if (topSession_) {
        topSession_->ExecuteControllerCommand(command);
    }
    return AVSESSION_SUCCESS;
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
    SLOGI("enter");
    auto pid = GetCallingPid();
    AVSessionTrace::TraceBegin("AVSessionService_OnClientDied", ON_SESSION_SERVICE_CLIENT_DIED_TASK_ID);
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
    AVSessionTrace::TraceEnd("AVSessionService_OnClientDied", ON_SESSION_SERVICE_CLIENT_DIED_TASK_ID);
    SLOGI("pid=%{public}d", pid);
    RemoveSessionListener(pid);
    RemoveClientDeathObserver(pid);

    std::lock_guard lockGuard(sessionAndControllerLock_);
    ClearSessionForClientDiedNoLock(pid);
    ClearControllerForClientDiedNoLock(pid);
}

void AVSessionService::HandleSessionRelease(AVSessionItem &session)
{
    SLOGI("sessionId=%{public}d", session.GetSessionId());
    NotifySessionRelease(session.GetDescriptor());
    std::lock_guard lockGuard(sessionAndControllerLock_);
    GetContainer().RemoveSession(session.GetPid());
}

void AVSessionService::HandleControllerRelease(AVControllerItem &controller)
{
    auto pid = controller.GetPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    auto it = controllers_.find(pid);
    if (it == controllers_.end()) {
        return;
    }
    SLOGI("remove controller");
    it->second.remove(&controller);
    if (it->second.empty()) {
        controllers_.erase(pid);
    }
}

std::int32_t AVSessionService::Dump(std::int32_t fd, const std::vector<std::u16string> &args)
{
    if (fd < 0) {
        SLOGE("dump fd invalid");
        return ERR_INVALID_PARAM;
    }

    if (dumpHelper_ == nullptr) {
        SLOGE("dumpHelper_ is nullptr!");
        return ERR_INVALID_PARAM;
    }

    std::vector<std::string> argsInStr;
    for (const auto &arg : args) {
        SLOGD("Dump args: %s", Str16ToStr8(arg).c_str());
        argsInStr.emplace_back(Str16ToStr8(arg));
    }

    std::string result;
    dumpHelper_->Dump(argsInStr, result, controllers_);
    std::int32_t ret = dprintf(fd, "%s", result.c_str());
    if (ret < 0) {
        SLOGE("dprintf to dump fd failed");
        return ERR_INVALID_PARAM;
    }
    return AVSESSION_SUCCESS;
}

void AVSessionService::ClearSessionForClientDiedNoLock(pid_t pid)
{
    auto session = GetContainer().RemoveSession(pid);
    if (session != nullptr) {
        SLOGI("remove sessionId=%{public}d", session->GetSessionId());
        session->Destroy();
    }
}

void AVSessionService::ClearControllerForClientDiedNoLock(pid_t pid)
{
    auto it = controllers_.find(pid);
    if (it != controllers_.end()) {
        auto controllers = std::move(it->second);
        SLOGI("remove controllers size=%{public}d", static_cast<int>(controllers.size()));
        controllers_.erase(it);
        if (!controllers.empty()) {
            for (const auto& controller : controllers) {
                controller->Destroy();
            }
        }
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