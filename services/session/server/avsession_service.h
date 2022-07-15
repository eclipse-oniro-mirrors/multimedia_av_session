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

#ifndef OHOS_AVSESSION_SERVICE_H
#define OHOS_AVSESSION_SERVICE_H

#include <atomic>
#include <mutex>
#include <map>

#include "iremote_stub.h"
#include "system_ability.h"
#include "avsession_dumper.h"
#include "avsession_service_stub.h"
#include "avsession_item.h"
#include "avcontroller_item.h"
#include "session_container.h"
#include "iclient_death.h"
#include "isession_listener.h"
#include "focus_session_strategy.h"

namespace OHOS::AVSession {
class AVSessionService : public SystemAbility, public AVSessionServiceStub {
    DECLARE_SYSTEM_ABILITY(AVSessionService);

public:
    DISALLOW_COPY_AND_MOVE(AVSessionService);

    explicit AVSessionService(int32_t systemAbilityId, bool runOnCreate = true);

    ~AVSessionService() override;

    void OnDump() override;

    void OnStart() override;

    void OnStop() override;

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

    sptr<IRemoteObject> CreateSessionInner(const std::string& tag, int32_t type,
                                           const AppExecFwk::ElementName& elementName) override;

    std::vector<AVSessionDescriptor> GetAllSessionDescriptors() override;

    int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId, AVSessionDescriptor& descriptor) override;

    sptr<IRemoteObject> CreateControllerInner(const std::string& sessionId) override;

    int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) override;

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) override;

    int32_t SendSystemControlCommand(const AVControlCommand& command) override;

    int32_t RegisterClientDeathObserver(const sptr<IClientDeath>& observer) override;

    void OnClientDied(pid_t pid);

    void HandleSessionRelease(AVSessionItem& session);

    void HandleControllerRelease(AVControllerItem& controller);

    std::int32_t Dump(std::int32_t fd, const std::vector<std::u16string> &args) override;

private:
    static SessionContainer& GetContainer();

    std::string AllocSessionId();

    bool AbilityHasSession(pid_t pid, const std::string& abilityName);

    sptr<AVControllerItem> GetPresentController(pid_t pid, const std::string& sessionId);

    void NotifySessionCreate(const AVSessionDescriptor& descriptor);
    void NotifySessionRelease(const AVSessionDescriptor& descriptor);
    void NotifyTopSessionChanged(const AVSessionDescriptor& descriptor);

    void AddClientDeathObserver(pid_t pid, const sptr<IClientDeath>& observer);
    void RemoveClientDeathObserver(pid_t pid);

    void AddSessionListener(pid_t pid, const sptr<ISessionListener>& listener);
    void RemoveSessionListener(pid_t pid);

    sptr<AVSessionItem> CreateNewSession(const std::string& tag, int32_t type,
                                         const AppExecFwk::ElementName& elementName);

    sptr<AVControllerItem> CreateNewControllerForSession(pid_t pid, sptr<AVSessionItem>& session);

    void ClearSessionForClientDiedNoLock(pid_t pid);

    void ClearControllerForClientDiedNoLock(pid_t pid);

    void InitKeyEvent();

    void InitFocusSessionStrategy();

    bool SelectFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo& info);

    void UpdateTopSession(const sptr<AVSessionItem>& newTopSession);

    void HandleFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo& info);

    std::atomic<uint32_t> sessionSeqNum_ {};

    std::recursive_mutex sessionAndControllerLock_;
    sptr<AVSessionItem> topSession_;
    std::map<pid_t, std::list<sptr<AVControllerItem>>> controllers_;

    std::recursive_mutex clientDeathObserversLock_;
    std::map<pid_t, sptr<IClientDeath>> clientDeathObservers_;

    std::recursive_mutex sessionListenersLock_;
    std::map<pid_t, sptr<ISessionListener>> sessionListeners_;

    FocusSessionStrategy focusSessionStrategy_;

    std::unique_ptr<AVSessionDumper> dumpHelper_ {};
};

class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit ClientDeathRecipient(const std::function<void()>& callback);

    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

private:
    std::function<void()> callback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVICE_H