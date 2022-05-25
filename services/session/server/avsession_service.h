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

#ifndef OHOS_AVSESSION_SERVICE_H
#define OHOS_AVSESSION_SERVICE_H

#include <mutex>
#include <map>

#include "iremote_stub.h"
#include "system_ability.h"
#include "avsession_service_stub.h"
#include "avsession_item.h"
#include "avcontroller_item.h"
#include "session_container.h"
#include "iclient_death.h"
#include "isession_listener.h"

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

    sptr<IRemoteObject> CreateSessionInner(const std::string& tag, int32_t type,
                                           const std::string& bundleName, const std::string& abilityName) override;

    sptr<IRemoteObject> GetSessionInner() override;

    std::vector<AVSessionDescriptor> GetAllSessionDescriptors() override;

    sptr<IRemoteObject> CreateControllerInner(int32_t sessionId) override;

    sptr<IRemoteObject> GetControllerInner(int32_t sessionId) override;

    std::vector<sptr<IRemoteObject>> GetAllControllersInner() override;

    int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) override;

    int32_t SendSystemMediaKeyEvent(MMI::KeyEvent& keyEvent) override;

    int32_t SetSystemMediaVolume(int32_t volume) override;

    int32_t RegisterClientDeathObserver(const sptr<IClientDeath>& observer) override;

    void OnClientDied(pid_t pid);

    void SessionRelease(AVSessionItem& session);

    void ControllerRelease(AVControllerItem& controller);

private:
    int32_t AllocSessionId();

    sptr<AVControllerItem> GetPresentController(pid_t pid, int32_t sessionId);

    void NotifySessionCreate(const AVSessionDescriptor& descriptor);
    void NotifySessionRelease(const AVSessionDescriptor& descriptor);

    void AddClientDeathObserver(pid_t pid, const sptr<IClientDeath>& observer);
    void RemoveClientDeathObserver(pid_t pid);

    void AddSessionListener(pid_t pid, const sptr<ISessionListener>& listener);
    void RemoveSessionListener(pid_t pid);

    sptr<AVSessionItem> CreateNewSession(const std::string& tag, int32_t type,
                                         const std::string& bundleName, const std::string& abilityName);

    sptr<AVControllerItem> CreateNewControllerForSession(pid_t pid, sptr<AVSessionItem>& session);

    std::recursive_mutex sessionIdsLock_;
    std::list<int32_t> sessionIds_;
    int32_t sessionSeqNum_ {};

    std::recursive_mutex lock_;
    std::map<pid_t, std::list<sptr<AVControllerItem>>> controllers_;
    SessionContainer* sessionContainer_ {};

    std::recursive_mutex clientDeathObserversLock_;
    std::map<pid_t, sptr<IClientDeath>> clientDeathObservers_;

    std::recursive_mutex sessionListenersLock_;
    std::map<pid_t, sptr<ISessionListener>> sessionListeners_;
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