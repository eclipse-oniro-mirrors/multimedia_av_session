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

#ifndef OHOS_AVSESSION_MANAGER_IMPL_H
#define OHOS_AVSESSION_MANAGER_IMPL_H

#include <string>
#include <memory>
#include <mutex>

#include "iremote_object.h"
#include "avsession.h"
#include "avsession_service_proxy.h"
#include "avsession_info.h"
#include "client_death_stub.h"
#include "isession_listener.h"

namespace OHOS::AVSession {
class AVSessionManagerImpl {
public:
    static AVSessionManagerImpl& GetInstance();

    std::shared_ptr<AVSession> CreateSession(const std::string& tag, const std::string& type,
                                             const std::string& bundleName, const std::string& abilityName);

    std::shard_ptr<AVSession> GetSession();

    std::vector<AVSessionDescriptor> GetAllSessionDescriptors();

    std::shared_ptr<AVSessionController> CreateController(int32_t sessionld);

    std::shared_ptr<AVSessionController> GetController(int32_t sessionld);

    std::vector<std::shared_ptr<AVSessionController>> GetAllControllers();

    int32_t RegisterSessionListener(std::shared_ptr<SessionListener>& listener);

    using DeathCallback = std::function<void>;

    int32_t RegisterServiceDeathCallback(const DeathCallback& callback);

    int32_t SendSystemMediaKeyEvent(KeyEvent& keyEvent);

    int32_t SetSystemMediaVolume(int32_t volume);

private:
    class DeathRecipientImpl : public IRemoteObject::DeathRecipient {
    public:
        explicit DeathRecipientImpl(const DeathCallback& callback);
        ~DeathRecipientImpl() override;
        void OnRemoteDied(const wptr<IRemoteObject> &object) override;
    private:
        const DeathCallback callback_;
    };

    AVSessionManagerImpl();

    sptr<AVSessionServiceProxy> GetService();

    void OnServiceDied();

    int32_t RegesterClientDeathObserver();

    std::mutex lock_;
    sptr<AVSessionServiceProxy> service_;
    sptr<ISessionListener> listener_;
    sptr<ClientDeathStub> clientDeath_;
    DeathCallback deathCallback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_MANAGER_IMPL_H