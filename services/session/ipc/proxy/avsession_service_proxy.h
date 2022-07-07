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

#ifndef OHOS_AVSESSION_SERVICE_PROXY_H
#define OHOS_AVSESSION_SERVICE_PROXY_H

#include "iavsession_service.h"
#include "iremote_proxy.h"
#include "av_session.h"
#include "avsession_controller.h"

namespace OHOS::AVSession {
class AVSessionServiceProxy : public IRemoteProxy<IAVSessionService> {
public:
    explicit AVSessionServiceProxy(const sptr<IRemoteObject>& impl);

    std::shared_ptr<AVSession> CreateSession(const std::string& tag, int32_t type,
                                             const AppExecFwk::ElementName& elementName);

    sptr<IRemoteObject> CreateSessionInner(const std::string& tag, int32_t type,
                                           const AppExecFwk::ElementName& elementName) override;

    std::vector<AVSessionDescriptor> GetAllSessionDescriptors() override;

    std::shared_ptr<AVSessionController> CreateController(int32_t sessionId);

    sptr<IRemoteObject> CreateControllerInner(int32_t sessionId) override;

    int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) override;

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) override;

    int32_t SendSystemControlCommand(const AVControlCommand& command) override;

    int32_t RegisterClientDeathObserver(const sptr<IClientDeath>& observer) override;

private:
    static inline BrokerDelegator<AVSessionServiceProxy> delegator_;
};
} // namespace OHOS
#endif // OHOS_AVSESSION_SERVICE_PROXY_H