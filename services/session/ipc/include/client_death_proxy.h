/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_CLIENT_DEATH_PROXY_H
#define OHOS_CLIENT_DEATH_PROXY_H

#include "iclent_death.h"
#include "iremote_proxy.h"

namespace OHOS::AVSession {
class ClientDeathProxy : public IRemoteProxy<IClientDeath> {
public:
    explicit ClientDeathProxy(const sptr<IRemoteObject>& impl) {};

private:
    static inline BrokerDelegator<ClientDeathProxy> delegator_;
};
}// namespace OHOS::AVSession
#endif // OHOS_CLIENT_DEATH_PROXY_H