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

#ifndef OHOS_IAVSESSION_SERVICE_H
#define OHOS_IAVSESSION_SERVICE_H

#include "iremote_broker.h"
#include "iavsession.h"
#include "isession_listener.h"

namespace OHOS::AVSession {
class IAVSessionService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.avsession.IAVSessionService");

    enum {
        SERVICE_CMD_CREATE_TABLE,
        SERVICE_CMD_REGISTER_SESSION_LISTENER,
        SERVICE_CMD_MAX
    };

    virtual sptr<IRemoteObject> CreateSessionInner(const std::string& tag) = 0;

    virtual int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_IAVSESSION_SERVICE_H