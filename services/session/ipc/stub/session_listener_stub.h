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

#ifndef OHOS_SESSION_LISTENER_STUB_H
#define OHOS_SESSION_LISTENER_STUB_H

#include "iremote_stub.h"
#include "isession_listener.h"

namespace OHOS::AVSession {
class SessionListenerStub : public IRemoteStub<ISessionListener> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    int32_t HandleOnSessionCreate(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnSessionRelease(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnTopSessionChange(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = int32_t(SessionListenerStub::*)(MessageParcel&, MessageParcel&);
    static inline HandlerFunc handlers[] = {
        [LISTENER_CMD_ON_CREATE] = &SessionListenerStub::HandleOnSessionCreate,
        [LISTENER_CMD_ON_RELEASE] = &SessionListenerStub::HandleOnSessionRelease,
        [LISTENER_CMD_TOP_CHANGED] = &SessionListenerStub::HandleOnTopSessionChange,
    };
};
}
#endif // OHOS_SESSION_LISTENER_STUB_H