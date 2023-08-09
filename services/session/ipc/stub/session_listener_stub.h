/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

    int32_t HandleOnAudioSessionChecked(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnDeviceAvailable(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnDeviceOffline(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = int32_t(SessionListenerStub::*)(MessageParcel&, MessageParcel&);
    static inline HandlerFunc handlers[] = {
        &SessionListenerStub::HandleOnSessionCreate,
        &SessionListenerStub::HandleOnSessionRelease,
        &SessionListenerStub::HandleOnTopSessionChange,
        &SessionListenerStub::HandleOnAudioSessionChecked,
        &SessionListenerStub::HandleOnDeviceAvailable,
        &SessionListenerStub::HandleOnDeviceOffline,
    };
};
}
#endif // OHOS_SESSION_LISTENER_STUB_H