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
#include "session_listener_stub.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
bool SessionListenerStub::CheckInterfaceToken(MessageParcel &data)
{
    auto localDescriptor = ISessionListener::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGE("interface token is not equal");
        return false;
    }
    return true;
}

int SessionListenerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                         MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= 0 && code < LISTENER_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int SessionListenerStub::HandleOnSessionCreate(MessageParcel &data, MessageParcel &reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::OnSessionCreate");
    AVSessionDescriptor descriptor;
    descriptor.ReadFromParcel(data);
    OnSessionCreate(descriptor);
    return ERR_NONE;
}

int SessionListenerStub::HandleOnSessionRelease(MessageParcel &data, MessageParcel &reply)
{
    AVSessionDescriptor descriptor;
    descriptor.ReadFromParcel(data);
    OnSessionRelease(descriptor);
    return ERR_NONE;
}

int SessionListenerStub::HandleOnTopSessionChange(MessageParcel &data, MessageParcel &reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::OnTopSessionChange");
    AVSessionDescriptor descriptor;
    descriptor.ReadFromParcel(data);
    OnTopSessionChange(descriptor);
    return ERR_NONE;
}
} // namespace OHOS::AVSession