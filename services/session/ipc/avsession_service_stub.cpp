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

#include "avsession_service_stub.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "session_listener_proxy.h"
#include "client_death_proxy.h"

namespace OHOS::AVSession {
bool AVSessionServiceStub::CheckInterfaceToken(MessageParcel &data)
{
    auto localDescriptor = IAVSessionService::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGE("interface token is not equal");
        return false;
    }
    return true;
}

int AVSessionServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                          MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= 0 && code < SERVICE_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int AVSessionServiceStub::HandleCreateSessionInner(MessageParcel &data, MessageParcel &reply)
{
    auto session = CreateSessionInner(data.ReadString(), data.ReadInt32(), data.ReadString(), data.ReadString());
    reply.WriteRemoteObject(session);
    return ERR_NONE;
}

int AVSessionServiceStub::HandleGetSessionInner(MessageParcel &data, MessageParcel &reply)
{
    auto session = GetSessionInner(data.ReadString(), data.ReadString(), data.ReadString(), data.ReadString());
    reply.WriteRemoteObject(session);
    return ERR_NONE;
}

int AVSessionServiceStub::HandleGetAllSessionDescriptors(MessageParcel &data, MessageParcel &reply)
{
    auto sessionDescriptors = GetAllSessionDescriptors();
    reply.WriteRemoteObject(sessionDescriptors);
    return ERR_NONE;
}

int AVSessionServiceStub::HandleCreateControllerInner(MessageParcel &data, MessageParcel &reply)
{
    auto controller = CreateControllerInner(data.ReadInt32());
    reply.WriteRemoteObject(controller);
    return ERR_NONE;
}

int AVSessionServiceStub::HandleGetControllerInner(MessageParcel &data, MessageParcel &reply)
{
    auto controller = GetControllerInner(data.ReadInt32());
    reply.WriteRemoteObject(controller);
    return ERR_NONE;
}

int AVSessionServiceStub::HandleGetAllControllersInner(MessageParcel &data, MessageParcel &reply)
{
    auto controllers = GetAllControllersInner();
    reply.WriteRemoteObject(controllers);
    return ERR_NONE;
}

int AVSessionServiceStub::HandleRegisterSessionListener(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        reply.WriteInt32(AVSESSION_ERROR);
        return ERR_NONE;
    }
    auto listener = iface_cast<SessionListenerProxy>(remoteObject);
    return RegisterSessionListener(listener);
}


int AVSessionServiceStub::HandleSendSystemMediaKeyEvent(MessageParcel &data, MessageParcel &reply)
{
    return ERR_NONE;
}

int AVSessionServiceStub::HandleSetSystemMediaVolume(MessageParcel &data, MessageParcel &reply)
{
    return ERR_NONE;
}

int AVSessionServiceStub::HandleRegisterClientDeathObserver(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        reply.WriteInt32(AVSESSION_ERROR);
        return ERR_NONE;
    }
    auto clientDeathObserver = iface_cast<ClientDeathProxy>(remoteObject);
    return RegisterClientDeathObserver(clientDeathObserver);
}
} // namespace OHOS::AVSession