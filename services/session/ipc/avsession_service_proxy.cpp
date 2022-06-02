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

#include "avsession_service_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_proxy.h"
#include "avsession_controller_proxy.h"

namespace OHOS::AVSession {
AVSessionServiceProxy::AVSessionServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVSessionService>(impl)
{
    SLOGD("constructor");
}

std::shared_ptr<AVSession> AVSessionServiceProxy::CreateSession(const std::string& tag, int32_t type,
    const std::string& bundleName, const std::string& abilityName)
{
    auto object = CreateSessionInner(tag, type, bundleName, abilityName);
    if (object == nullptr) {
        SLOGE("object is nullptr");
        return nullptr;
    }
    auto session = iface_cast<AVSessionProxy>(object);
    if (session == nullptr) {
        SLOGE("session is nullptr");
        return nullptr;
    }
    return std::shared_ptr<AVSession>(session.GetRefPtr(), [holder = session](const auto*) {});
}

sptr<IRemoteObject> AVSessionServiceProxy::CreateSessionInner(const std::string& tag, int32_t type,
    const std::string& bundleName, const std::string& abilityName)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), nullptr, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(tag), nullptr, "write tag failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(type), nullptr, "write type failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(bundleName), nullptr, "write bundleName failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(abilityName), nullptr, "write abilityName failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_CREATE_SESSION, data, reply, option) == 0,
                             nullptr, "send request failed");
    return reply.ReadRemoteObject();
}

std::vector<AVSessionDescriptor> AVSessionServiceProxy::GetAllSessionDescriptors()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), {}, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS, data, reply, option) == 0,
                             {}, "send request failed");

    uint32_t size {};
    if (!reply.ReadUint32(size)) {
        SLOGE("read vector size failed");
        return {};
    }
    if (!size) {
        SLOGI("size=0");
        return {};
    }

    std::vector<AVSessionDescriptor> result(size);
    for (auto& descriptor : result) {
        if (!descriptor.ReadFromParcel(reply)) {
            return {};
        }
    }
    return result;
}

std::shared_ptr<AVSessionController> AVSessionServiceProxy::CreateController(int32_t sessionId)
{
    auto object = CreateControllerInner(sessionId);
    if (object == nullptr) {
        SLOGE("object is nullptr");
        return nullptr;
    }
    auto controller = iface_cast<AVSessionControllerProxy>(object);
    if (controller == nullptr) {
        SLOGE("controller is nullptr");
        return nullptr;
    }
    return std::shared_ptr<AVSessionController>(controller.GetRefPtr(), [holder = controller](const auto*) {});
}

sptr<IRemoteObject> AVSessionServiceProxy::CreateControllerInner(int32_t sessionId)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), nullptr, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(sessionId), nullptr, "write sessionId failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_CREATE_CONTROLLER, data, reply, option) == 0,
                             nullptr, "send request failed");
    return reply.ReadRemoteObject();
}

int32_t AVSessionServiceProxy::RegisterSessionListener(const sptr<ISessionListener>& listener)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(listener->AsObject()), ERR_MARSHALLING, "write tag failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_REGISTER_SESSION_LISTENER, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::SendSystemMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(keyEvent.WriteToParcel(data), ERR_MARSHALLING, "write keyEvent failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_SEND_SYSTEM_MEDIA_KEY_EVENT, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::SendSystemControlCommand(const AVControlCommand &command)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&command), ERR_MARSHALLING, "write keyEvent failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_SEND_SYSTEM_CONTROL_COMMAND, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::RegisterClientDeathObserver(const sptr<IClientDeath>& observer)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(observer->AsObject()), ERR_MARSHALLING, "write observer failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_REGISTER_CLIENT_DEATH, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}
} // namespace OHOS::AVSession