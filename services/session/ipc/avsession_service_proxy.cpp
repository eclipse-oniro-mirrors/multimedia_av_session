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
    auto session = iface_cast<AVSessionProxy>(object);
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

std::shared_ptr<AVSession> AVSessionServiceProxy::GetSession()
{
    auto remoteObject = GetSessionInner();
    auto session = iface_cast<AVSessionProxy>(remoteObject);
    return std::shared_ptr<AVSession>(session.GetRefPtr(), [holder = session](const auto*) {});
}

sptr<IRemoteObject> AVSessionServiceProxy::GetSessionInner()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), nullptr, "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_GET_SESSION, data, reply, option) == 0,
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
    return {};
}

std::shared_ptr<AVSessionController> AVSessionServiceProxy::CreateController(int32_t sessionId)
{
    auto remoteObject = CreateControllerInner(sessionId);
    auto controller = iface_cast<AVSessionControllerProxy>(remoteObject);
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

std::shared_ptr<AVSessionController> AVSessionServiceProxy::GetController(int32_t sessionId)
{
    auto remoteObject = GetControllerInner(sessionId);
    auto controller = iface_cast<AVSessionControllerProxy>(remoteObject);
    return std::shared_ptr<AVSessionController>(controller.GetRefPtr(), [holder = controller](const auto*) {});
}

sptr<IRemoteObject> AVSessionServiceProxy::GetControllerInner(int32_t sessionId)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), nullptr, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(sessionId), nullptr, "write sessionId failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_GET_CONTROLLER, data, reply, option) == 0,
                             nullptr, "send request failed");
    return reply.ReadRemoteObject();
}

std::vector<std::shared_ptr<AVSessionController>> AVSessionServiceProxy::GetAllControllers()
{
    std::vector<std::shared_ptr<AVSessionController>> sessionControllers;
    auto controls = GetAllControllersInner();
    for (auto& control : controls) {
        auto sessionController = iface_cast<AVSessionControllerProxy>(control);
        sessionControllers.push_back(std::shared_ptr<AVSessionController>(
            sessionController.GetRefPtr(), [holder = sessionController](const auto*) {}));
    }
    return sessionControllers;
}

std::vector<sptr<IRemoteObject>> AVSessionServiceProxy::GetAllControllersInner()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), {}, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_GET_ALL_CONTROLLERS, data, reply, option) == 0,
                             {}, "send request failed");
    return {};
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

int32_t AVSessionServiceProxy::SendSystemMediaKeyEvent(MMI::KeyEvent& keyEvent)
{
    return AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::SetSystemMediaVolume(int32_t volume)
{
    return AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::RegisterClientDeathObserver(const sptr<IClientDeath>& observer)
{
    return AVSESSION_ERROR;
}
} // namespace OHOS::AVSession