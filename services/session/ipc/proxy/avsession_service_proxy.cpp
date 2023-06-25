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

#include "avsession_service_proxy.h"
#include "avsession_log.h"
#include "avsession_proxy.h"
#include "avsession_controller_proxy.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "avcast_controller_proxy.h"
#endif

namespace OHOS::AVSession {
AVSessionServiceProxy::AVSessionServiceProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVSessionService>(impl)
{
    SLOGI("constructor");
}

std::shared_ptr<AVSession> AVSessionServiceProxy::CreateSession(const std::string& tag, int32_t type,
                                                                const AppExecFwk::ElementName& elementName)
{
    auto object = CreateSessionInner(tag, type, elementName);
    if (object == nullptr) {
        SLOGI("object is nullptr");
        return nullptr;
    }
    auto session = iface_cast<AVSessionProxy>(object);
    if (session == nullptr) {
        SLOGI("session is nullptr");
        return nullptr;
    }
    return std::shared_ptr<AVSession>(session.GetRefPtr(), [holder = session](const auto*) {});
}

sptr<IRemoteObject> AVSessionServiceProxy::CreateSessionInner(const std::string& tag, int32_t type,
                                                              const AppExecFwk::ElementName& elementName)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), nullptr, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(tag), nullptr, "write tag failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(type), nullptr, "write type failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&elementName), nullptr, "write bundleName failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_CREATE_SESSION, data, reply, option) == 0,
                             nullptr, "send request failed");

    int32_t res = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(res), nullptr, "read res failed");

    return res == AVSESSION_SUCCESS ? reply.ReadRemoteObject() : nullptr;
}

int32_t AVSessionServiceProxy::GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        uint32_t size {};
        CHECK_AND_RETURN_RET_LOG(reply.ReadUint32(size), ERR_UNMARSHALLING, "read vector size failed");
        CHECK_AND_RETURN_RET_LOG(size, ret, "size=0");

        std::vector<AVSessionDescriptor> result(size);
        for (auto& descriptor : result) {
            CHECK_AND_RETURN_RET_LOG(descriptor.ReadFromParcel(reply), ERR_UNMARSHALLING, "read descriptor failed");
        }
        descriptors = result;
    }
    return ret;
}

int32_t AVSessionServiceProxy::GetSessionDescriptorsBySessionId(const std::string& sessionId,
    AVSessionDescriptor& descriptor)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(sessionId), ERR_MARSHALLING, "write sessionId failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_GET_SESSION_DESCRIPTORS_BY_ID, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(descriptor.ReadFromParcel(reply), ERR_UNMARSHALLING, "read descriptor failed");
    }
    return ret;
}

int32_t AVSessionServiceProxy::GetHistoricalSessionDescriptors(int32_t maxSize,
    std::vector<AVSessionDescriptor>& descriptors)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(maxSize), ERR_MARSHALLING, "write maxSize failed");
    
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_GET_HISTORY_SESSION_DESCRIPTORS, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        uint32_t size {};
        CHECK_AND_RETURN_RET_LOG(reply.ReadUint32(size), ERR_UNMARSHALLING, "read vector size failed");
        CHECK_AND_RETURN_RET_LOG(size, ret, "size=0");

        std::vector<AVSessionDescriptor> result(size);
        for (auto& descriptor : result) {
            CHECK_AND_RETURN_RET_LOG(descriptor.ReadFromParcel(reply), ERR_UNMARSHALLING, "read descriptor failed");
        }
        descriptors = result;
    }
    return ret;
}

int32_t AVSessionServiceProxy::CreateController(const std::string& sessionId,
    std::shared_ptr<AVSessionController>& controller)
{
    sptr<IRemoteObject> object;
    auto ret = CreateControllerInner(sessionId, object);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CreateControllerInner failed");

    auto controllerObject = iface_cast<AVSessionControllerProxy>(object);
    CHECK_AND_RETURN_RET_LOG(controllerObject, AVSESSION_ERROR, "controllerObject is nullptr");

    controller = std::shared_ptr<AVSessionController>(controllerObject.GetRefPtr(),
        [holder = controllerObject](const auto*) {});
    return ret;
}

int32_t AVSessionServiceProxy::CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_UNMARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(sessionId), ERR_UNMARSHALLING, "write sessionId failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_CREATE_CONTROLLER, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        object = reply.ReadRemoteObject();
    }
    return ret;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionServiceProxy::GetAVCastController(const std::string& sessionId,
    std::shared_ptr<AVCastController>& castController)
{
    sptr<IRemoteObject> object;
    auto ret = GetAVCastControllerInner(sessionId, object);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CreateControllerInner failed");

    auto castControllerObject = iface_cast<AVCastControllerProxy>(object);
    CHECK_AND_RETURN_RET_LOG(castControllerObject, AVSESSION_ERROR, "castControllerObject is nullptr");

    castController = std::shared_ptr<AVCastController>(castControllerObject.GetRefPtr(),
        [holder = castControllerObject](const auto*) {});
    return ret;
}

int32_t AVSessionServiceProxy::GetAVCastControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_UNMARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(sessionId), ERR_UNMARSHALLING, "write sessionId failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_GET_AV_CAST_CONTROLLER, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        object = reply.ReadRemoteObject();
    }
    return ret;
}
#endif

int32_t AVSessionServiceProxy::RegisterSessionListener(const sptr<ISessionListener>& listener)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(listener->AsObject()), ERR_MARSHALLING, "write tag failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_REGISTER_SESSION_LISTENER, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(keyEvent.WriteToParcel(data), ERR_MARSHALLING, "write keyEvent failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_SEND_SYSTEM_AV_KEY_EVENT, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::SendSystemControlCommand(const AVControlCommand& command)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&command), ERR_MARSHALLING, "write keyEvent failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_SEND_SYSTEM_CONTROL_COMMAND, data, reply, option) == 0,
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

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_REGISTER_CLIENT_DEATH, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::CastAudio(const SessionToken& token,
                                         const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(token.sessionId), ERR_MARSHALLING, "write sessionId failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(token.pid), ERR_MARSHALLING, "write pid failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(token.uid), ERR_MARSHALLING, "write uid failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(static_cast<int32_t>(descriptors.size())), ERR_MARSHALLING,
                             "write descriptors size failed");
    for (auto descriptor : descriptors) {
        SLOGI("networkId_: %{public}.6s, role %{public}d", descriptor.networkId_.c_str(),
              static_cast<int32_t>(descriptor.deviceRole_));
        CHECK_AND_RETURN_RET_LOG(descriptor.Marshalling(data), ERR_MARSHALLING, "write descriptor failed");
    }

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_CAST_AUDIO, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(static_cast<int32_t>(descriptors.size())), ERR_MARSHALLING,
                             "write descriptors size failed");
    for (auto descriptor : descriptors) {
        SLOGI("networkId_: %{public}.6s, role %{public}d", descriptor.networkId_.c_str(),
              static_cast<int32_t>(descriptor.deviceRole_));
        CHECK_AND_RETURN_RET_LOG(descriptor.Marshalling(data), ERR_MARSHALLING, "write descriptor failed");
    }

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_CAST_AUDIO_FOR_ALL, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionServiceProxy::StartCastDiscovery(const int32_t castDeviceCapability)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(castDeviceCapability),
        ERR_MARSHALLING, "write castDeviceCapability failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_START_CAST_DISCOVERY, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::StopCastDiscovery()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_STOP_CAST_DISCOVERY, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(sessionToken.sessionId), ERR_MARSHALLING, "write sessionId failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(sessionToken.pid), ERR_MARSHALLING, "write pid failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(sessionToken.uid), ERR_MARSHALLING, "write uid failed");

    int32_t deviceInfoSize = outputDeviceInfo.deviceInfos_.size();
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfoSize), ERR_MARSHALLING, "write deviceInfoSize failed");
    for (const DeviceInfo deviceInfo : outputDeviceInfo.deviceInfos_) {
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.castCategory_),
            ERR_MARSHALLING, "write castCategory failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteString(deviceInfo.deviceId_), ERR_MARSHALLING, "write deviceId failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteString(deviceInfo.deviceName_), ERR_MARSHALLING, "write deviceName failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.deviceType_), ERR_MARSHALLING, "write deviceType failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteString(deviceInfo.ipAddress_), ERR_MARSHALLING, "write ipAddress failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.providerId_), ERR_MARSHALLING, "write providerId failed");
    }

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_START_CAST, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::StopCast(const SessionToken& sessionToken)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(sessionToken.sessionId), ERR_MARSHALLING, "write sessionId failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(sessionToken.pid), ERR_MARSHALLING, "write pid failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(sessionToken.uid), ERR_MARSHALLING, "write uid failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SERVICE_CMD_STOP_CAST, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}
#endif
} // namespace OHOS::AVSession
