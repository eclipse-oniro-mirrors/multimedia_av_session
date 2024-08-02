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
    auto object = AVSessionServiceProxy::CreateSessionInner(tag, type, elementName);
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

int32_t AVSessionServiceProxy::CreateSession(const std::string& tag, int32_t type,
                                             const AppExecFwk::ElementName& elementName,
                                             std::shared_ptr<AVSession>& session)
{
    sptr<IRemoteObject> object;
    auto ret = AVSessionServiceProxy::CreateSessionInner(tag, type, elementName, object);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CreateSession failed");

    auto sessionObj = iface_cast<AVSessionProxy>(object);
    CHECK_AND_RETURN_RET_LOG(sessionObj, AVSESSION_ERROR, "sessionObj is nullptr");

    session = std::shared_ptr<AVSession>(sessionObj.GetRefPtr(), [holder = sessionObj](const auto*) {});
    return ret;
}

sptr<IRemoteObject> AVSessionServiceProxy::CreateSessionInner(const std::string& tag, int32_t type,
                                                              const AppExecFwk::ElementName& elementName)
{
    sptr<IRemoteObject> object;
    auto ret = AVSessionServiceProxy::CreateSessionInner(tag, type, elementName, object);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, nullptr, "CreateSessionInner failed");
    return object;
}

int32_t AVSessionServiceProxy::CreateSessionInner(const std::string& tag, int32_t type,
                                                  const AppExecFwk::ElementName& elementName,
                                                  sptr<IRemoteObject>& object)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_UNMARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(tag), ERR_UNMARSHALLING, "write tag failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(type), ERR_UNMARSHALLING, "write type failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&elementName), ERR_UNMARSHALLING, "write bundleName failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_UNMARSHALLING, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CREATE_SESSION), data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t res = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(res), ERR_UNMARSHALLING, "read res failed");
    if (res == AVSESSION_SUCCESS) {
        object = reply.ReadRemoteObject();
    }
    return res;
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_NO_PERMISSION, ret, "no permission");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_PERMISSION_DENIED, ret, "permission denied");
    if (ret == AVSESSION_SUCCESS) {
        uint32_t size {};
        CHECK_AND_RETURN_RET_LOG(reply.ReadUint32(size), ERR_UNMARSHALLING, "read vector size failed");
        CHECK_AND_RETURN_RET_LOG(size, ret, "get all session with true empty");

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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_SESSION_DESCRIPTORS_BY_ID),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_NO_PERMISSION, ret, "no permission");
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_HISTORY_SESSION_DESCRIPTORS),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_NO_PERMISSION, ret, "no permission");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_PERMISSION_DENIED, ret, "permission denied");
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

void AVSessionServiceProxy::UnMarshallingAVQueueInfos(MessageParcel &reply, std::vector<AVQueueInfo>& avQueueInfos)
{
    uint32_t size {};
    CHECK_AND_RETURN_LOG(reply.ReadUint32(size), "UnMarshallingAVQueueInfos size failed");
    CHECK_AND_RETURN_LOG(size, "UnMarshallingAVQueueInfos size=0");

    for (uint32_t i = 0; i < size; i++) {
        AVQueueInfo avQueueInfo;
        avQueueInfo.SetBundleName(reply.ReadString());
        avQueueInfo.SetAVQueueName(reply.ReadString());
        avQueueInfo.SetAVQueueId(reply.ReadString());
        avQueueInfo.SetAVQueueImageUri(reply.ReadString());
        avQueueInfo.SetAVQueueLength(reply.ReadUint32());
        avQueueInfos.push_back(avQueueInfo);
    }
}

void AVSessionServiceProxy::BufferToAVQueueInfoImg(const char *buffer, std::vector<AVQueueInfo>& avQueueInfos)
{
    int k = 0;
    for (auto& avQueueInfo : avQueueInfos) {
        auto pixelMap = new (std::nothrow) AVSessionPixelMap();
        std::vector<uint8_t> imgBuffer;
        int avQueueLength = avQueueInfo.GetAVQueueLength();
        for (int i = 0; i < avQueueLength; i++, k++) {
            imgBuffer.push_back((uint8_t)buffer[k]);
        }
        pixelMap->SetInnerImgBuffer(imgBuffer);
        avQueueInfo.SetAVQueueImage(std::shared_ptr<AVSessionPixelMap>(pixelMap));
    }
}

int32_t AVSessionServiceProxy::GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
    std::vector<AVQueueInfo>& avQueueInfos)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(maxSize), ERR_MARSHALLING, "write maxSize failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(maxAppSize), ERR_MARSHALLING, "write maxAppSize failed");
    
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_HISTORY_AVQUEUE_INFOS),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_NO_PERMISSION, ret, "no permission");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_PERMISSION_DENIED, ret, "permission denied");
    if (ret != AVSESSION_SUCCESS) {
        return ret;
    }
    int bufferLength = reply.ReadInt32();
    if (bufferLength == 0) {
        uint32_t size {};
        CHECK_AND_RETURN_RET_LOG(reply.ReadUint32(size), ERR_UNMARSHALLING, "read vector size failed");
        CHECK_AND_RETURN_RET_LOG(size, ret, "size=0");

        std::vector<AVQueueInfo> result(size);
        for (auto& avqueueInfo : result) {
            CHECK_AND_RETURN_RET_LOG(avqueueInfo.Unmarshalling(reply), ERR_UNMARSHALLING, "read avqueueInfo failed");
        }
        avQueueInfos = result;
        return ret;
    }
    UnMarshallingAVQueueInfos(reply, avQueueInfos);
    const char *buffer = nullptr;
    buffer = reinterpret_cast<const char *>(reply.ReadRawData(bufferLength));
    if (buffer == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
        SLOGE("read raw data failed, length = %{public}d", bufferLength);
        return AVSESSION_ERROR;
    }
    BufferToAVQueueInfoImg(buffer, avQueueInfos);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionServiceProxy::StartAVPlayback(const std::string& bundleName, const std::string& assetId)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(bundleName), ERR_MARSHALLING, "write bundleName failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(assetId), ERR_MARSHALLING, "write assetId failed");
    
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_AV_PLAYBACK),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    return ret;
}

int32_t AVSessionServiceProxy::CreateController(const std::string& sessionId,
    std::shared_ptr<AVSessionController>& controller)
{
    SLOGI("create controller in without lock");
    sptr<IRemoteObject> object;
    auto ret = AVSessionServiceProxy::CreateControllerInner(sessionId, object);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CreateControllerInner failed");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_NO_PERMISSION, ret, "no permission");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_PERMISSION_DENIED, ret, "permission denied");
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CREATE_CONTROLLER), data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS || ret == ERR_CONTROLLER_IS_EXIST) {
        object = reply.ReadRemoteObject();
    }
    return ret;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionServiceProxy::GetAVCastController(const std::string& sessionId,
    std::shared_ptr<AVCastController>& castController)
{
    sptr<IRemoteObject> object;
    auto ret = AVSessionServiceProxy::GetAVCastControllerInner(sessionId, object);
    CHECK_AND_RETURN_RET_LOG(ret != ERR_NO_PERMISSION, ret, "no permission");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_PERMISSION_DENIED, ret, "permission denied");
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_AV_CAST_CONTROLLER),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_NO_PERMISSION, ret, "no permission");
    CHECK_AND_RETURN_RET_LOG(ret != ERR_PERMISSION_DENIED, ret, "permission denied");
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_SESSION_LISTENER),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    SLOGI("try SendSystemAVKeyEvent with key=%{public}d", keyEvent.GetKeyCode());
    CHECK_AND_RETURN_RET_LOG(keyEvent.WriteToParcel(data), ERR_MARSHALLING, "write keyEvent failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_SYSTEM_AV_KEY_EVENT),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::SendSystemControlCommand(const AVControlCommand& command)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    SLOGI("try SendSystemControlCommand with cmd=%{public}d", command.GetCommand());
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&command), ERR_MARSHALLING, "write keyEvent failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_SYSTEM_CONTROL_COMMAND),\
        data, reply, option) == 0,
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_CLIENT_DEATH),\
        data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::Close(void)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CLOSE),\
        data, reply, option) == 0,
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CAST_AUDIO), data, reply, option) == 0,
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CAST_AUDIO_FOR_ALL), data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionServiceProxy::StartCastDiscovery(int32_t castDeviceCapability, std::vector<std::string> drmSchemes)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(castDeviceCapability),
        ERR_MARSHALLING, "write castDeviceCapability failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(drmSchemes.size()), ERR_MARSHALLING, "write drmSchemes size failed");
    for (auto drmScheme : drmSchemes) {
        CHECK_AND_RETURN_RET_LOG(data.WriteString(drmScheme), ERR_MARSHALLING, "write drmScheme failed");
    }
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_CAST_DISCOVERY),\
        data, reply, option) == 0,
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_STOP_CAST_DISCOVERY), data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}

int32_t AVSessionServiceProxy::SetDiscoverable(const bool enable)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteBool(enable), ERR_MARSHALLING, "write enable failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SET_DISCOVERYABLE), data, reply, option) == 0,
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

    int32_t deviceInfoSize = static_cast<int32_t>(outputDeviceInfo.deviceInfos_.size());
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfoSize), ERR_MARSHALLING, "write deviceInfoSize failed");
    for (const DeviceInfo& deviceInfo : outputDeviceInfo.deviceInfos_) {
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.castCategory_),
            ERR_MARSHALLING, "write castCategory failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteString(deviceInfo.deviceId_), ERR_MARSHALLING, "write deviceId failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteString(deviceInfo.deviceName_), ERR_MARSHALLING, "write deviceName failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.deviceType_), ERR_MARSHALLING, "write deviceType failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteString(deviceInfo.ipAddress_), ERR_MARSHALLING, "write ipAddress failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.providerId_), ERR_MARSHALLING, "write providerId failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.supportedProtocols_), ERR_MARSHALLING,
            "write supportedProtocols failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.authenticationStatus_), ERR_MARSHALLING,
            "write authenticationStatus failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(deviceInfo.supportedDrmCapabilities_.size()), ERR_MARSHALLING,
            "write supportedDrmCapabilities size failed");
        for (auto supportedDrmCapability : deviceInfo.supportedDrmCapabilities_) {
            CHECK_AND_RETURN_RET_LOG(data.WriteString(supportedDrmCapability), ERR_MARSHALLING,
                "write supportedDrmCapability failed");
        }
    }

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_CAST), data, reply, option) == 0,
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_STOP_CAST), data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}
#endif
} // namespace OHOS::AVSession
