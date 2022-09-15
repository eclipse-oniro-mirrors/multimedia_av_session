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

#include "avsession_service_stub.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "session_listener_proxy.h"
#include "client_death_proxy.h"
#include "avsession_trace.h"
#include "avsession_sysevent.h"

using namespace OHOS::AudioStandard;
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
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::CreateSessionInner");
    auto sessionTag = data.ReadString();
    auto sessionType = data.ReadInt32();
    sptr elementName = data.ReadParcelable<AppExecFwk::ElementName>();
    if (elementName == nullptr) {
        SLOGE("read element name failed");
        reply.WriteInt32(ERR_UNMARSHALLING);
        return ERR_NONE;
    }
    auto session = CreateSessionInner(sessionTag, sessionType, *elementName);
    if (session == nullptr) {
        SLOGE("session is nullptr");
        reply.WriteInt32(ERR_UNMARSHALLING);
        return ERR_NONE;
    }
    reply.WriteInt32(AVSESSION_SUCCESS);
    reply.WriteRemoteObject(session);
    return ERR_NONE;
}

int AVSessionServiceStub::HandleGetAllSessionDescriptors(MessageParcel &data, MessageParcel &reply)
{
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = GetAllSessionDescriptors(descriptors);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteUint32(descriptors.size()), ERR_NONE, "write size failed");
    for (const auto& descriptor : descriptors) {
        if (!descriptor.WriteToParcel(reply)) {
            SLOGE("write descriptor failed");
            break;
        }
    }
    return ERR_NONE;
}

int AVSessionServiceStub::HandleGetSessionDescriptorsById(MessageParcel &data, MessageParcel &reply)
{
    AVSessionDescriptor descriptor;
    int32_t ret = GetSessionDescriptorsBySessionId(data.ReadString(), descriptor);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(descriptor.WriteToParcel(reply), "write AVSessionDescriptor failed");
    }
    return ERR_NONE;
}

int AVSessionServiceStub::HandleCreateControllerInner(MessageParcel &data, MessageParcel &reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::CreateControllerInner");
    sptr<IRemoteObject> object;
    int32_t ret = CreateControllerInner(data.ReadString(), object);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteRemoteObject(object), "write object failed");
    }
    return ERR_NONE;
}

int AVSessionServiceStub::HandleRegisterSessionListener(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        SLOGE("read remote object failed");
        reply.WriteInt32(ERR_UNMARSHALLING);
        return ERR_NONE;
    }
    auto listener = iface_cast<SessionListenerProxy>(remoteObject);
    if (!reply.WriteInt32(RegisterSessionListener(listener))) {
        SLOGE("reply write int32 failed");
    }
    return ERR_NONE;
}

int AVSessionServiceStub::HandleSendSystemAVKeyEvent(MessageParcel &data, MessageParcel &reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::SendSystemAVKeyEvent");
    auto keyEvent = MMI::KeyEvent::Create();
    if (keyEvent == nullptr) {
        SLOGE("create keyEvent failed");
        reply.WriteInt32(ERR_NO_MEMORY);
        return ERR_NONE;
    }
    if (!keyEvent->ReadFromParcel(data)) {
        SLOGE("read keyEvent failed");
        reply.WriteInt32(ERR_UNMARSHALLING);
        return ERR_NONE;
    }
    if (!reply.WriteInt32(SendSystemAVKeyEvent(*keyEvent))) {
        SLOGE("reply write int32 failed");
    }
    return ERR_NONE;
}

int AVSessionServiceStub::HandleSendSystemControlCommand(MessageParcel &data, MessageParcel &reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::SendSystemControlCommand");
    sptr command = data.ReadParcelable<AVControlCommand>();
    if (command == nullptr) {
        SLOGE("read command failed");
        reply.WriteInt32(ERR_UNMARSHALLING);
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "READ_PARCELABLE_FAILED",
            "ERROR_INFO", "handle send system control command read command failed");
        return ERR_NONE;
    }
    if (!reply.WriteInt32(SendSystemControlCommand(*command))) {
        SLOGE("reply write int32 failed");
    }
    return ERR_NONE;
}

int AVSessionServiceStub::HandleRegisterClientDeathObserver(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        SLOGE("read remote object failed");
        reply.WriteInt32(ERR_UNMARSHALLING);
        return ERR_NONE;
    }
    auto clientDeathObserver = iface_cast<ClientDeathProxy>(remoteObject);
    reply.WriteInt32(RegisterClientDeathObserver(clientDeathObserver));
    return ERR_NONE;
}

int AVSessionServiceStub::HandleCastAudio(MessageParcel &data, MessageParcel &reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::CastAudio");
    SLOGI("start");
    SessionToken token {};
    token.sessionId = data.ReadString();
    token.pid = data.ReadInt32();
    token.uid = data.ReadUint32();
    int32_t deviceNum = data.ReadInt32();
    std::vector<AudioDeviceDescriptor> sinkAudioDescriptors;
    for (int i = 0; i < deviceNum; i++) {
        auto audioDeviceDescriptor = AudioDeviceDescriptor::Unmarshalling(data);
        if (audioDeviceDescriptor == nullptr) {
            SLOGE("read AudioDeviceDescriptor failed");
            reply.WriteInt32(ERR_UNMARSHALLING);
            return ERR_NONE;
        }
        SLOGI("networkId_: %{public}s, role %{public}d", (*audioDeviceDescriptor).networkId_.c_str(),
              static_cast<int32_t>((*audioDeviceDescriptor).deviceRole_));
        sinkAudioDescriptors.push_back(*audioDeviceDescriptor);
    }
    int32_t ret = CastAudio(token, sinkAudioDescriptors);
    SLOGE("CastAudio ret %{public}d", ret);
    reply.WriteInt32(ret);
    SLOGI("success");
    return ERR_NONE;
}

int AVSessionServiceStub::HandleCastAudioForAll(MessageParcel &data, MessageParcel &reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::CastAudioForAll");
    SLOGI("start");
    int32_t deviceNum = data.ReadInt32();
    std::vector<AudioDeviceDescriptor> sinkAudioDescriptors {};
    for (int i = 0; i < deviceNum; i++) {
        auto audioDeviceDescriptor = AudioDeviceDescriptor::Unmarshalling(data);
        if (audioDeviceDescriptor == nullptr) {
            SLOGE("read AudioDeviceDescriptor failed");
            reply.WriteInt32(ERR_UNMARSHALLING);
            return ERR_NONE;
        }
        SLOGI("networkId_: %{public}s, role %{public}d", (*audioDeviceDescriptor).networkId_.c_str(),
              static_cast<int32_t>((*audioDeviceDescriptor).deviceRole_));
        sinkAudioDescriptors.push_back(*audioDeviceDescriptor);
    }
    int32_t ret = CastAudioForAll(sinkAudioDescriptors);
    SLOGI("CastAudioForAll ret %{public}d", ret);
    reply.WriteInt32(ret);
    return ERR_NONE;
}

int AVSessionServiceStub::HandleRemoteCastAudio(MessageParcel &data, MessageParcel &reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::RemoteCastAudio");
    SLOGI("start");
    auto command = static_cast<RemoteServiceCommand>(data.ReadInt32());
    std::string sessionInfo = data.ReadString();
    std::string output;
    int32_t ret = ProcessCastAudioCommand(command, sessionInfo, output);
    SLOGE("RemoteCastAudio ret %{public}d", ret);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("RemoteCastAudio failed");
        reply.WriteInt32(ret);
        return ERR_NONE;
    }
    reply.WriteInt32(ret);
    reply.WriteString(output);
    return ERR_NONE;
}
} // namespace OHOS::AVSession