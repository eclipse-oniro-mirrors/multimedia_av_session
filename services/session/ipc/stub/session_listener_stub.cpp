/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "ipc_skeleton.h"

namespace OHOS::AVSession {
bool SessionListenerStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = ISessionListener::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t SessionListenerStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
                                             MessageOption& option)
{
    CHECK_AND_RETURN_RET_LOG(IPCSkeleton::IsLocalCalling(), AVSESSION_ERROR, "forbid rpc remote request");
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= static_cast<uint32_t>(ISessionListener::LISTENER_CMD_ON_CREATE)
        && code < static_cast<uint32_t>(ISessionListener::LISTENER_CMD_MAX)) {
        return handlers[code](data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SessionListenerStub::HandleOnSessionCreate(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::OnSessionCreate");
    AVSessionDescriptor descriptor;
    CHECK_AND_RETURN_RET_LOG(descriptor.ReadFromParcel(data), ERR_NONE, "read descriptor failed");
    OnSessionCreate(descriptor);
    return ERR_NONE;
}

int32_t SessionListenerStub::HandleOnSessionRelease(MessageParcel& data, MessageParcel& reply)
{
    AVSessionDescriptor descriptor;
    CHECK_AND_RETURN_RET_LOG(descriptor.ReadFromParcel(data), ERR_NONE, "read descriptor failed");
    OnSessionRelease(descriptor);
    return ERR_NONE;
}

int32_t SessionListenerStub::HandleOnTopSessionChange(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::OnTopSessionChange");
    AVSessionDescriptor descriptor;
    CHECK_AND_RETURN_RET_LOG(descriptor.ReadFromParcel(data), ERR_NONE, "read descriptor failed");
    OnTopSessionChange(descriptor);
    return ERR_NONE;
}

int32_t SessionListenerStub::HandleOnAudioSessionChecked(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::OnAudioSessionChecked");
    int32_t uid = data.ReadInt32();
    OnAudioSessionChecked(uid);
    reply.WriteInt32(AVSESSION_SUCCESS);
    return ERR_NONE;
}

int32_t SessionListenerStub::HandleOnDeviceAvailable(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::HandleOnDeviceAvailable");
    OutputDeviceInfo castOutputDeviceInfo;
    CHECK_AND_RETURN_RET_LOG(castOutputDeviceInfo.ReadFromParcel(data), ERR_NONE, "read castOutputDeviceInfo failed");
    OnDeviceAvailable(castOutputDeviceInfo);
    return ERR_NONE;
}

int32_t SessionListenerStub::HandleOnDeviceLogEvent(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::HandleOnDeviceLogEvent");
    DeviceLogEventCode eventId = static_cast<DeviceLogEventCode>(data.ReadInt32());
    int64_t param = data.ReadInt64();
    OnDeviceLogEvent(eventId, param);
    return ERR_NONE;
}

int32_t SessionListenerStub::HandleOnDeviceOffline(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::HandleOnDeviceOffline");
    auto deviceId = data.ReadString();
    OnDeviceOffline(deviceId);
    return ERR_NONE;
}

int32_t SessionListenerStub::HandleOnRemoteDistributedSessionChange(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::HandleOnRemoteDistributedSessionChange");
    uint32_t size {};
    CHECK_AND_RETURN_RET_LOG(data.ReadUint32(size), ERR_UNMARSHALLING, "read vector size failed");

    std::vector<sptr<IRemoteObject>> controllerResult(size);
    for (auto& controller : controllerResult) {
        controller = data.ReadRemoteObject();
        CHECK_AND_RETURN_RET_LOG(controller, ERR_UNMARSHALLING, "read controller failed");
    }
    OnRemoteDistributedSessionChange(controllerResult);
    return ERR_NONE;
}

int32_t SessionListenerStub::HandleOnDeviceStateChange(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("SessionListenerStub::HandleOnDeviceStateChange");
    DeviceState deviceState;
    deviceState.deviceId = data.ReadString();
    deviceState.deviceState = static_cast<ConnectionState>(data.ReadInt32());
    deviceState.reasonCode = static_cast<ReasonCode>(data.ReadInt32());
    deviceState.radarErrorCode = data.ReadInt32();

    OnDeviceStateChange(deviceState);
    return ERR_NONE;
}
} // namespace OHOS::AVSession
