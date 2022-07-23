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

#include "avsession_stub.h"
#include "avsession_callback_proxy.h"
#include "avsession_trace.h"
#include "want_agent_adapter.h"

namespace OHOS::AVSession {
bool AVSessionStub::CheckInterfaceToken(MessageParcel &data)
{
    auto localDescriptor = IAVSession::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGE("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVSessionStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    SLOGD("cmd code is %{public}d", code);
    if (code >= 0 && code < SESSION_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVSessionStub::HandleGetSessionId(MessageParcel &data, MessageParcel &reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::GetSessionId");
    CHECK_AND_PRINT_LOG(reply.WriteString(GetSessionId()), "write int32_t failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleRegisterCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::RegisterCallbackInner");
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32_t failed");
        return ERR_NONE;
    }
    auto callback = iface_cast<AVSessionCallbackProxy>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(RegisterCallbackInner(callback)),
                             ERR_NONE, "write int32_t failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleDestroy(MessageParcel &data, MessageParcel &reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::Destroy");
    Destroy();
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_SUCCESS), ERR_NONE, "write int32_t failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::GetAVPlaybackState");
    AVPlaybackState avPlaybackState;
    int32_t ret = GetAVPlaybackState(avPlaybackState);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "GetAVPlaybackState failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteParcelable(&avPlaybackState), ERR_NONE, "write avPlaybackState failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::SetAVPlaybackState");
    sptr avPlaybackState = data.ReadParcelable<AVPlaybackState>();
    if (avPlaybackState == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "WriteInt32 result failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SetAVPlaybackState(*avPlaybackState)), ERR_NONE,
        "WriteInt32 result failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::SetAVMetaData");
    sptr avMetaData = data.ReadParcelable<AVMetaData>();
    if (avMetaData == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "WriteInt32 result failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SetAVMetaData(*avMetaData)), ERR_NONE, "WriteInt32 result failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetLaunchAbility(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::SetLaunchAbility");
    sptr want = data.ReadParcelable<WantAgentAdapter>();
    if (want == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "WriteInt32 result failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SetLaunchAbilityInner(*want)), ERR_NONE, "Write LaunchAbility failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::GetAVMetaData");
    AVMetaData avMetaData;
    int32_t ret = GetAVMetaData(avMetaData);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "GetAVMetaData failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteParcelable(&avMetaData), ERR_NONE, "write avMetaData failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetController(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::GetController");
    sptr<IRemoteObject>  controller = GetControllerInner();
    if (controller == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_SUCCESS), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(controller), ERR_NONE, "write object failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleActivate(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::Activate");
    CHECK_AND_PRINT_LOG(reply.WriteInt32(Activate()), "WriteInt32 failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleDeactivate(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::Deactivate");
    CHECK_AND_PRINT_LOG(reply.WriteInt32(Deactivate()), "WriteInt32 failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleIsActive(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::IsActive");
    CHECK_AND_PRINT_LOG(reply.WriteBool(IsActive()), "WriteBool failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleAddSupportCommand(MessageParcel& data, MessageParcel& reply)
{
    AVSessionTrace avSessionTrace("AVSessionStub::AddSupportCommand");
    CHECK_AND_PRINT_LOG(reply.WriteInt32(AddSupportCommand(data.ReadInt32())), "WriteInt32 failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleDeleteSupportCommand(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(DeleteSupportCommand(data.ReadInt32())), "WriteInt32 failed");
    return ERR_NONE;
}
}