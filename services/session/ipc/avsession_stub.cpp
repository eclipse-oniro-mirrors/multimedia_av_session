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

#include "avsession_stub.h"
#include "avsession_callback_proxy.h"

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

int32_t AVSessionStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                   MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= 0 && code < SESSION_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVSessionStub::HandleGetSessionId(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(GetSessionId());
    return ERR_NONE;
}

int32_t AVSessionStub::HandleRegisterCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        reply.WriteInt32(AVSESSION_ERROR);
        return ERR_NONE;
    }
    auto callback = iface_cast<AVSessionCallbackProxy>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(RegisterCallbackInner(callback)), ERR_MARSHALLING, "write int32_t failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleRelease(MessageParcel &data, MessageParcel &reply)
{
    Release();
    reply.WriteInt32(AVSESSION_SUCCESS);
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVPlaybackState avPlaybackState;
    int32_t ret = GetAVPlaybackState(avPlaybackState);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "write int32 failed");
    CHECK_AND_PRINT_LOG(reply.WriteParcelable(&avPlaybackState), "write avPlaybackState failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    sptr avPlaybackState = data.ReadParcelable<AVPlaybackState>();
    if(avPlaybackState != nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SetAVPlaybackState(*avPlaybackState)), "WriteInt32 result failed");
    }
    else
    {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "WriteInt32 result failed");
    }
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    sptr avMetaData = data.ReadParcelable<AVMetaData>();
    if(avMetaData != nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SetAVMetaData(*avMetaData)), "WriteInt32 result failed");
    }
    else
    {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "WriteInt32 result failed");
    }
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetLaunchAbility(MessageParcel& data, MessageParcel& reply)
{
    sptr want = data.ReadParcelable<AbilityRuntime::WantAgent::WantAgent>();
    if(want != nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SetLaunchAbility(*want)), "WriteInt32 result failed");
    }
    else
    {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "WriteInt32 result failed");
    }
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVMetaData avMetaData;
    int32_t ret = GetAVMetaData(avMetaData);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&avMetaData), "write avMetaData failed");
    }
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetController(MessageParcel& data, MessageParcel& reply)
{
    sptr<IRemoteObject>  controller = GetControllerInner();
    if(controller != nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(AVSESSION_SUCCESS), "write int32 failed");
        CHECK_AND_PRINT_LOG(reply.WriteRemoteObject(controller), "write object failed");
    }
    else
    {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(AVSESSION_ERROR), "write int32 failed");
    }
    return ERR_NONE;
}

    int32_t AVSessionStub::HandleActive(MessageParcel& data, MessageParcel& reply)
{
    int32_t ret = Active();
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "WriteInt32 failed");
    }
    return ERR_NONE;
}

int32_t AVSessionStub::HandleDisactive(MessageParcel& data, MessageParcel& reply)
{
    int32_t ret = Disactive();
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "WriteInt32 failed");
    }
    return ERR_NONE;
}

int32_t AVSessionStub::HandleIsActive(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteBool(IsActive()), "WriteBool failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleAddSupportCommand(MessageParcel& data, MessageParcel& reply)
{
    int32_t ret = AddSupportCommand(data.ReadInt32());
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "WriteInt32 failed");
    }
    return ERR_NONE;
}
}