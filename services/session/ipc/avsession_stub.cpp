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
#include "avsession_log.h"
#include "avsession_errors.h"
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

int AVSessionStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
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

int AVSessionStub::HandleGetSessionId(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(GetSessionId());
    return ERR_NONE;
}

int AVSessionStub::HandleRegisterCallback(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        reply.WriteInt32(AVSESSION_ERROR);
        return ERR_NONE;
    }
    auto callback = iface_cast<AVSessionCallbackProxy>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(RegisterCallbackInner(callback)), ERR_MARSHALLING, "write int failed");
    return ERR_NONE;
}

int AVSessionStub::HandleRelease(MessageParcel &data, MessageParcel &reply)
{
    Release();
    reply.WriteInt32(AVSESSION_SUCCESS);
    return ERR_NONE;
}

int AVSessionStub::HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVPlaybackState avPlaybackState;
    avPlaybackState.SetState(data.ReadInt32());
    avPlaybackState.SetBufferedTime(data.ReadInt64());
    reply.WriteInt32(GetAVPlaybackState(avPlaybackState));
    return ERR_NONE;
}

int AVSessionStub::HandleSetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVPlaybackState* avPlaybackState = data.ReadParcelable<AVPlaybackState>();
    reply.WriteInt32(GetAVPlaybackState(*avPlaybackState));
    delete avPlaybackState;
    avPlaybackState = nullptr;
    return ERR_NONE;
}

int AVSessionStub::HandleSetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    const AVMetaData* avMetaData = data.ReadParcelable<AVMetaData>();
    reply.WriteInt32(SetAVMetaData(*avMetaData));
    delete avMetaData;
    avMetaData = nullptr;
    return ERR_NONE;
}

int AVSessionStub::HandleSetLaunchAbility(MessageParcel& data, MessageParcel& reply)
{
    const AbilityRuntime::WantAgent::WantAgent* want = data.ReadParcelable<AbilityRuntime::WantAgent::WantAgent>();
    reply.WriteInt32(SetLaunchAbility(*want));
    delete want;
    want = nullptr;
    return ERR_NONE;
}

int AVSessionStub::HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVMetaData* avMetaData = data.ReadParcelable<AVMetaData>();
    reply.WriteInt32(GetAVMetaData(*avMetaData));
    delete avMetaData;
    avMetaData = nullptr;
    return ERR_NONE;
}

int AVSessionStub::HandleGetController(MessageParcel& data, MessageParcel& reply)
{
    return ERR_NONE;
}

int AVSessionStub::HandleActive(MessageParcel& data, MessageParcel& reply)
{
    reply.WriteInt32(Active());
    return ERR_NONE;
}

int AVSessionStub::HandleDisactive(MessageParcel& data, MessageParcel& reply)
{
    reply.WriteInt32(Disactive());
    return ERR_NONE;
}

int AVSessionStub::HandleIsActive(MessageParcel& data, MessageParcel& reply)
{
    reply.WriteBool(IsActive());
    return ERR_NONE;
}

int AVSessionStub::HandleAddSupportCommand(MessageParcel& data, MessageParcel& reply)
{

    reply.WriteInt32(AddSupportCommand(data.ReadInt32()));
    return ERR_NONE;
}

int32_t AVSessionStub::RegisterCallback(std::shared_ptr<AVSessionCallback>& callback)
{
    return 0;
}
}