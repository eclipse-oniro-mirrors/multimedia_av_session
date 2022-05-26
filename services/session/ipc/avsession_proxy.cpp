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

#include "avsession_proxy.h"
#include "avplayback_state.h"
#include "avsession_callback_client.h"
#include "iavsession_callback.h"
#include "avsession_log.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
AVSessionProxy::AVSessionProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVSession>(impl)
{
    SLOGD("construct");
}

int32_t AVSessionProxy::GetSessionId()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING,"GetSessionId write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_GET_SESSION_ID, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "GetSessionId send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionProxy::RegisterCallback(std::shared_ptr<AVSessionCallback> &callback)
{
    sptr<IAVSessionCallback> callback_;
    callback_ = new(std::nothrow) AVSessionCallbackClient(callback);
    if (callback_ == nullptr) {
        return ERR_NO_MEMORY;
    }
    if (RegisterCallbackInner(callback_) != AVSESSION_SUCCESS) {
        callback_.clear();
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionProxy::RegisterCallbackInner(const sptr<IAVSessionCallback> &callback)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(callback->AsObject()), ERR_MARSHALLING,
                             "write remote object failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_REGISTER_CALLBACK, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionProxy::Release()
{
    SLOGD("Release enter");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "Release write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_RELEASE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "Release send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionProxy::SetAVMetaData(const AVMetaData& meta)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "SetAVMetaData write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&meta),
        ERR_MARSHALLING, "SetAVMetaData WriteParcelable failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_SET_META_DATA, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "SetAVMetaData send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionProxy::GetAVPlaybackState(AVPlaybackState& state)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "GetAVPlaybackState write interface token failed");
    CHECK_AND_RETURN_RET_LOG(state.Marshalling(data),
        ERR_MARSHALLING, "GetAVPlaybackState Write state failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_GET_PLAYBACK_STATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "GetAVPlaybackState send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionProxy::SetAVPlaybackState(const AVPlaybackState& state)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "SetAVPlaybackState write interface token failed");
    CHECK_AND_RETURN_RET_LOG(state.Marshalling(data),
        ERR_MARSHALLING, "SetAVPlaybackState Write state failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_SET_PLAYBACK_STATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "SetAVPlaybackState send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionProxy::GetAVMetaData(AVMetaData& meta)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "GetAVMetaData write interface token failed");
    CHECK_AND_RETURN_RET_LOG(meta.Marshalling(data),
        ERR_MARSHALLING, "GetAVMetaData Write AVMetaData failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_GET_META_DATA, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "GetAVMetaData send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionProxy::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "SetLaunchAbility write interface token failed");
    CHECK_AND_RETURN_RET_LOG(ability.Marshalling(data),
        ERR_MARSHALLING, "SetLaunchAbility Write WantAgent failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_SET_LAUNCH_ABILITY, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "SetLaunchAbility send request failed");
    return reply.ReadInt32();
}

std::shared_ptr<AVSessionController> AVSessionProxy::GetController()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        nullptr, "GetController write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_GET_CONTROLLER, data, reply, option) == 0,
        nullptr, "GetController send request failed");

    return std::shared_ptr<AVSessionController>();
}

int32_t AVSessionProxy::Active()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "Active write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_ACTIVE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "Active send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionProxy::Disactive()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "Disactive write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_DISACTIVE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "Disactive send request failed");
    return reply.ReadInt32();
}

bool AVSessionProxy::IsActive()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "IsActive write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_ISACTIVE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "IsActive send request failed");
    return reply.ReadBool();
}

int32_t AVSessionProxy::AddSupportCommand(const int32_t cmd)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "AddSupportCommand write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(cmd),
        ERR_MARSHALLING, "AddSupportCommand Write cmd failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_ADDSUPPORTCOMMAND, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "AddSupportCommand send request failed");
    return reply.ReadInt32();
}
}