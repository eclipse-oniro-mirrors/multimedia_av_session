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

#include "avsession_controller_proxy.h"

#include "avcontroller_callback_client.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVSessionControllerProxy::AVSessionControllerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVSessionController>(impl)
{
    SLOGD("construct");
}

int32_t AVSessionControllerProxy::GetAVPlaybackState(AVPlaybackState &state)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_AV_PLAYBACK_STATE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        sptr<AVPlaybackState> state_ = reply.ReadParcelable<AVPlaybackState>();
        CHECK_AND_RETURN_RET_LOG(state_ != nullptr, ERR_UNMARSHALLING, "read AVPlaybackState failed");
        state = *state_;
    }
    return ret;
}

int32_t AVSessionControllerProxy::GetAVMetaData(AVMetaData &data)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_AV_META_DATA, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        sptr<AVMetaData> data_ = reply.ReadParcelable<AVMetaData>();
        CHECK_AND_RETURN_RET_LOG(data_ != nullptr, ERR_UNMARSHALLING, "read AVMetaData failed");
        data = *data_;
    }
    return ret;
}

int32_t AVSessionControllerProxy::SendMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    CHECK_AND_RETURN_RET_LOG(keyEvent.IsValid(), ERR_INVALID_PARAM, "keyEvent not valid");

    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(keyEvent.WriteToParcel(parcel), ERR_MARSHALLING, "write keyEvent failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SEND_MEDIA_KEYEVENT, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent &ability)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_LAUNCH_ABILITY, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        sptr<AbilityRuntime::WantAgent::WantAgent> ability_ =
            reply.ReadParcelable<AbilityRuntime::WantAgent::WantAgent>();
        CHECK_AND_RETURN_RET_LOG(ability_ != nullptr, ERR_UNMARSHALLING, "read LaunchAbility failed");
        ability = *ability_;
    }
    return ret;
}

int32_t AVSessionControllerProxy::GetSupportedCommand(std::vector<int32_t> &cmds)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_SUPPORTED_COMMAND, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.ReadInt32Vector(&cmds), ERR_UNMARSHALLING, "read int32 vector failed");
    }
    return ret;
}

int32_t AVSessionControllerProxy::IsSessionActive(bool &isActive)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_IS_SESSION_ACTIVE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.ReadBool(isActive), ERR_UNMARSHALLING, "read LaunchAbility failed");
    }
    return ret;
}

int32_t AVSessionControllerProxy::SendCommand(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd.IsValid(), ERR_INVALID_PARAM, "command not valid");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteParcelable(&cmd), ERR_MARSHALLING, "write cmd failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SEND_COMMAND, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::SetMetaFilter(const AVMetaData::MetaMaskType &filter)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(filter.to_string()), ERR_MARSHALLING, "write filter failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SET_META_FILTER, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::RegisterCallback(std::shared_ptr<AVControllerCallback> &callback)
{
    sptr<IRemoteObject> callback_;

    callback_ = new(std::nothrow) AVControllerCallbackClient(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, ERR_NO_MEMORY, "new AVControllerCallbackClient failed");

    return RegisterCallbackInner(callback_);
}

int32_t AVSessionControllerProxy::RegisterCallbackInner(const sptr<IRemoteObject> &callback)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteRemoteObject(callback), ERR_MARSHALLING,
        "write remote object failed");

    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_REGISTER_CALLBACK, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::Release()
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_RELEASE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}
}