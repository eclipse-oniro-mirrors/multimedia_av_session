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
    return 0;
}

int32_t AVSessionControllerProxy::GetAVMetaData(AVMetaData &data)
{
    return 0;
}

int32_t AVSessionControllerProxy::GetAVVolumeInfo(AVVolumeInfo &info)
{
    return 0;
}

int32_t AVSessionControllerProxy::SendSystemMediaKeyEvent(MMI::KeyEvent& keyEvent)
{
    return 0;
}

int32_t AVSessionControllerProxy::GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent &ability)
{
    return 0;
}

int32_t AVSessionControllerProxy::GetSupportedCommand(std::vector<int32_t> &cmds)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(CONTROLLER_CMD_GET_SUPPORTED_COMMAND, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32Vector(&cmds), ERR_UNMARSHALLING, "read int32 vector failed");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionControllerProxy::IsSessionActive(bool &isActive)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(CONTROLLER_CMD_IS_SESSION_ACTIVE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    isActive = reply.ReadBool();
    return AVSESSION_SUCCESS;
}

int32_t AVSessionControllerProxy::SendCommand(AVControlCommand &cmd)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(cmd.Marshalling(data), ERR_MARSHALLING, "write cmd failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(CONTROLLER_CMD_SEND_COMMAND, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionControllerProxy::SetMetaFilter(const AVMetaData::MetaMaskType &filter)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(filter.to_string()), ERR_MARSHALLING, "write string failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(CONTROLLER_CMD_SET_META_FILTER, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionControllerProxy::RegisterCallback(std::shared_ptr<AVControllerCallback> &callback)
{
    sptr<IAVControllerCallback> callback_;

    callback_ = new(std::nothrow) AVControllerCallbackClient(callback);
    if (callback_ == nullptr) {
        return ERR_NO_MEMORY;
    }
    if (RegisterCallbackInner(callback_) != AVSESSION_SUCCESS) {
        callback_.clear();
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionControllerProxy::RegisterCallbackInner(const sptr<IAVControllerCallback> &callback)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(callback->AsObject()), ERR_MARSHALLING,
        "write remote object failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(CONTROLLER_CMD_REGISTER_CALLBACK, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    return reply.ReadInt32();
}

int32_t AVSessionControllerProxy::Release()
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(CONTROLLER_CMD_RELEASE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    return reply.ReadInt32();
}
}