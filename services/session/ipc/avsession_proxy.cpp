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

#include "avsession_proxy.h"
#include "avsession_callback_client.h"
#include "avsession_controller_proxy.h"
#include "iavsession_callback.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
AVSessionProxy::AVSessionProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVSession>(impl)
{
    SLOGD("construct");
}

int32_t AVSessionProxy::GetSessionId()
{
    AVSessionTrace trace("AVSessionProxy::GetSessionId");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_GET_SESSION_ID, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t sessionId = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(sessionId), AVSESSION_ERROR, "read sessionId failed");
    return sessionId;
}

int32_t AVSessionProxy::RegisterCallback(const std::shared_ptr<AVSessionCallback> &callback)
{
    AVSessionTrace trace("AVSessionProxy::RegisterCallback");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AVSESSION_ERROR, "callback is nullptr");
    callback_ = new(std::nothrow) AVSessionCallbackClient(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, ERR_NO_MEMORY, "new AVSessionCallbackClient failed");
    if (RegisterCallbackInner(callback_) != AVSESSION_SUCCESS) {
        callback_.clear();
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionProxy::RegisterCallbackInner(const sptr<IAVSessionCallback> &callback)
{
    AVSessionTrace trace("AVSessionProxy::RegisterCallbackInner");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(callback->AsObject()), ERR_MARSHALLING,
                             "write remote object failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_REGISTER_CALLBACK, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::Destroy()
{
    AVSessionTrace::TraceBegin("AVControllerCallback::OnSessionDestroy", ON_SESSION_DESTROY_TASK_ID);
    AVSessionTrace trace("AVSessionProxy::Release");
    SLOGD("enter");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_RELEASE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    if (!reply.ReadInt32(ret)) {
        return AVSESSION_ERROR;
    }
    if (ret == AVSESSION_SUCCESS) {
        isDestroyed_ = true;
    }
    return ret;
}

int32_t AVSessionProxy::SetAVMetaData(const AVMetaData& meta)
{
    AVSessionTrace::TraceBegin("AVControllerCallback::OnMetaDataChange", ON_MEDA_DATA_CHANGE_TASK_ID);
    AVSessionTrace trace("AVSessionProxy::SetAVMetaData");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&meta),
        ERR_MARSHALLING, "WriteParcelable failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_META_DATA, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::GetAVMetaData(AVMetaData& meta)
{
    AVSessionTrace trace("AVSessionProxy::GetAVMetaData");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_META_DATA, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::shared_ptr<AVMetaData> metaData(reply.ReadParcelable<AVMetaData>());
        CHECK_AND_RETURN_RET_LOG(metaData != nullptr, ERR_UNMARSHALLING, "read metaData failed");
        meta = *metaData;
    }
    return ret;
}

int32_t AVSessionProxy::GetAVPlaybackState(AVPlaybackState& state)
{
    AVSessionTrace trace("AVSessionProxy::GetAVPlaybackState");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_PLAYBACK_STATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::shared_ptr<AVPlaybackState> playbackState(reply.ReadParcelable<AVPlaybackState>());
        CHECK_AND_RETURN_RET_LOG(playbackState != nullptr, ERR_UNMARSHALLING, "read playbackState failed");
        state = *playbackState;
    }
    return ret;
}

int32_t AVSessionProxy::SetAVPlaybackState(const AVPlaybackState& state)
{
    AVSessionTrace::TraceBegin("AVControllerCallback::OnPlaybackStateChange", ON_PLAYBACK_STATE_CHANGE_TASK_ID);
    AVSessionTrace trace("AVSessionProxy::SetAVPlaybackState");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&state),
        ERR_MARSHALLING, "Write state failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_PLAYBACK_STATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    AVSessionTrace trace("AVSessionProxy::SetLaunchAbility");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&ability),
        ERR_MARSHALLING, "Write WantAgent failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_LAUNCH_ABILITY, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

sptr<IRemoteObject> AVSessionProxy::GetControllerInner()
{
    AVSessionTrace trace("AVSessionProxy::GetControllerInner");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, nullptr, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             nullptr, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, nullptr, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_CONTROLLER, data, reply, option) == 0,
                             nullptr, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), nullptr, "read int32 failed");
    sptr <IRemoteObject> controller = nullptr;
    if (ret == AVSESSION_SUCCESS) {
        controller = reply.ReadRemoteObject();
        CHECK_AND_RETURN_RET_LOG(controller != nullptr, nullptr, "read IRemoteObject failed");
    }
    return controller;
}

std::shared_ptr<AVSessionController> AVSessionProxy::GetController()
{
    AVSessionTrace trace("AVSessionProxy::GetController");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, nullptr, "session is destroyed");
    sptr <IRemoteObject> object = GetControllerInner();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "get object failed");
    auto controller = iface_cast<AVSessionControllerProxy>(object);
    return std::shared_ptr<AVSessionController>(controller.GetRefPtr(), [holder = controller](const auto*) {});
}

int32_t AVSessionProxy::Activate()
{
    AVSessionTrace::TraceBegin("AVControllerCallback::OnActiveStateChange", ON_ACTIVE_STATE_CHANGE_TASK_ID);
    AVSessionTrace trace("AVSessionProxy::Active");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_ACTIVE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::Deactivate()
{
    AVSessionTrace trace("AVSessionProxy::Disactive");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_DISACTIVE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

bool AVSessionProxy::IsActive()
{
    AVSessionTrace trace("AVSessionProxy::IsActive");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_ISACTIVE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    bool ret = false;
    return reply.ReadBool(ret) ? ret : false;
}

int32_t AVSessionProxy::AddSupportCommand(const int32_t cmd)
{
    AVSessionTrace::TraceBegin("AVControllerCallback::OnValidCommandChange", ON_VALID_COMMAND_CHANGE_TASK_ID);
    AVSessionTrace trace("AVSessionProxy::AddSupportCommand");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(cmd),
        ERR_MARSHALLING, "Write cmd failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_ADD_SUPPORT_COMMAND, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::DeleteSupportCommand(const int32_t cmd)
{
    AVSessionTrace trace("AVSessionProxy::DeleteSupportCommand");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, AVSESSION_ERROR, "session is destroyed");
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(cmd),
                             ERR_MARSHALLING, "Write cmd failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_DELETE_SUPPORT_COMMAND, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}
}