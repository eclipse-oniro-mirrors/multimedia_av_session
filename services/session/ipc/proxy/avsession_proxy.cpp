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

AVSessionProxy::~AVSessionProxy()
{
    SLOGI("destroy");
    Destroy();
}

std::string AVSessionProxy::GetSessionId()
{
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, "", "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), "", "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, "", "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SESSION_CMD_GET_SESSION_ID, data, reply, option) == 0,
        "", "send request failed");

    std::string sessionId;
    CHECK_AND_RETURN_RET_LOG(reply.ReadString(sessionId), "", "read sessionId failed");
    return sessionId;
}

int32_t AVSessionProxy::RegisterCallback(const std::shared_ptr<AVSessionCallback> &callback)
{
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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
    SLOGD("enter");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_DESTROY, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    if (!reply.ReadInt32(ret)) {
        return AVSESSION_ERROR;
    }
    if (ret == AVSESSION_SUCCESS) {
        isDestroyed_ = true;
        controller_ = nullptr;
    }
    return ret;
}

int32_t AVSessionProxy::SetAVMetaData(const AVMetaData& meta)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetAVMetaData");
    CHECK_AND_RETURN_RET_LOG(meta.IsValid(), AVSESSION_ERROR, "invalid meta data");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetAVPlaybackState");
    CHECK_AND_RETURN_RET_LOG(state.IsValid(), ERR_INVALID_PARAM, "state not valid");
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, nullptr, "session is destroyed");
    CHECK_AND_RETURN_RET_LOG(controller_ == nullptr || controller_->IsDestroy(), controller_,
        "controller already exist");
    sptr <IRemoteObject> object = GetControllerInner();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "get object failed");
    auto controller = iface_cast<AVSessionControllerProxy>(object);
    controller_ = std::shared_ptr<AVSessionController>(controller.GetRefPtr(), [holder = controller](const auto*) {});
    return controller_;
}

int32_t AVSessionProxy::Activate()
{
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_ACTIVATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::Deactivate()
{
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "remote is nullptr");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_DEACTIVATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

bool AVSessionProxy::IsActive()
{
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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
    CHECK_AND_RETURN_RET_LOG(isDestroyed_ == false, ERR_SESSION_NOT_EXIST, "session is destroyed");
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