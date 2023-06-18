/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "avcast_controller_proxy.h"
#include "avcast_controller_callback_client.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "media_info_holder.h"

namespace OHOS::AVSession {
AVCastControllerProxy::AVCastControllerProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVCastController>(impl)
{
    SLOGD("AVCastControllerProxy construct");
}

AVCastControllerProxy::~AVCastControllerProxy()
{
    SLOGI("AVCastControllerProxy destroy");
    Destroy();
}

int32_t AVCastControllerProxy::SetMediaList(const MediaInfoHolder& mediaInfoHolder)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteParcelable(&mediaInfoHolder), ERR_UNMARSHALLING, "Write items failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_START, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVCastControllerProxy::UpdateMediaInfo(const MediaInfo& mediaInfo)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(mediaInfo.WriteToParcel(parcel), ERR_UNMARSHALLING, "Write items failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_UPDATE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVCastControllerProxy::SendControlCommand(const AVCastControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVCastControllerProxy::SendControlCommand");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    CHECK_AND_RETURN_RET_LOG(cmd.IsValid(), ERR_COMMAND_NOT_SUPPORT, "command not valid");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteParcelable(&cmd), ERR_MARSHALLING, "write cmd failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_SEND_CONTROL_COMMAND, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVCastControllerProxy::GetDuration(int32_t& duration)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_GET_DURATION, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        int32_t tempDuration;
        CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(tempDuration), ERR_UNMARSHALLING, "read string failed");
        duration = tempDuration;
    }
    return ret;
}

int32_t AVCastControllerProxy::GetPosition(int32_t& position)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_GET_POSITION, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        int32_t temoPosition;
        CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(temoPosition), ERR_UNMARSHALLING, "read string failed");
        position = temoPosition;
    }
    return ret;
}

int32_t AVCastControllerProxy::GetVolume(int32_t& volume)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_GET_VOLUME, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        int32_t tempVolume;
        CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(tempVolume), ERR_UNMARSHALLING, "read string failed");
        volume = tempVolume;
    }
    return ret;
}

int32_t AVCastControllerProxy::GetLoopMode(int32_t& loopMode)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()),
        AVSESSION_ERROR, "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, AVSESSION_ERROR, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_GET_LOOP_MODE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        int32_t tempLoopMode;
        CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(tempLoopMode), ERR_UNMARSHALLING, "read string failed");
        loopMode = tempLoopMode;
    }
    return ret;
}

int32_t AVCastControllerProxy::GetPlaySpeed(int32_t& playSpeed)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()),
        AVSESSION_ERROR, "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, AVSESSION_ERROR, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_GET_PLAY_SPEED, parcel, reply, option) == 0,
        AVSESSION_ERROR, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        int32_t tempPlaySpeed;
        CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(tempPlaySpeed), ERR_UNMARSHALLING, "read string failed");
        playSpeed = tempPlaySpeed;
    }
    return ret;
}

int32_t AVCastControllerProxy::GetPlayState(AVCastPlayerState& playState)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()),
        AVSESSION_ERROR, "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, AVSESSION_ERROR, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_GET_PLAY_STATE, parcel, reply, option) == 0,
        AVSESSION_ERROR, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        AVCastPlayerState tempPlayState;
        CHECK_AND_RETURN_RET_LOG(tempPlayState.ReadFromParcel(reply), ERR_UNMARSHALLING, "read string failed");
        playState = tempPlayState;
    }
    return ret;
}

int32_t AVCastControllerProxy::SetDisplaySurface(std::string& surfaceId)
{
    AVSESSION_TRACE_SYNC_START("AVCastControllerProxy::SetDisplaySurface");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(surfaceId), ERR_MARSHALLING, "write surfaceId failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_SET_DISPLAY_SURFACE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVCastControllerProxy::RegisterCallback(const std::shared_ptr<AVCastControllerCallback>& callback)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");

    sptr<AVCastControllerCallbackClient> callback_;
    callback_ = new(std::nothrow) AVCastControllerCallbackClient(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, ERR_NO_MEMORY, "new AVCastControllerCallbackClient failed");

    return RegisterCallbackInner(callback_);
}

int32_t AVCastControllerProxy::RegisterCallbackInner(const sptr<IRemoteObject>& callback)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteRemoteObject(callback), ERR_MARSHALLING,
        "write remote object failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_REGISTER_CALLBACK, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVCastControllerProxy::Destroy()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_DESTROY, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    isDestroy_ = true;

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}
}
