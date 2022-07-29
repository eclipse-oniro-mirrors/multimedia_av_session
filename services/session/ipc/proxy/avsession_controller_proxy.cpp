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

#include "avsession_controller_proxy.h"

#include "avcontroller_callback_client.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
AVSessionControllerProxy::AVSessionControllerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVSessionController>(impl)
{
    SLOGD("construct");
}

int32_t AVSessionControllerProxy::GetAVPlaybackState(AVPlaybackState &state)
{
    AVSessionTrace trace("AVSessionControllerProxy::GetAVPlaybackState");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_AV_PLAYBACK_STATE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        sptr<AVPlaybackState> state_ = reply.ReadParcelable<AVPlaybackState>();
        CHECK_AND_RETURN_RET_LOG(state_ != nullptr, ERR_UNMARSHALLING, "read AVPlaybackState failed");
        state = *state_;
        currentState_ = *state_;
    }
    return ret;
}

int32_t AVSessionControllerProxy::GetAVMetaData(AVMetaData &data)
{
    AVSessionTrace trace("AVSessionControllerProxy::GetAVMetaData");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
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

int32_t AVSessionControllerProxy::SendAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSessionTrace trace("AVSessionControllerProxy::SendAVKeyEvent");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    CHECK_AND_RETURN_RET_LOG(keyEvent.IsValid(), ERR_INVALID_PARAM, "keyEvent not valid");
    bool isActive {};
    CHECK_AND_RETURN_RET_LOG(IsSessionActive(isActive) == AVSESSION_SUCCESS &&
        isActive, ERR_SESSION_DEACTIVE, "session is deactivate");

    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(keyEvent.WriteToParcel(parcel), ERR_MARSHALLING, "write keyEvent failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SEND_AV_KEYEVENT, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent &ability)
{
    AVSessionTrace trace("AVSessionControllerProxy::GetLaunchAbility");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
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

int32_t AVSessionControllerProxy::GetValidCommands(std::vector<int32_t> &cmds)
{
    AVSessionTrace trace("AVSessionControllerProxy::GetValidCommands");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_VALID_COMMANDS, parcel, reply, option) == 0,
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
    AVSessionTrace trace("AVSessionControllerProxy::IsSessionActive");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_IS_SESSION_ACTIVE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.ReadBool(isActive), ERR_UNMARSHALLING, "read bool failed");
    }
    return ret;
}

int32_t AVSessionControllerProxy::SendControlCommand(const AVControlCommand &cmd)
{
    AVSessionTrace trace("AVSessionControllerProxy::SendControlCommand");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    CHECK_AND_RETURN_RET_LOG(cmd.IsValid(), ERR_INVALID_PARAM, "command not valid");
    bool isActive {};
    CHECK_AND_RETURN_RET_LOG(IsSessionActive(isActive) == AVSESSION_SUCCESS &&
        isActive, ERR_SESSION_DEACTIVE, "session is deactivate");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteParcelable(&cmd), ERR_MARSHALLING, "write cmd failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SEND_CONTROL_COMMAND, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::SetMetaFilter(const AVMetaData::MetaMaskType &filter)
{
    AVSessionTrace trace("AVSessionControllerProxy::SetMetaFilter");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(filter.to_string()), ERR_MARSHALLING, "write filter failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SET_META_FILTER, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType &filter)
{
    AVSessionTrace trace("AVSessionControllerProxy::SetPlaybackFilter");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(filter.to_string()), ERR_MARSHALLING, "write filter failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SET_PLAYBACK_FILTER, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::RegisterCallback(const std::shared_ptr<AVControllerCallback> &callback)
{
    AVSessionTrace trace("AVSessionControllerProxy::RegisterCallback");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");

    sptr<AVControllerCallbackClient> callback_;
    callback_ = new(std::nothrow) AVControllerCallbackClient(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, ERR_NO_MEMORY, "new AVControllerCallbackClient failed");

    callback_->AddListenerForPlaybackState([this](const AVPlaybackState &state) { currentState_ = state; });

    return RegisterCallbackInner(callback_);
}

int32_t AVSessionControllerProxy::RegisterCallbackInner(const sptr<IRemoteObject> &callback)
{
    AVSessionTrace trace("AVSessionControllerProxy::RegisterCallbackInner");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteRemoteObject(callback), ERR_MARSHALLING,
        "write remote object failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_REGISTER_CALLBACK, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::Destroy()
{
    AVSessionTrace trace("AVSessionControllerProxy::Destroy");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_DESTROY, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    isDestroy_ = true;

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

std::string AVSessionControllerProxy::GetSessionId()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, "", "controller is destroy");
    AVSessionTrace trace("AVSessionControllerProxy::GetSessionId");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "", "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, "", "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_SESSION_ID, parcel, reply, option) == 0,
        "", "send request failed");

    std::string result;
    return reply.ReadString(result) ? result : "";
}

int64_t AVSessionControllerProxy::GetRealPlaybackPosition()
{
    AVSessionTrace trace("AVSessionControllerProxy::GetRealPlaybackPosition");
    auto position = currentState_.GetPosition();
    CHECK_AND_RETURN_RET_LOG(position.updateTime_ > 0, 0, "playbackState not update");
    auto now = std::chrono::system_clock::now();
    auto nowMS = std::chrono::time_point_cast<std::chrono::milliseconds>(now);

    int64_t currentSysTime = nowMS.time_since_epoch().count();
    SLOGI("elapsedTime:%{public}" PRId64 ", currentSysTime:%{public}" PRId64 ", updateTime:%{public}" PRId64,
          position.elapsedTime_, currentSysTime, position.updateTime_);

    return (position.elapsedTime_ + (currentSysTime - position.updateTime_));
}
}