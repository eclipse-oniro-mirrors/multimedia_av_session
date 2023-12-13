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
AVSessionControllerProxy::AVSessionControllerProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVSessionController>(impl)
{
    SLOGD("construct");
}

AVSessionControllerProxy::~AVSessionControllerProxy()
{
    SLOGI("destroy");
    Destroy();
}

int32_t AVSessionControllerProxy::GetAVCallMetaData(AVCallMetaData& avCallMetaData)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_AVCALL_META_DATA, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        sptr<AVCallMetaData> data = reply.ReadParcelable<AVCallMetaData>();
        CHECK_AND_RETURN_RET_LOG(data != nullptr, ERR_UNMARSHALLING, "read AVCallMetaData failed");
        avCallMetaData = *data;
    }
    return ret;
}

int32_t AVSessionControllerProxy::GetAVCallState(AVCallState& avCallState)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_AVCALL_STATE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        AVCallState* statePtr = reply.ReadParcelable<AVCallState>();
        CHECK_AND_RETURN_RET_LOG(statePtr != nullptr, ERR_UNMARSHALLING, "read AVCallState failed");
        avCallState = *statePtr;
    }
    return ret;
}

int32_t AVSessionControllerProxy::GetAVPlaybackState(AVPlaybackState& state)
{
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
        AVPlaybackState* statePtr = reply.ReadParcelable<AVPlaybackState>();
        CHECK_AND_RETURN_RET_LOG(statePtr != nullptr, ERR_UNMARSHALLING, "read AVPlaybackState failed");
        state = *statePtr;

        std::lock_guard lockGuard(currentStateLock_);
        currentState_ = *statePtr;
    }
    return ret;
}

int32_t AVSessionControllerProxy::GetAVMetaData(AVMetaData& data)
{
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

    int twoImageLength = reply.ReadInt32();
    if (twoImageLength == 0) {
        sptr<AVMetaData> data_ = reply.ReadParcelable<AVMetaData>();
        CHECK_AND_RETURN_RET_LOG(data_ != nullptr, ERR_UNMARSHALLING, "read AVMetaData failed");
        data = *data_;
        return AVSESSION_SUCCESS;
    }
    
    AVMetaData::UnmarshallingExceptImg(reply, data);
    const char *buffer = nullptr;
    if ((buffer = reinterpret_cast<const char *>(reply.ReadRawData(twoImageLength))) == nullptr) {
        SLOGE("read raw data failed, length = %{public}d", twoImageLength);
        return AVSESSION_ERROR;
    }
    
    int mediaImageLength = data.GetMediaLength();
    auto mediaPixelMap = new (std::nothrow) AVSessionPixelMap();
    std::vector<uint8_t> mediaImageBuffer;
    for (int i = 0; i < mediaImageLength; i++) {
        mediaImageBuffer.push_back((uint8_t)buffer[i]);
    }
    mediaPixelMap->SetInnerImgBuffer(mediaImageBuffer);
    data.SetMediaImage(std::shared_ptr<AVSessionPixelMap>(mediaPixelMap));
    
    if (twoImageLength > mediaImageLength) {
        auto avQueuePixelMap = new (std::nothrow) AVSessionPixelMap();
        std::vector<uint8_t> avQueueImageBuffer;
        for (int i = mediaImageLength; i < twoImageLength; i++) {
            avQueueImageBuffer.push_back((uint8_t)buffer[i]);
        }
        avQueuePixelMap->SetInnerImgBuffer(avQueueImageBuffer);
        data.SetAVQueueImage(std::shared_ptr<AVSessionPixelMap>(avQueuePixelMap));
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionControllerProxy::GetAVQueueItems(std::vector<AVQueueItem>& items)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_AV_QUEUE_ITEMS, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::vector<AVQueueItem> items_;
        int32_t itemNum = reply.ReadInt32();
        CHECK_AND_RETURN_RET_LOG(itemNum >= 0, ERR_UNMARSHALLING, "read int32 itemNum failed");
        for (int32_t i = 0; i < itemNum; i++) {
            AVQueueItem *item = reply.ReadParcelable<AVQueueItem>();
            CHECK_AND_RETURN_RET_LOG(item != nullptr, ERR_UNMARSHALLING, "read parcelable AVQueueItem failed");
            items_.emplace_back(*item);
            delete item;
        }
        items = items_;
    }
    return ret;
}

int32_t AVSessionControllerProxy::GetAVQueueTitle(std::string& title)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_AV_QUEUE_TITLE, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::string title_;
        CHECK_AND_RETURN_RET_LOG(reply.ReadString(title_), ERR_UNMARSHALLING, "read string failed");
        title = title_;
    }
    return ret;
}

int32_t AVSessionControllerProxy::SkipToQueueItem(int32_t& itemId)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(itemId), ERR_MARSHALLING, "write interface token failed");
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SKIP_TO_QUEUE_ITEM, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::GetExtras(AAFwk::WantParams& extras)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_GET_EXTRAS, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        sptr<AAFwk::WantParams> extras_ = reply.ReadParcelable<AAFwk::WantParams>();
        CHECK_AND_RETURN_RET_LOG(extras_ != nullptr, ERR_UNMARSHALLING, "read extras failed");
        extras = *extras_;
    }
    return ret;
}

int32_t AVSessionControllerProxy::SendAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerProxy::SendAVKeyEvent");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    CHECK_AND_RETURN_RET_LOG(keyEvent.IsValid(), ERR_COMMAND_NOT_SUPPORT, "keyEvent not valid");
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

int32_t AVSessionControllerProxy::GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent& ability)
{
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

int32_t AVSessionControllerProxy::GetValidCommands(std::vector<int32_t>& cmds)
{
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

int32_t AVSessionControllerProxy::IsSessionActive(bool& isActive)
{
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

int32_t AVSessionControllerProxy::SendControlCommand(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerProxy::SendControlCommand");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    CHECK_AND_RETURN_RET_LOG(cmd.IsValid(), ERR_COMMAND_NOT_SUPPORT, "command not valid");
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
    std::lock_guard lockGuard(controllerProxyLock_);
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SEND_CONTROL_COMMAND, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::SendCommonCommand(const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerProxy::SendCommonCommand");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "Controller is destroy");
    bool isActive {};
    CHECK_AND_RETURN_RET_LOG(IsSessionActive(isActive) == AVSESSION_SUCCESS &&
        isActive, ERR_SESSION_DEACTIVE, "Session is deactivate");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "Write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(commonCommand), ERR_MARSHALLING, "Write commonCommand string failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteParcelable(&commandArgs),
        ERR_MARSHALLING, "Write args failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "Get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SEND_COMMON_COMMAND, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "Send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::SetAVCallMetaFilter(const AVCallMetaData::AVCallMetaMaskType& filter)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(filter.to_string()), ERR_MARSHALLING, "write filter failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SET_AVCALL_META_FILTER, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::SetAVCallStateFilter(const AVCallState::AVCallStateMaskType& filter)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(filter.to_string()), ERR_MARSHALLING, "write filter failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_SET_AVCALL_STATE_FILTER, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::SetMetaFilter(const AVMetaData::MetaMaskType& filter)
{
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

int32_t AVSessionControllerProxy::SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter)
{
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

int32_t AVSessionControllerProxy::RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");

    sptr<AVControllerCallbackClient> callback_;
    callback_ = new(std::nothrow) AVControllerCallbackClient(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, ERR_NO_MEMORY, "new AVControllerCallbackClient failed");

    callback_->AddListenerForPlaybackState([this](const AVPlaybackState& state) {
        std::lock_guard lockGuard(currentStateLock_);
        currentState_ = state;
    });

    return RegisterCallbackInner(callback_);
}

int32_t AVSessionControllerProxy::RegisterCallbackInner(const sptr<IRemoteObject>& callback)
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
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_REGISTER_CALLBACK, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionControllerProxy::Destroy()
{
    SLOGI("Proxy received destroy event");
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, ERR_CONTROLLER_NOT_EXIST, "controller is destroy");
    MessageParcel parcel;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
        "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    MessageParcel reply;
    MessageOption option;
    std::lock_guard lockGuard(controllerProxyLock_);
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(CONTROLLER_CMD_DESTROY, parcel, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");
    isDestroy_ = true;

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

std::string AVSessionControllerProxy::GetSessionId()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroy_, "", "controller is destroy");
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
    AVPlaybackState::Position position;
    {
        std::lock_guard lockGuard(currentStateLock_);
        position = currentState_.GetPosition();
    }
    CHECK_AND_RETURN_RET_LOG(position.updateTime_ > 0, 0, "playbackState not update");
    auto now = std::chrono::system_clock::now();
    auto nowMS = std::chrono::time_point_cast<std::chrono::milliseconds>(now);

    int64_t currentSysTime = nowMS.time_since_epoch().count();
    SLOGI("elapsedTime:%{public}" PRId64 ", currentSysTime:%{public}" PRId64 ", updateTime:%{public}" PRId64,
          position.elapsedTime_, currentSysTime, position.updateTime_);

    return (position.elapsedTime_ + (currentSysTime - position.updateTime_));
}

bool AVSessionControllerProxy::IsDestroy()
{
    return isDestroy_;
}
}
