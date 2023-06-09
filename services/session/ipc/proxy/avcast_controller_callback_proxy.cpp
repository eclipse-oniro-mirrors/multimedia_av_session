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

#include "avcast_controller_callback_proxy.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVCastControllerCallbackProxy::AVCastControllerCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVCastControllerCallback>(impl)
{
    SLOGD("construct");
}

void AVCastControllerCallbackProxy::OnStateChange(const AVCastPlayerState& state)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteString(state.castPlayerState_), "write cast PlaybackState failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_STATE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&avQueueItem), "Write avQueueItem failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_MEDIA_ITEM_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnVolumeChange(const int32_t volume)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(volume), "write volume failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_VOLUME_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnLoopModeChange(const int32_t loopMode)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(loopMode), "write loopMode failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_LOOP_MODE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnPlaySpeedChange(const int32_t speed)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(speed), "write speed failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_PLAY_SPEED_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnPositionChange(const int32_t seek)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(seek), "write seek failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_POSITION_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnVideoSizeChange(const int32_t width, const int32_t height)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(width), "write width failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(height), "write height failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_VIDEO_SIZE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnError(const int32_t errorCode, const std::string& errorMsg)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(errorCode), "write time failed");
    CHECK_AND_RETURN_LOG(parcel.WriteString(errorMsg), "write time failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_ERROR, parcel, reply, option) == 0,
        "send request failed");
}
} // namespace OHOS::AVSession
