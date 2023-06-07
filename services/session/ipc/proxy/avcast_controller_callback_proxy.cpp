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


void AVCastControllerCallbackProxy::OnStateChanged(const AVCastPlayerState& state)
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

void AVCastControllerCallbackProxy::OnVolumeChanged(const int32_t volume)
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

void AVCastControllerCallbackProxy::OnSeekDone(const int32_t seek)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(seek), "write seek failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_SEEK_DONE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnPlaySpeedChanged(const int32_t speed)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(speed), "write speed failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_SPEED_DONE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnTimeUpdate(const int32_t time)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(time), "write time failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_TIME_UPDATE, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
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
