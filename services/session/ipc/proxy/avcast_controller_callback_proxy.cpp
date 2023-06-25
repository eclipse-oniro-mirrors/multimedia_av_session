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

#include "avcast_controller_callback_proxy.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVCastControllerCallbackProxy::AVCastControllerCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVCastControllerCallback>(impl)
{
    SLOGD("construct");
}

void AVCastControllerCallbackProxy::OnCastPlaybackStateChange(const AVPlaybackState& state)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&state), "write PlaybackState failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_CAST_PLAYBACK_STATE_CHANGE,
        parcel, reply, option) == 0,
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

void AVCastControllerCallbackProxy::OnPlayNext()
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_PLAY_NEXT, parcel, reply, option) == 0,
        "send request failed");
}

void AVCastControllerCallbackProxy::OnPlayPrevious()
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CAST_CONTROLLER_CMD_ON_PLAY_PREVIOUS, parcel, reply, option) == 0,
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
