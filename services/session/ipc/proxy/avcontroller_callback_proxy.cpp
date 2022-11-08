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

#include "avcontroller_callback_proxy.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVControllerCallbackProxy::AVControllerCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVControllerCallback>(impl)
{
    SLOGD("construct");
}

void AVControllerCallbackProxy::OnSessionDestroy()
{
    MessageParcel parcel;
    CHECK_AND_PRINT_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_PRINT_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_PRINT_LOG(remote->SendRequest(CONTROLLER_CMD_ON_SESSION_DESTROY, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnPlaybackStateChange(const AVPlaybackState& state)
{
    MessageParcel parcel;
    CHECK_AND_PRINT_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_PRINT_LOG(parcel.WriteParcelable(&state), "write PlaybackState failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_PRINT_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_PRINT_LOG(remote->SendRequest(CONTROLLER_CMD_ON_PLAYBACK_STATE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnMetaDataChange(const AVMetaData& data)
{
    MessageParcel parcel;
    CHECK_AND_PRINT_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_PRINT_LOG(parcel.WriteParcelable(&data), "write AVMetaData failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_PRINT_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_PRINT_LOG(remote->SendRequest(CONTROLLER_CMD_ON_METADATA_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnActiveStateChange(bool isActive)
{
    MessageParcel parcel;
    CHECK_AND_PRINT_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_PRINT_LOG(parcel.WriteBool(isActive), "write bool failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_PRINT_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_PRINT_LOG(remote->SendRequest(CONTROLLER_CMD_ON_ACTIVE_STATE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    MessageParcel parcel;
    CHECK_AND_PRINT_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_PRINT_LOG(parcel.WriteInt32Vector(cmds), "write int32 vector failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_PRINT_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_PRINT_LOG(remote->SendRequest(CONTROLLER_CMD_ON_VALID_COMMAND_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteBool(outputDeviceInfo.isRemote_), "write isRemote_ failed");
    CHECK_AND_RETURN_LOG(parcel.WriteStringVector(outputDeviceInfo.deviceIds_), "write deviceIds_ failed");
    CHECK_AND_RETURN_LOG(parcel.WriteStringVector(outputDeviceInfo.deviceNames_), "write deviceNames_ failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_PRINT_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_PRINT_LOG(remote->SendRequest(CONTROLLER_CMD_ON_OUTPUT_DEVICE_CHANGE, parcel, reply, option) == 0,
                        "send request failed");
}
}