/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "avsession_callback_proxy.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVSessionCallbackProxy::AVSessionCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVSessionCallback>(impl)
{
    SLOGD("construct");
}

void AVSessionCallbackProxy::OnAVCallAnswer()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_AVCALL_ANSWER, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnAVCallHangUp()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_AVCALL_HANGUP, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnAVCallToggleCallMute()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_AVCALL_TOGGLE_CALL_MUTE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlay()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_PLAY, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPause()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_PAUSE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnStop()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_STOP, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlayNext()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_PLAY_NEXT, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlayPrevious()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_PLAY_PREVIOUS, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnFastForward(int64_t time)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt64(time), "write time failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_FAST_FORWARD, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnRewind(int64_t time)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt64(time), "write time failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_REWIND, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnSeek(int64_t time)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt64(time), "write time failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_SEEK, data, reply, option) == 0,
        "OnSeek send request failed");
}

void AVSessionCallbackProxy::OnSetSpeed(double speed)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteDouble(speed), "write speed failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_SET_SPEED, data, reply, option) == 0,
        "OnSetSpeed send request failed");
}

void AVSessionCallbackProxy::OnSetLoopMode(int32_t loopMode)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(loopMode), "write loopMode failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_SET_LOOPMODE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnToggleFavorite(const std::string& mediaId)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteString(mediaId), "write mediaId failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_TOGGLE_FAVORITE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(keyEvent.WriteToParcel(data), "write keyEvent failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_MEDIA_KEY_EVENT, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnOutputDeviceChange(const int32_t connectionState,
    const OutputDeviceInfo& outputDeviceInfo)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(connectionState), "write connectionState failed");

    int32_t deviceInfoSize = static_cast<int32_t>(outputDeviceInfo.deviceInfos_.size());
    CHECK_AND_RETURN_LOG(data.WriteInt32(deviceInfoSize), "write deviceInfoSize failed");
    for (DeviceInfo deviceInfo : outputDeviceInfo.deviceInfos_) {
        CHECK_AND_RETURN_LOG(data.WriteInt32(deviceInfo.castCategory_), "write castCategory failed");
        CHECK_AND_RETURN_LOG(data.WriteString(deviceInfo.deviceId_), "write deviceId failed");
        CHECK_AND_RETURN_LOG(data.WriteString(deviceInfo.deviceName_), "write deviceName failed");
        CHECK_AND_RETURN_LOG(data.WriteInt32(deviceInfo.deviceType_), "write deviceType failed");
        CHECK_AND_RETURN_LOG(data.WriteString(deviceInfo.ipAddress_), "write ipAddress failed");
        CHECK_AND_RETURN_LOG(data.WriteInt32(deviceInfo.providerId_), "write providerId failed");
        CHECK_AND_RETURN_LOG(data.WriteInt32(deviceInfo.supportedProtocols_),
            "write supportedProtocols failed");
        CHECK_AND_RETURN_LOG(data.WriteInt32(deviceInfo.authenticationStatus_),
            "write authenticationStatus failed");
    }

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_OUTPUT_DEVICE_CHANGE, data, reply, option) == 0,
                         "send request failed");
}

void AVSessionCallbackProxy::OnCommonCommand(const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "Write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteString(commonCommand), "Write event string failed");
    CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&commandArgs), "Write Want failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "Get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_SEND_COMMON_COMMAND, parcel, reply, option) == 0,
        "Send request failed");
}

void AVSessionCallbackProxy::OnSkipToQueueItem(int32_t itemId)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(itemId), "write itemId failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(SESSION_CALLBACK_ON_SKIP_TO_QUEUE_ITEM, data, reply, option) == 0,
        "send request failed");
}
} // namespace OHOS::AVSession
