/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

void AVSessionCallbackProxy::OnPlay()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnPlay write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY, data, reply, option) == 0,
        "OnPlay send request failed");
}

void AVSessionCallbackProxy::OnPause()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnPause write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PAUSE, data, reply, option) == 0,
        "OnPause send request failed");
}

void AVSessionCallbackProxy::OnStop()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnStop write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_STOP, data, reply, option) == 0,
        "OnStop send request failed");
}

void AVSessionCallbackProxy::OnPlayNext()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnPlayNext write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY_NEXT, data, reply, option) == 0,
        "OnPlayNext send request failed");
}

void AVSessionCallbackProxy::OnPlayPrevious()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnPlayPrevious write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY_PREVIOUS, data, reply, option) == 0,
        "OnPlayPrevious send request failed");
}

void AVSessionCallbackProxy::OnFastForward()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnFastForward write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_FAST_FORWARD, data, reply, option) == 0,
        "OnFastForward send request failed");
}

void AVSessionCallbackProxy::OnRewind()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnRewind write interface token failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_REWIND, data, reply, option) == 0,
        "OnRewind send request failed");
}

void AVSessionCallbackProxy::OnSeek(int64_t time)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnSeek write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt64(time), "OnSeek write time failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SEEK, data, reply, option) == 0,
        "OnSeek send request failed");
}

void AVSessionCallbackProxy::OnSetSpeed(int32_t speed)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnSetSpeed write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(speed), "OnSetSpeed write speed failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SEEK, data, reply, option) == 0,
        "OnSetSpeed send request failed");
}

void AVSessionCallbackProxy::OnSetLoopMode(int32_t loopMode)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnSetLoopMode write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(loopMode), "OnSetLoopMode write loopMode failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SET_LOOPMODE, data, reply, option) == 0,
        "OnSetLoopMode send request failed");
}

void AVSessionCallbackProxy::OnToggleFavorite(const std::string& mediald)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnToggleFavorite write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteString(mediald), "OnToggleFavorite write mediald failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_TOGGLE_FAVORITE, data, reply, option) == 0,
        "OnToggleFavorite send request failed");
}

void AVSessionCallbackProxy::OnVolumeChanged(const AVVolumeInfo& volume)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "OnVolumeChanged write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(volume.currentVolume_), "OnVolumeChanged write volume currentVolume failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(volume.maxVolume_), "OnVolumeChanged write volume maxVolume failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(volume.volumeType_), "OnVolumeChanged write volume volumeType failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_VOLUME_CHANGED, data, reply, option) == 0,
        "OnVolumeChanged send request failed");
}

void AVSessionCallbackProxy::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(keyEvent.WriteToParcel(data), "write keyEvent failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_MEDIA_KEY_EVENT, data, reply, option) == 0,
        "send request failed");
}
} // namespace OHOS::AVSession