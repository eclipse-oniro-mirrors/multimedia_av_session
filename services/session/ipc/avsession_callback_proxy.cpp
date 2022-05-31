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
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPause()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PAUSE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnStop()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_STOP, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlayNext()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY_NEXT, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlayPrevious()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY_PREVIOUS, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnFastForward()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_FAST_FORWARD, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnRewind()
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_REWIND, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnSeek(int64_t time)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt64(time), "write time failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SEEK, data, reply, option) == 0,
        "OnSeek send request failed");
}

void AVSessionCallbackProxy::OnSetSpeed(int32_t speed)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(speed), "write speed failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SEEK, data, reply, option) == 0,
        "OnSetSpeed send request failed");
}

void AVSessionCallbackProxy::OnSetLoopMode(int32_t loopMode)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(loopMode), "write loopMode failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SET_LOOPMODE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnToggleFavorite(const std::string& mediaId)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteString(mediald), "write mediald failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_TOGGLE_FAVORITE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(keyEvent.WriteToParcel(data), "write keyEvent failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_MEDIA_KEY_EVENT, data, reply, option) == 0,
        "send request failed");
}
} // namespace OHOS::AVSession