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

#include "avsession_callback_proxy.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
AVSessionCallbackProxy::AVSessionCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVSessionCallback>(impl)
{
    SLOGD("construct");
}

void AVSessionCallbackProxy::OnPlay()
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnPlay", ON_SESSION_CALLBACK_PLAY_TASK_ID);
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPause()
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnPause", ON_SESSION_CALLBACK_PAUSE_TASK_ID);
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PAUSE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnStop()
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnStop", ON_SESSION_CALLBACK_STOP_TASK_ID);
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_STOP, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlayNext()
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnPlayNext", ON_SESSION_CALLBACK_PLAY_NEXT_TASK_ID);
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY_NEXT, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlayPrevious()
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnPlayPrevious", ON_SESSION_CALLBACK_PLAY_PREVIOUS_TASK_ID);
    MessageParcel data;
    AVSessionTrace mAVSessionTrace("Proxy::OnPlayPrevious");
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY_PREVIOUS, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnFastForward()
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnFastForward", ON_SESSION_CALLBACK_FAST_FORWARD_TASK_ID);
    MessageParcel data;
    AVSessionTrace mAVSessionTrace("AVSessionCallbackProxy::OnFastForward");
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_FAST_FORWARD, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnRewind()
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnRewind", ON_SESSION_CALLBACK_REWIND_TASK_ID);
    MessageParcel data;
    AVSessionTrace mAVSessionTrace("AVSessionCallbackProxy::OnRewind");
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_REWIND, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnSeek(int64_t time)
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnSeek", ON_SESSION_CALLBACK_SEEK_TASK_ID);
    MessageParcel data;
    AVSessionTrace mAVSessionTrace("AVSessionCallbackProxy::OnSeek");
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt64(time), "write time failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SEEK, data, reply, option) == 0,
        "OnSeek send request failed");
}

void AVSessionCallbackProxy::OnSetSpeed(double speed)
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnSetSpeed", ON_SESSION_CALLBACK_SET_SPEED_TASK_ID);
    MessageParcel data;
    AVSessionTrace mAVSessionTrace("AVSessionCallbackProxy::OnSetSpeed");
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteDouble(speed), "write speed failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SET_SPEED, data, reply, option) == 0,
        "OnSetSpeed send request failed");
}

void AVSessionCallbackProxy::OnSetLoopMode(int32_t loopMode)
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnSetLoopMode", ON_SESSION_CALLBACK_SET_LOOP_MODE_TASK_ID);
    MessageParcel data;
    AVSessionTrace mAVSessionTrace("AVSessionCallbackProxy::OnSetLoopMode");
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(loopMode), "write loopMode failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_SET_LOOPMODE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnToggleFavorite(const std::string& mediaId)
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnToggleFavorite", ON_SESSION_CALLBACK_TOGGLE_FAVORITE_TASK_ID);

    MessageParcel data;
    AVSessionTrace mAVSessionTrace("AVSessionCallbackProxy::OnToggleFavorite");
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteString(mediaId), "write mediaId failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_TOGGLE_FAVORITE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSessionTrace::TraceBegin("AVSessionCallback_OnMediaKeyEvent", ON_SESSION_CALLBACK_MEDIA_KEY_EVENT_TASK_ID);

    MessageParcel data;
    AVSessionTrace mAVSessionTrace("AVSessionCallbackProxy::OnMediaKeyEvent");
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(keyEvent.WriteToParcel(data), "write keyEvent failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_MEDIA_KEY_EVENT, data, reply, option) == 0,
        "send request failed");
}
} // namespace OHOS::AVSession