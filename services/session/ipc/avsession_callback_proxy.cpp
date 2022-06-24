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
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnPlay", ON_SESSIONCALLBACK_PLAYTASK_ID);
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPause()
{
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnPause", ON_SESSIONCALLBACK_PAUSETASK_ID);
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PAUSE, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnStop()
{
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnStop", ON_SESSIONCALLBACK_STOPTASK_ID);
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_STOP, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlayNext()
{
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnPlayNext", ON_SESSIONCALLBACK_PLAYNEXTTASK_ID);
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(Remote()->SendRequest(SESSION_CALLBACK_ON_PLAY_NEXT, data, reply, option) == 0,
        "send request failed");
}

void AVSessionCallbackProxy::OnPlayPrevious()
{
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnPlayPrevious", ON_SESSIONCALLBACK_PLAYPREVIOUSTASK_ID);
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
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnFastForward", ON_SESSIONCALLBACK_FASTFORWARDTASK_ID);
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
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnRewind", ON_SESSIONCALLBACK_REWINDTASK_ID);
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
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnSeek", ON_SESSIONCALLBACK_SEEKTASK_ID);
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
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnSetSpeed", ON_SESSIONCALLBACK_SETSPEEDTASK_ID);
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
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnSetLoopMode", ON_SESSIONCALLBACK_SETLOOPMODETASK_ID);
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
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnToggleFavorite", ON_SESSIONCALLBACK_TOGGLEFAVORITETASK_ID);
    
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
    AVSessionTrace::TraceBegin("AVSessionCallbackProxy::OnMediaKeyEvent", ON_SESSIONCALLBACK_MEDIAKEYEVENTTASK_ID);
    
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