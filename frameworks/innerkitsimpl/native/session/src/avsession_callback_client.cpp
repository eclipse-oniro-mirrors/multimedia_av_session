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

#include "avsession_callback_client.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
AVSessionCallbackClient::AVSessionCallbackClient(const std::shared_ptr<AVSessionCallback>& callback)
    : callback_(callback)
{
    SLOGI("construct");
}

void AVSessionCallbackClient::OnPlay()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnPlay", ON_SESSION_CALLBACK_PLAY_TASK_ID);
    callback_->OnPlay();
}

void AVSessionCallbackClient::OnPause()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnPause", ON_SESSION_CALLBACK_PAUSE_TASK_ID);
    callback_->OnPause();
}

void AVSessionCallbackClient::OnStop()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnStop", ON_SESSION_CALLBACK_STOP_TASK_ID);
    callback_->OnStop();
}

void AVSessionCallbackClient::OnPlayNext()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnPlayNext", ON_SESSION_CALLBACK_PLAY_NEXT_TASK_ID);
    callback_->OnPlayNext();
}

void AVSessionCallbackClient::OnPlayPrevious()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnPlayPrevious", ON_SESSION_CALLBACK_PLAY_PREVIOUS_TASK_ID);
    callback_->OnPlayPrevious();
}

void AVSessionCallbackClient::OnFastForward()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnFastForward", ON_SESSION_CALLBACK_FAST_FORWARD_TASK_ID);
    callback_->OnFastForward();
}

void AVSessionCallbackClient::OnRewind()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnRewind", ON_SESSION_CALLBACK_REWIND_TASK_ID);
    callback_->OnRewind();
}

void AVSessionCallbackClient::OnSeek(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnSeek", ON_SESSION_CALLBACK_SEEK_TASK_ID);
    callback_->OnSeek(time);
}

void AVSessionCallbackClient::OnSetSpeed(double speed)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnSetSpeed", ON_SESSION_CALLBACK_SET_SPEED_TASK_ID);
    callback_->OnSetSpeed(speed);
}

void AVSessionCallbackClient::OnSetLoopMode(int32_t loopMode)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnSetLoopMode", ON_SESSION_CALLBACK_SET_LOOP_MODE_TASK_ID);
    callback_->OnSetLoopMode(loopMode);
}

void AVSessionCallbackClient::OnToggleFavorite(const std::string& mediald)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnToggleFavorite", ON_SESSION_CALLBACK_TOGGLE_FAVORITE_TASK_ID);
    callback_->OnToggleFavorite(mediald);
}

void AVSessionCallbackClient::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    AVSessionTrace::TraceEnd("AVSessionCallback_OnMediaKeyEvent", ON_SESSION_CALLBACK_MEDIA_KEY_EVENT_TASK_ID);
    callback_->OnMediaKeyEvent(keyEvent);
}
}