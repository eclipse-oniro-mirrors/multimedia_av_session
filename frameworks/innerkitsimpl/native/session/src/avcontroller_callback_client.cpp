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

#include "avcontroller_callback_client.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
AVControllerCallbackClient::AVControllerCallbackClient(const std::shared_ptr<AVControllerCallback>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void AVControllerCallbackClient::OnSessionDestroy()
{
    if (callback_) {
        callback_->OnSessionDestroy();
    }
    AVSessionTrace::TraceEnd("AVControllerCallback::OnSessionDestroy", ON_SESSION_DESTROY_TASK_ID);
}

void AVControllerCallbackClient::OnPlaybackStateChange(const AVPlaybackState &state)
{
    if (callback_) {
        callback_->OnPlaybackStateChange(state);
    }
    if (playbackStateListener_) {
        playbackStateListener_(state);
    }
    AVSessionTrace::TraceEnd("AVControllerCallback::OnPlaybackStateChange", ON_PLAYBACK_STATE_CHANGE_TASK_ID);
}

void AVControllerCallbackClient::OnMetaDataChange(const AVMetaData &data)
{
    if (callback_) {
        callback_->OnMetaDataChange(data);
    }
    AVSessionTrace::TraceEnd("AVControllerCallback::OnMetaDataChange", ON_MEDA_DATA_CHANGE_TASK_ID);
}

void AVControllerCallbackClient::OnActiveStateChange(bool isActive)
{
    if (callback_) {
        callback_->OnActiveStateChange(isActive);
    }
    AVSessionTrace::TraceEnd("AVControllerCallback::OnActiveStateChange", ON_ACTIVE_STATE_CHANGE_TASK_ID);
}

void AVControllerCallbackClient::OnValidCommandChange(const std::vector<int32_t> &cmds)
{
    if (callback_) {
        callback_->OnValidCommandChange(cmds);
    }
    AVSessionTrace::TraceEnd("AVControllerCallback::OnValidCommandChange", ON_VALID_COMMAND_CHANGE_TASK_ID);
}

void AVControllerCallbackClient::AddListenerForPlaybackState(const std::function<void(const AVPlaybackState&)>
    &listener)
{
    playbackStateListener_ = listener;
}
}