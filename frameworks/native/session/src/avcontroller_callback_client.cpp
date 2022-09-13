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

namespace OHOS::AVSession {
AVControllerCallbackClient::AVControllerCallbackClient(const std::shared_ptr<AVControllerCallback>& callback)
    : callback_(callback)
{
    if (handler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("AVControllerCallbackClient");
        handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    SLOGD("construct");
}

void AVControllerCallbackClient::OnSessionDestroy()
{
    if (callback_) {
        if (!handler_->PostTask([this]() { callback_->OnSessionDestroy(); })) {
            SLOGI("AVSessionCallbackClient handler postTask failed");
        }
    }
}

void AVControllerCallbackClient::OnPlaybackStateChange(const AVPlaybackState &state)
{
    if (callback_) {
        if (!handler_->PostTask([this, state]() { callback_->OnPlaybackStateChange(state); })) {
            SLOGI("AVSessionCallbackClient handler postTask failed");
        }
    }
    if (playbackStateListener_) {
        playbackStateListener_(state);
    }
}

void AVControllerCallbackClient::OnMetaDataChange(const AVMetaData &data)
{
    if (callback_) {
        if (!handler_->PostTask([this, data]() { callback_->OnMetaDataChange(data); })) {
            SLOGI("AVSessionCallbackClient handler postTask failed");
        }
    }
}

void AVControllerCallbackClient::OnActiveStateChange(bool isActive)
{
    if (callback_) {
        if (!handler_->PostTask([this, isActive]() { callback_->OnActiveStateChange(isActive); })) {
            SLOGI("AVSessionCallbackClient handler postTask failed");
        }
    }
}

void AVControllerCallbackClient::OnValidCommandChange(const std::vector<int32_t> &cmds)
{
    if (callback_) {
        if (!handler_->PostTask([this, cmds]() { callback_->OnValidCommandChange(cmds); })) {
            SLOGI("AVSessionCallbackClient handler postTask failed");
        }
    }
}

void AVControllerCallbackClient::OnOutputDeviceChange(const OutputDeviceInfo &info)
{
    if (callback_) {
        if (!handler_->PostTask([this, info]() { callback_->OnOutputDeviceChange(info); })) {
            SLOGI("AVSessionCallbackClient handler postTask failed");
        }
    }
}

void AVControllerCallbackClient::AddListenerForPlaybackState(const std::function<void(const AVPlaybackState&)>
    &listener)
{
    playbackStateListener_ = listener;
}
}