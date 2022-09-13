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

namespace OHOS::AVSession {
AVSessionCallbackClient::AVSessionCallbackClient(const std::shared_ptr<AVSessionCallback>& callback)
    : callback_(callback)
{
    if (handler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("AVSessionCallbackClient");
        handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    SLOGI("construct");
}

void AVSessionCallbackClient::OnPlay()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this]() { callback_->OnPlay(); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnPause()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this]() { callback_->OnPause(); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnStop()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this]() { callback_->OnStop(); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnPlayNext()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this]() { callback_->OnPlayNext(); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnPlayPrevious()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this]() { callback_->OnPlayPrevious(); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnFastForward()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this]() { callback_->OnFastForward(); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnRewind()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this]() { callback_->OnRewind(); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnSeek(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this, time]() { callback_->OnSeek(time); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnSetSpeed(double speed)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this, speed]() { callback_->OnSetSpeed(speed); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnSetLoopMode(int32_t loopMode)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this, loopMode]() { callback_->OnSetLoopMode(loopMode); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnToggleFavorite(const std::string& mediald)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this, mediald]() { callback_->OnToggleFavorite(mediald); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this, keyEvent]() { callback_->OnMediaKeyEvent(keyEvent); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}

void AVSessionCallbackClient::OnOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    CHECK_AND_RETURN_LOG(handler_, "handler is null");

    if (!handler_->PostTask([this, outputDeviceInfo]() { callback_->OnOutputDeviceChange(outputDeviceInfo); })) {
        SLOGI("AVSessionCallbackClient handler postTask failed");
    }
}
}