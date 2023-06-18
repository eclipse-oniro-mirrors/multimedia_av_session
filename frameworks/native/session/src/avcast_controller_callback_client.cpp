/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "avcast_controller_callback_client.h"
#include "avsession_log.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {
AVCastControllerCallbackClient::AVCastControllerCallbackClient(
    const std::shared_ptr<AVCastControllerCallback>& callback) : callback_(callback)
{
    SLOGD("construct");
}

void AVCastControllerCallbackClient::OnStateChanged(const AVCastPlayerState& state)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, state]() { callback->OnStateChanged(state); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnMediaItemChanged(const AVQueueItem& avQueueItem)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, avQueueItem]() { callback->OnMediaItemChanged(avQueueItem); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnVolumeChanged(const int32_t volume)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, volume]() { callback->OnVolumeChanged(volume); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnLoopModeChanged(const int32_t loopMode)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, loopMode]() { callback->OnLoopModeChanged(loopMode); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnPlaySpeedChanged(const int32_t playSpeed)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, playSpeed]() { callback->OnPlaySpeedChanged(playSpeed); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnPositionChanged(const int32_t position,
    const int32_t bufferPosition, const int32_t duration)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, position, bufferPosition, duration]() {
            callback->OnPositionChanged(position, bufferPosition, duration);
        }, EVENT_NAME), "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnVideoSizeChanged(const int32_t width, const int32_t height)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, width, height]() {
            callback->OnVideoSizeChanged(width, height);
        }, EVENT_NAME), "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, errorCode, errorMsg]() {
            callback->OnPlayerError(errorCode, errorMsg);
        }, EVENT_NAME), "AVCastControllerCallbackClient handler postTask failed");
}

AVCastControllerCallbackClient::~AVCastControllerCallbackClient()
{
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(EVENT_NAME);
    SLOGD("destroy");
}
}
