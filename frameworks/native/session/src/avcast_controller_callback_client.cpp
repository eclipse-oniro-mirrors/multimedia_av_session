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

#include "avcast_controller_callback_client.h"
#include "avsession_log.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {
AVCastControllerCallbackClient::AVCastControllerCallbackClient(const std::shared_ptr<AVCastControllerCallback>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void AVCastControllerCallbackClient::OnStateChange(const AVCastPlayerState& state)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, state]() { callback->OnStateChange(state); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, avQueueItem]() { callback->OnMediaItemChange(avQueueItem); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnVolumeChange(const int32_t volume)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, volume]() { callback->OnVolumeChange(volume); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnLoopModeChange(const int32_t loopMode)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, loopMode]() { callback->OnLoopModeChange(loopMode); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnPlaySpeedChange(const int32_t playSpeed)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, playSpeed]() { callback->OnPlaySpeedChange(playSpeed); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnPositionChange(const int32_t position, const int32_t bufferPosition, const int32_t duration)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, position, bufferPosition, duration]() { callback->OnPositionChange(position, bufferPosition, duration); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnVideoSizeChange(const int32_t width, const int32_t height)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, width, height]() { callback->OnVideoSizeChange(width, height); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnError(const int32_t errorCode, const std::string& errorMsg)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, errorCode, errorMsg]() { callback->OnError(errorCode, errorMsg); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

AVCastControllerCallbackClient::~AVCastControllerCallbackClient()
{
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(EVENT_NAME);
    SLOGD("destroy");
}
}
