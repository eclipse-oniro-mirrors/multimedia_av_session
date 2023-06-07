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

void AVCastControllerCallbackClient::OnStateChanged(const AVCastPlayerState& state)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, state]() { callback->OnStateChanged(state); }, EVENT_NAME),
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

void AVCastControllerCallbackClient::OnSeekDone(const int32_t seek)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, seek]() { callback->OnSeekDone(seek); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnPlaySpeedChanged(const int32_t speed)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, speed]() { callback->OnPlaySpeedChanged(speed); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnTimeUpdate(const int32_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, time]() { callback->OnTimeUpdate(time); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, errorCode, errorMsg]() { callback->OnPlayerError(errorCode, errorMsg); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

AVCastControllerCallbackClient::~AVCastControllerCallbackClient()
{
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(EVENT_NAME);
    SLOGD("destroy");
}
}
