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

void AVCastControllerCallbackClient::OnCastPlaybackStateChange(const AVPlaybackState& state)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, state]() { callback->OnCastPlaybackStateChange(state); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
    if (castPlaybackStateListener_) {
        castPlaybackStateListener_(state);
    }
    SLOGI("OnCastPlaybackStateChange done with state: %{public}d", static_cast<int32_t>(castState));
}

void AVCastControllerCallbackClient::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, avQueueItem]() { callback->OnMediaItemChange(avQueueItem); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
    SLOGI("OnCastPlaybackStateChange done");
}

void AVCastControllerCallbackClient::OnPlayNext()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPlayNext(); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnPlayPrevious()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPlayPrevious(); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnSeekDone(const int32_t seekNumber)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, seekNumber]() { callback->OnSeekDone(seekNumber); }, EVENT_NAME),
        "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::OnVideoSizeChange(const int32_t width, const int32_t height)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, width, height]() {
            callback->OnVideoSizeChange(width, height);
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

void AVCastControllerCallbackClient::OnEndOfStream(const int32_t isLooping)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, isLooping]() {
            callback->OnEndOfStream(isLooping);
        }, EVENT_NAME), "AVCastControllerCallbackClient handler postTask failed");
}

void AVCastControllerCallbackClient::AddListenerForCastPlaybackState(const std::function<void(const AVPlaybackState&)>&
    listener)
{
    castPlaybackStateListener_ = listener;
}

AVCastControllerCallbackClient::~AVCastControllerCallbackClient()
{
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(EVENT_NAME);
    SLOGD("destroy");
}
}
