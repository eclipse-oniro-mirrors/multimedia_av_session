/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {
AVControllerCallbackClient::AVControllerCallbackClient(const std::shared_ptr<AVControllerCallback>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

ErrCode AVControllerCallbackClient::OnSessionDestroy()
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnSessionDestroy(); }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnAVCallMetaDataChange(const AVCallMetaData& data)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, data]() { callback->OnAVCallMetaDataChange(data); }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnAVCallStateChange(const AVCallState& state)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, state]() { callback->OnAVCallStateChange(state); }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnPlaybackStateChange(const AVPlaybackState& state)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    callback->OnPlaybackStateChange(state);

    if (playbackStateListener_) {
        playbackStateListener_(state);
    }
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnMetaDataChange(const AVMetaData& data)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    callback->OnMetaDataChange(data);
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnActiveStateChange(bool isActive)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, isActive]() { callback->OnActiveStateChange(isActive); }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    callback->OnValidCommandChange(cmds);
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& info)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, connectionState, info]() {
            callback->OnOutputDeviceChange(connectionState, info);
        }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, event, args]() { callback->OnSessionEventChange(event, args); }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnQueueItemsChange(const std::vector<AVQueueItem>& items)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, items]() { callback->OnQueueItemsChange(items); }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnQueueTitleChange(const std::string& title)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, title]() { callback->OnQueueTitleChange(title); }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::OnExtrasChange(const AAFwk::WantParams& extras)
{
    CHECK_AND_RETURN_RET_LOG(callback_, AVSESSION_ERROR, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, extras]() { callback->OnExtrasChange(extras); }, EVENT_NAME),
        "AVControllerCallbackClient handler postTask failed");
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::AddListenerForPlaybackState(
    const std::function<void(const AVPlaybackState&)>& listener)
{
    playbackStateListener_ = listener;
    return AVSESSION_SUCCESS;
}

ErrCode AVControllerCallbackClient::RemoveListenerForPlaybackState()
{
    playbackStateListener_ = nullptr;
    return AVSESSION_SUCCESS;
}

AVControllerCallbackClient::~AVControllerCallbackClient()
{
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(EVENT_NAME);
    SLOGD("destroy");
}
}