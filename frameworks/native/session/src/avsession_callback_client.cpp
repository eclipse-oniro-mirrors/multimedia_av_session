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

#include "avsession_callback_client.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {
AVSessionCallbackClient::AVSessionCallbackClient(const std::shared_ptr<AVSessionCallback>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void AVSessionCallbackClient::OnAVCallAnswer()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnAVCallAnswer(); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnAVCallHangUp()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnAVCallHangUp(); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnAVCallToggleCallMute()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnAVCallToggleCallMute(); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlay()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPlay(); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPause()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPause(); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnStop()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnStop(); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlayNext()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPlayNext(); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlayPrevious()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPlayPrevious(); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnFastForward(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, time]() { callback->OnFastForward(time); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnRewind(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, time]() { callback->OnRewind(time); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSeek(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, time]() { callback->OnSeek(time); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSetSpeed(double speed)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, speed]() { callback->OnSetSpeed(speed); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSetLoopMode(int32_t loopMode)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, loopMode]() { callback->OnSetLoopMode(loopMode); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnToggleFavorite(const std::string& mediald)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, mediald]() { callback->OnToggleFavorite(mediald); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, keyEvent]() { callback->OnMediaKeyEvent(keyEvent); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnOutputDeviceChange(const int32_t connectionState,
    const OutputDeviceInfo& outputDeviceInfo)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, connectionState, outputDeviceInfo]() {
            callback->OnOutputDeviceChange(connectionState, outputDeviceInfo);
        }, EVENT_NAME), "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnCommonCommand(const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance().AVSessionPostTask([callback,
        commonCommand, commandArgs]() { callback->OnCommonCommand(commonCommand, commandArgs); },
        EVENT_NAME), "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSkipToQueueItem(int32_t itemId)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, itemId]() { callback->OnSkipToQueueItem(itemId); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlayFromAssetId(int64_t assetId)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, assetId]() { callback->OnPlayFromAssetId(assetId); }, EVENT_NAME),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, castDisplayInfo]() { callback->OnCastDisplayChange(castDisplayInfo); },
        EVENT_NAME), "AVSessionCallbackClient handler postTask failed");
}

AVSessionCallbackClient::~AVSessionCallbackClient()
{
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(EVENT_NAME);
    SLOGD("destroy");
}
}