/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
        .AVSessionPostTask([callback]() { callback->OnAVCallAnswer(); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnAVCallHangUp()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnAVCallHangUp(); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnAVCallToggleCallMute()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnAVCallToggleCallMute(); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlay()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPlay(); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPause()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPause(); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnStop()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnStop(); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlayNext()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPlayNext(); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlayPrevious()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback]() { callback->OnPlayPrevious(); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnFastForward(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, time]() { callback->OnFastForward(time); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnRewind(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, time]() { callback->OnRewind(time); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSeek(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, time]() { callback->OnSeek(time); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSetSpeed(double speed)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, speed]() { callback->OnSetSpeed(speed); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSetLoopMode(int32_t loopMode)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, loopMode]() { callback->OnSetLoopMode(loopMode); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSetTargetLoopMode(int32_t targetLoopMode)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, targetLoopMode]() { callback->OnSetTargetLoopMode(targetLoopMode); },
        std::string(__FUNCTION__)), "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnToggleFavorite(const std::string& mediaId)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, mediaId]() { callback->OnToggleFavorite(mediaId); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, keyEvent]() { callback->OnMediaKeyEvent(keyEvent); }, std::string(__FUNCTION__)),
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
        }, std::string(__FUNCTION__)), "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnCommonCommand(const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance().AVSessionPostTask([callback,
        commonCommand, commandArgs]() { callback->OnCommonCommand(commonCommand, commandArgs); },
        std::string(__FUNCTION__)), "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnSkipToQueueItem(int32_t itemId)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, itemId]() { callback->OnSkipToQueueItem(itemId); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlayFromAssetId(int64_t assetId)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, assetId]() { callback->OnPlayFromAssetId(assetId); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnPlayWithAssetId(const std::string& assetId)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, assetId]() { callback->OnPlayWithAssetId(assetId); }, std::string(__FUNCTION__)),
        "AVSessionCallbackClient handler postTask failed");
}

void AVSessionCallbackClient::OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");

    auto callback = callback_;
    CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
        .AVSessionPostTask([callback, castDisplayInfo]() { callback->OnCastDisplayChange(castDisplayInfo); },
        std::string(__FUNCTION__)), "AVSessionCallbackClient handler postTask failed");
}

AVSessionCallbackClient::~AVSessionCallbackClient()
{
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(std::string(__FUNCTION__));
    SLOGD("destroy");
}
}