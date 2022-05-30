/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
AVSessionCallbackClient::AVSessionCallbackClient(std::shared_ptr<AVSessionCallback>& callback)
    : callback_(callback)
{
}

void AVSessionCallbackClient::OnPlay()
{
    if (callback_) {
        callback_->OnPlay();
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnPause()
{
    if (callback_) {
        callback_->OnPause();
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnStop()
{
    if (callback_) {
        callback_->OnStop();
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnPlayNext()
{
    if (callback_) {
        callback_->OnPlayNext();
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnPlayPrevious()
{
    if (callback_) {
        callback_->OnPlayPrevious();
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnFastForward()
{
    if (callback_) {
        callback_->OnFastForward();
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnRewind()
{
    if (callback_) {
        callback_->OnRewind();
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnSeek(int64_t time)
{
    if (callback_) {
        callback_->OnSeek(time);
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnSetSpeed(int32_t speed)
{
    if (callback_) {
        callback_->OnSetSpeed(speed);
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnSetLoopMode(int32_t loopMode)
{
    if (callback_) {
        callback_->OnSetLoopMode(loopMode);
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnToggleFavorite(const std::string& mediald)
{
    if (callback_) {
        callback_->OnToggleFavorite(mediald);
    }
    else
    {
        SLOGE("callback_ is null");
    }
}

void AVSessionCallbackClient::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    if (callback_) {
        callback_->OnMediaKeyEvent(keyEvent);
    }
    else
    {
        SLOGE("callback_ is null");
    }
}
}