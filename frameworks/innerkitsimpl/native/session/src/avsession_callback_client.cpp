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
    SLOGI("construct");
}

void AVSessionCallbackClient::OnPlay()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnPlay();
}

void AVSessionCallbackClient::OnPause()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnPause();
}

void AVSessionCallbackClient::OnStop()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnStop();
}

void AVSessionCallbackClient::OnPlayNext()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnPlayNext();
}

void AVSessionCallbackClient::OnPlayPrevious()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnPlayPrevious();
}

void AVSessionCallbackClient::OnFastForward()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnFastForward();
}

void AVSessionCallbackClient::OnRewind()
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnRewind();
}

void AVSessionCallbackClient::OnSeek(int64_t time)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnSeek(time);
}

void AVSessionCallbackClient::OnSetSpeed(int32_t speed)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnSetSpeed(speed);
}

void AVSessionCallbackClient::OnSetLoopMode(int32_t loopMode)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnSetLoopMode(loopMode);
}

void AVSessionCallbackClient::OnToggleFavorite(const std::string& mediald)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnToggleFavorite(mediald);
}

void AVSessionCallbackClient::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    CHECK_AND_RETURN_LOG(callback_, "callback is null");
    callback_->OnMediaKeyEvent(keyEvent);
}
}