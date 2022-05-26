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
}

void AVSessionCallbackClient::OnPause()
{
}

void AVSessionCallbackClient::OnStop()
{
}

void AVSessionCallbackClient::OnPlayNext()
{
}

void AVSessionCallbackClient::OnPlayPrevious()
{
}

void AVSessionCallbackClient::OnFastForward()
{
}

void AVSessionCallbackClient::OnRewind()
{
}

void AVSessionCallbackClient::OnSeek(int64_t time)
{
}

void AVSessionCallbackClient::OnSetSpeed(int32_t speed)
{
}

void AVSessionCallbackClient::OnSetLoopMode(int32_t loopMode)
{
}

void AVSessionCallbackClient::OnToggleFavorite(const std::string& mediald)
{
}

void AVSessionCallbackClient::OnVolumeChanged(const AVVolumeInfo& volume)
{
}

void AVSessionCallbackClient::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
}
}