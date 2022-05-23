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

#include "iavsession_callback.h"

namespace OHOS::AVSession {
void IAVSessionCallback::OnPlay()
{
}

void IAVSessionCallback::OnPause()
{
}

void IAVSessionCallback::OnStop()
{
}

void IAVSessionCallback::OnPlayNext()
{
}

void IAVSessionCallback::OnPlayPrevious()
{
}

void IAVSessionCallback::OnFastForward()
{
}

void IAVSessionCallback::OnRewind()
{
}

void IAVSessionCallback::OnSeek(int64_t time)
{
}

void IAVSessionCallback::OnSetSpeed(int32_t speed)
{
}

void IAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
}

void IAVSessionCallback::OnToggleFavorite(const std::string& mediald)
{
}

void IAVSessionCallback::OnVolumeChanged(const AVVolumeInfo& volume)
{
}

void IAVSessionCallback::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
}
} // namespace OHOS::AVSession