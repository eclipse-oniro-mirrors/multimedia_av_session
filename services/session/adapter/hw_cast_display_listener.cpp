/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hw_cast_display_listener.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
void HwCastDisplayListener::OnConnect(Rosen::ScreenId screenId)
{
    SLOGI("Screen OnConnect");
    auto displayInfo = Rosen::ScreenManager::GetInstance().GetScreenById(screenId);
    if (displayInfo == nullptr) {
        return;
    }
    auto displayName = displayInfo->GetName();
    SLOGI("ScreenId OnConnect: %{public}s", displayName.c_str());
    if (displayName == "CastEngine") {
        ReportCastDisplay(displayInfo, CastDisplayState::STATE_ON);
        SetDisplayInfo(displayInfo);
    }
}

void HwCastDisplayListener::OnDisconnect(Rosen::ScreenId screenId)
{
    SLOGI("ScreenId OnDisconnect");
    auto curDisplayInfo = GetDisplayInfo();
    if (!curDisplayInfo || curDisplayInfo->GetId() != screenId) {
        SLOGE("curDisplayInfo_ is null");
        return;
    }
    auto displayName = curDisplayInfo->GetName();
    SLOGI("ScreenId OnDisconnect: %{public}s", displayName.c_str());
    ReportCastDisplay(curDisplayInfo, CastDisplayState::STATE_OFF);
    SetDisplayInfo(nullptr);
}

void HwCastDisplayListener::OnChange(Rosen::ScreenId screenId) {}

void HwCastDisplayListener::SetDisplayInfo(sptr<Rosen::Screen> displayInfo)
{
    std::lock_guard<std::mutex> lock(dataMutex_);
    curDisplayInfo_ = displayInfo;
}

sptr<Rosen::Screen> HwCastDisplayListener::GetDisplayInfo()
{
    std::lock_guard<std::mutex> lock(dataMutex_);
    return curDisplayInfo_;
}

void HwCastDisplayListener::ReportCastDisplay(sptr<Rosen::Screen> displayInfo, CastDisplayState displayState)
{
    CastDisplayInfo castDisplayInfo;
    castDisplayInfo.displayState = displayState;
    castDisplayInfo.displayId = displayInfo->GetId();
    castDisplayInfo.name = displayInfo->GetName();
    castDisplayInfo.width = static_cast<int32_t>(displayInfo->GetWidth());
    castDisplayInfo.height = static_cast<int32_t>(displayInfo->GetHeight());
    listener_->OnCastDisplayChange(castDisplayInfo);
}
} // namespace OHOS::AVSession
