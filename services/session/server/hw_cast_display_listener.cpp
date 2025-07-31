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
// LCOV_EXCL_START
void HwCastDisplayListener::OnConnect(Rosen::DisplayId displayId)
{
    SLOGI("Screen OnConnect");
    auto display = Rosen::DisplayManagerLite::GetInstance().GetDisplayById(displayId);
    CHECK_AND_RETURN_LOG(display != nullptr, "display is nullptr");
    auto displayInfo = display->GetDisplayInfo();
    CHECK_AND_RETURN_LOG(displayInfo != nullptr, "displayInfo is nullptr");
    auto displayName = displayInfo->GetName();
    auto curDisplayInfo = GetDisplayInfo();
    if (displayName == "HwCast_AppModeDisplay" && curDisplayInfo != nullptr) {
        appCastId_ = displayId;
        ReportCastDisplay(curDisplayInfo, CastDisplayState::STATE_OFF);
        return;
    }
    SLOGI("DisplayId OnConnect: %{public}s", displayName.c_str());
    auto flag = Rosen::DisplayManagerLite::GetInstance().GetVirtualScreenFlag(displayId);
    if (flag == Rosen::VirtualScreenFlag::CAST) {
        ReportCastDisplay(displayInfo, CastDisplayState::STATE_ON);
        SetDisplayInfo(displayInfo);
    }
}
// LCOV_EXCL_STOP

void HwCastDisplayListener::OnDisconnect(Rosen::DisplayId displayId)
{
    SLOGI("OnDisconnect in");
    auto curDisplayInfo = GetDisplayInfo();
    if (!curDisplayInfo) {
        SLOGE("curDisplayInfo_ is null");
        return;
    }
    if (appCastId_ == displayId) {
        SLOGI("AppCast OnDisconnect");
        appCastId_ = 0;
        ReportCastDisplay(curDisplayInfo, CastDisplayState::STATE_ON);
        return;
    }
    if (curDisplayInfo->GetDisplayId() == displayId) {
        auto displayName = curDisplayInfo->GetName();
        SLOGI("DisplayId OnDisconnect: %{public}s", displayName.c_str());
        ReportCastDisplay(curDisplayInfo, CastDisplayState::STATE_OFF);
        SetDisplayInfo(nullptr);
    }
}

void HwCastDisplayListener::OnChange(Rosen::DisplayId displayId)
{
    auto display = Rosen::DisplayManagerLite::GetInstance().GetDisplayById(displayId);
    CHECK_AND_RETURN_LOG(display != nullptr, "display is nullptr");
    auto displayInfo = display->GetDisplayInfo();
    CHECK_AND_RETURN_LOG(displayInfo != nullptr, "displayInfo is nullptr");

    CastDisplayInfo castDisplayInfo;
    castDisplayInfo.displayId = displayInfo->GetDisplayId();
    castDisplayInfo.name = displayInfo->GetName();
    castDisplayInfo.width = static_cast<int32_t>(displayInfo->GetWidth());
    castDisplayInfo.height = static_cast<int32_t>(displayInfo->GetHeight());
    listener_->OnCastDisplaySizeChange(castDisplayInfo);
}

void HwCastDisplayListener::SetAppCastDisplayId(Rosen::DisplayId displayId)
{
    appCastId_ = displayId;
}

// LCOV_EXCL_START
void HwCastDisplayListener::SetDisplayInfo(sptr<Rosen::DisplayInfo> displayInfo)
{
    std::lock_guard<std::mutex> lock(dataMutex_);
    curDisplayInfo_ = displayInfo;
}
// LCOV_EXCL_STOP

sptr<Rosen::DisplayInfo> HwCastDisplayListener::GetDisplayInfo()
{
    std::lock_guard<std::mutex> lock(dataMutex_);
    return curDisplayInfo_;
}

// LCOV_EXCL_START
void HwCastDisplayListener::ReportCastDisplay(sptr<Rosen::DisplayInfo> displayInfo, CastDisplayState displayState)
{
    SLOGI("Screen ReportCastDisplay");
    CastDisplayInfo castDisplayInfo;
    castDisplayInfo.displayState = displayState;
    castDisplayInfo.displayId = displayInfo->GetDisplayId();
    castDisplayInfo.name = displayInfo->GetName();
    castDisplayInfo.width = static_cast<int32_t>(displayInfo->GetWidth());
    castDisplayInfo.height = static_cast<int32_t>(displayInfo->GetHeight());
    listener_->OnCastDisplayChange(castDisplayInfo);
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
