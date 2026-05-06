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

void HwCastDisplayListener::OnChange(Rosen::DisplayId displayId) {}

void HwCastDisplayListener::SetAppCastDisplayId(Rosen::DisplayId displayId)
{
    appCastId_ = displayId;
}

void HwCastDisplayListener::SetSupportExtendedScreen(bool isSupport)
{
    sptr<Rosen::DisplayInfo> displayInfo;
    Rosen::DisplayId displayId;
    std::string displayName;
    
    if (!isSupport) {
        {
            std::lock_guard<std::recursive_mutex> lock(dataMutex_);
            CHECK_AND_RETURN_LOG(isSupportExtendedScreen_.load(), "isSupportExtendedScreen already false, skip");
            CHECK_AND_RETURN_LOG(curDisplayInfo_ != nullptr, "curDisplayInfo_ is nullptr");
            displayInfo = curDisplayInfo_;
            displayId = curDisplayInfo_->GetDisplayId();
            displayName = curDisplayInfo_->GetName();
        }
        auto flag = Rosen::DisplayManagerLite::GetInstance().GetVirtualScreenFlag(displayId);
        CHECK_AND_RETURN_LOG(flag == Rosen::VirtualScreenFlag::CAST, "curDisplayInfo is not cast screen");
        SLOGI("SetSupportExtendedScreen false, disconnect cast display: %{public}s", displayName.c_str());
        ReportCastDisplay(displayInfo, CastDisplayState::STATE_OFF);
        {
            std::lock_guard<std::recursive_mutex> lock(dataMutex_);
            stashedDisplayInfo_ = curDisplayInfo_;
            isSupportExtendedScreen_.store(isSupport);
        }
    }
    if (isSupport) {
        {
            std::lock_guard<std::recursive_mutex> lock(dataMutex_);
            CHECK_AND_RETURN_LOG(!isSupportExtendedScreen_.load(), "isSupportExtendedScreen already true, skip");
            CHECK_AND_RETURN_LOG(stashedDisplayInfo_ != nullptr, "stashedDisplayInfo_ is nullptr");
            displayInfo = stashedDisplayInfo_;
            displayId = stashedDisplayInfo_->GetDisplayId();
            displayName = stashedDisplayInfo_->GetName();
        }
        auto flag = Rosen::DisplayManagerLite::GetInstance().GetVirtualScreenFlag(displayId);
        CHECK_AND_RETURN_LOG(flag == Rosen::VirtualScreenFlag::CAST, "stashedDisplayInfo is not cast screen");
        SLOGI("SetSupportExtendedScreen true, connect cast display: %{public}s", displayName.c_str());
        ReportCastDisplay(displayInfo, CastDisplayState::STATE_ON);
        {
            std::lock_guard<std::recursive_mutex> lock(dataMutex_);
            curDisplayInfo_ = stashedDisplayInfo_;
            isSupportExtendedScreen_.store(isSupport);
        }
    }
}

// LCOV_EXCL_START
void HwCastDisplayListener::SetDisplayInfo(sptr<Rosen::DisplayInfo> displayInfo)
{
    std::lock_guard<std::recursive_mutex> lock(dataMutex_);
    curDisplayInfo_ = displayInfo;
}
// LCOV_EXCL_STOP

sptr<Rosen::DisplayInfo> HwCastDisplayListener::GetDisplayInfo()
{
    std::lock_guard<std::recursive_mutex> lock(dataMutex_);
    return curDisplayInfo_;
}

bool HwCastDisplayListener::IsSupportExtendedScreen()
{
    return isSupportExtendedScreen_.load();
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
