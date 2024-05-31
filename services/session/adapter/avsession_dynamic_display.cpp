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
 
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_descriptor.h"
#include "hw_cast_display_listener.h"
#include "parameter.h"
#include "parameters.h"

namespace OHOS {
namespace AVSession {
using namespace std;
 
sptr<HwCastDisplayListener> displayListener_ = nullptr;
 
//--------------------------------------------------------------------------
// Display Interface
//--------------------------------------------------------------------------
extern "C" void GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays)
{
    std::vector<sptr<Rosen::Screen>> allDisplays;
    Rosen::ScreenManager::GetInstance().GetAllScreens(allDisplays);
    std::vector<CastDisplayInfo> displays;
    for (auto &display : allDisplays) {
        SLOGI("GetAllCastDisplays name: %{public}s, id: %{public}llu",
            display->GetName().c_str(), (unsigned long long)display->GetId());
        auto flag = Rosen::ScreenManager::GetInstance().GetVirtualScreenFlag(display->GetId());
        SLOGI("GetAllCastDisplays name: %{public}s, flag: %{public}d", display->GetName().c_str(), flag);
        if (flag == Rosen::VirtualScreenFlag::CAST) {
            SLOGI("ReportCastDisplay start in");
            CastDisplayInfo castDisplayInfo;
            castDisplayInfo.displayState = CastDisplayState::STATE_ON;
            castDisplayInfo.displayId = display->GetId();
            castDisplayInfo.name = display->GetName();
            castDisplayInfo.width = static_cast<int32_t>(display->GetWidth());
            castDisplayInfo.height = static_cast<int32_t>(display->GetHeight());
            displays.push_back(castDisplayInfo);
            if (displayListener_ != nullptr) {
                displayListener_->SetDisplayInfo(display);
            }
        }
    }
    castDisplays = displays;
    SLOGI("GetAllCastDisplaysEx castDisplays.size(): %{public}zu", castDisplays.size());
}

extern "C" void StartCastDisplayListener(sptr<IAVSessionCallback> callback)
{
    if (displayListener_ == nullptr) {
        SLOGI("displayListener_ is null, try to create new listener");
        displayListener_ = new HwCastDisplayListener(callback);
        if (displayListener_ == nullptr) {
            SLOGI("Create displayListener failed");
            return;
        }
        SLOGI("Start to register display listener");
        Rosen::DMError ret = Rosen::ScreenManager::GetInstance().RegisterScreenListener(displayListener_);
        if (ret != Rosen::DMError::DM_OK) {
            SLOGE("RegisterScreenListener failed, ret: %{public}d.", ret);
        }
    }
}
 
extern "C" int32_t StopCastDisplayListener()
{
    SLOGI("StopCastDisplayListener in");
    Rosen::DMError ret = Rosen::ScreenManager::GetInstance().UnregisterScreenListener(displayListener_);
    if (ret != Rosen::DMError::DM_OK) {
        SLOGE("UnregisterScreenListener failed, ret: %{public}d.", ret);
    }
    displayListener_ = nullptr;
    return AVSESSION_SUCCESS;
}
 
}  // namespace AVSession
}  // namespace OHOS