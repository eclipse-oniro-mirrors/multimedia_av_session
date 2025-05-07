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

#ifndef HW_CAST_DISPLAY_LISTENER_H
#define HW_CAST_DISPLAY_LISTENER_H

#include <mutex>
#include "avsession_descriptor.h"
#include "screen_manager_lite.h"
#include "display_manager_lite.h"
#include "display_info.h"
#include "iavsession_callback.h"

namespace OHOS::AVSession {
class HwCastDisplayListener : public Rosen::ScreenManagerLite::IScreenListener {
public:
    explicit HwCastDisplayListener(sptr<IAVSessionCallback> callback) : listener_(callback) {};
    void OnConnect(Rosen::DisplayId displayId) override;
    void OnDisconnect(Rosen::DisplayId displayId) override;
    void OnChange(Rosen::DisplayId displayId) override;
    void SetDisplayInfo(sptr<Rosen::DisplayInfo> displayInfo);
    sptr<Rosen::DisplayInfo> GetDisplayInfo();
    void SetAppCastDisplayId(Rosen::DisplayId displayId);

private:
    void ReportCastDisplay(sptr<Rosen::DisplayInfo> displayInfo, CastDisplayState displayState);

    sptr<IAVSessionCallback> listener_;
    sptr<Rosen::DisplayInfo> curDisplayInfo_;
    unit64_t appCastId_ = 0;
    std::mutex dataMutex_;
};
} // namespace OHOS::AVSession
#endif // HW_CAST_DISPLAY_LISTENER_H
