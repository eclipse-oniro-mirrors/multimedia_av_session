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
#include "screen_manager.h"
#include "screen.h"
#include "iavsession_callback.h"

namespace OHOS::AVSession {
class HwCastDisplayListener : public Rosen::ScreenManager::IScreenListener {
public:
    explicit HwCastDisplayListener(sptr<IAVSessionCallback> callback) : listener_(callback) {};
    void OnConnect(Rosen::ScreenId screenId) override;
    void OnDisconnect(Rosen::ScreenId screenId) override;
    void OnChange(Rosen::ScreenId screenId) override;
    void SetDisplayInfo(sptr<Rosen::Screen> displayInfo);
    sptr<Rosen::Screen> GetDisplayInfo();

private:
    void ReportCastDisplay(sptr<Rosen::Screen> displayInfo, CastDisplayState displayState);

    sptr<IAVSessionCallback> listener_;
    sptr<Rosen::Screen> curDisplayInfo_;
    std::mutex dataMutex_;
};
} // namespace OHOS::AVSession
#endif // HW_CAST_DISPLAY_LISTENER_H
