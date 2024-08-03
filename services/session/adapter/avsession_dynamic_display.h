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

#ifndef AV_SESSION_DYNAMIC_DISPLAY_H
#define AV_SESSION_DYNAMIC_DISPLAY_H

#include "avsession_descriptor.h"
#include "avsession_display_interface.h"
#include "hw_cast_display_listener.h"
#include "iavsession_callback.h"

namespace OHOS {
namespace AVSession {
using namespace std;

class DisplayAdapter : public OHOS::AVSession::AVSessionDisplayIntf {
public:
    DisplayAdapter();
    virtual ~DisplayAdapter() = default;
    void GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays);
    void StartCastDisplayListener(sptr<IAVSessionCallback> callback);
    int32_t StopCastDisplayListener();

private:
    sptr<HwCastDisplayListener> displayListener_ = nullptr;
};

} // namespace AVSession
} // namespace OHOS

#endif // AV_SESSION_DYNAMIC_DISPLAY_H