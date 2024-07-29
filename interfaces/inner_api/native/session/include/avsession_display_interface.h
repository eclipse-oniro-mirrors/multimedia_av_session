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

#ifndef OHOS_AVSESSION_DISPLAY_INTERFACE_H
#define OHOS_AVSESSION_DISPLAY_INTERFACE_H

#include "avsession_descriptor.h"
#include "iavsession_callback.h"

/**
 * @brief Internal usage only, for AVSession interacts with display related interfaces.
 * @since 12
 */
namespace OHOS::AVSession {
class AVSessionDisplayIntf {
public:
    virtual void GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays);
    virtual void StartCastDisplayListener(sptr<IAVSessionCallback> callback);
    virtual int32_t StopCastDisplayListener();
};
} // namespace OHOS::AVSession
#endif