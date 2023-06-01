/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_I_AVCAST_STATE_LISTENER_H
#define OHOS_I_AVCAST_STATE_LISTENER_H

#include <string>
#include "avsession_descriptor.h"

/**
 * @brief Router is a part related to cast media
 * @since 10
 */
namespace OHOS::AVSession {
class IAVCastStateListener {
public:
    /**
     * Notify Router that the device has been discovered.
     *
     * @param { OutputDeviceInfo } castOutputDeviceInfo - Discovered device infos.
     * @return { number } Whether the notify operation was successful
     * @since 10
    */
    virtual void OnDeviceFound(std::vector<DeviceInfo> deviceInfos) = 0;

    virtual void OnCastServerDied() = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_I_AVCAST_STATE_LISTENER_H
