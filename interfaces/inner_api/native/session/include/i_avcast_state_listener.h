/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
     * @param { std::vector<DeviceInfo> } deviceInfos - Discovered device infos.
     * @since 10
    */
    virtual void OnDeviceAvailable(std::vector<DeviceInfo> deviceInfos) = 0;

    /**
     * @brief Listen for the event of device logging.
     *
     * @param { int32_t } eventId - Event ID.
     * @param { int64_t } int64_t - Param.
     * @since 13
    */
    virtual int32_t OnDeviceLogEvent(const int32_t eventId, const int64_t param) {};

    /**
     * Listen for the event of device offline.
     *
     * @param { std::string& } deviceId - Offlined device ID.
     * @since 10
    */
    virtual void OnDeviceOffline(const std::string& deviceId) = 0;

    /**
     * Notify Router that the cast session should be destroy.
     *
     * @since 10
    */
    virtual void OnSessionNeedDestroy() = 0;

    /**
     * Notify Router that the cast session has created.
     *
     * @param { int32_t } castId - Cast id for AVRouter's control.
     * @since 10
    */
    virtual void OnSessionCreated(const int32_t castId) = 0;

    /**
     * Notify Router that the cast engine service has died.
     *
     * @since 10
    */
    virtual void OnCastServerDied() = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_I_AVCAST_STATE_LISTENER_H
