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

#ifndef OHOS_I_AVSESSION_SERVICE_LISTENER_H
#define OHOS_I_AVSESSION_SERVICE_LISTENER_H

#include <string>
#include "avsession_descriptor.h"

/**
 * @brief Router is a part related to cast media
 * @since 10
 */
namespace OHOS::AVSession {
class IAVSessionServiceListener {
public:

#ifdef CASTPLUS_CAST_ENGINE_ENABLE

    /**
     * Release cast session at sink end.
     *
     * @since 10
    */
    virtual void ReleaseCastSession() = 0;
    /**
     * Create a new session at sink device.
     *
     * @param { int64_t } castHandle - Cast handle for cast session.
     * @since 10
    */
    virtual void CreateSessionByCast(const int64_t castHandle) = 0;

    /**
     * Notify Router that the device has been discovered.
     *
     * @param { OutputDeviceInfo } castOutputDeviceInfo - Discovered device infos.
     * @since 10
    */
    virtual void NotifyDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) = 0;

    /**
     * @brief Listen for the event of device logging.
     *
     * @param { DeviceLogEventCode } eventId - Event ID.
     * @param { int64_t } int64_t - Param.
     * @since 13
    */
    virtual void NotifyDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) {};

    /**
     * Notify Router that the device has been offlined.
     *
     * @param { std::string& } deviceId - Offlined device ID.
     * @since 10
    */
    virtual void NotifyDeviceOffline(const std::string& deviceId) = 0;

    /**
     * Notify the event of device changed.
     *
     * @param { DeviceState& } deviceState - state info.
     * @since 20
    */
    virtual void NotifyDeviceStateChange(const DeviceState& deviceState) = 0;

    /**
     * set cast state at castservice state changed.
     *
     * @param { bool } isInCast - cast state.
     * @since 14
    */
    virtual void setInCast(bool isInCast) = 0;

    /**
     * Set is support mirror to stream state at castservice state changed.
     *
     * @param { bool } isSupportMirrorToStream - cast state.
     * @since 18
    */
    virtual void SetIsSupportMirrorToStream(bool isSupportMirrorToStream) = 0;

    /**
     * Set discoverable for cast.
     *
     * @param { bool } enable - enable cast.
     * @since 18
    */
    virtual int32_t checkEnableCast(bool enable) = 0;
#endif
};
} // namespace OHOS::AVSession
#endif // OHOS_I_AVSESSION_SERVICE_LISTENER_H
