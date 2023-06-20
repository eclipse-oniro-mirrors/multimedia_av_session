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

#ifndef OHOS_AVROUTER_H
#define OHOS_AVROUTER_H

#include "avsession_descriptor.h"
#include "avsession_info.h"
#include "i_avsession_service_listener.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "i_avcast_controller_proxy.h"
#endif

/**
 * @brief Router is a part related to cast media
 * @since 10
 */
namespace OHOS::AVSession {
class AVRouter {
public:
    /**
     * Get AVRouter instance.
     *
     * @return AVRouter instance.
     * @since 10
    */
    static AVRouter& GetInstance();

    /**
     * Get AVRouter instance.
     * @param { AVSessionService* } servicePtr - The pointer of avsession service.
     * @since 10
    */
    virtual void Init(IAVSessionServiceListener *servicePtr) = 0;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    /**
     * Get AVRouter instance.
     * @param { AVCastDeviceCapability } castDeviceCapability - The type of device you want to discover.
     * @return { number } Whether the device discovery operation was successful
     * @since 10
    */
    virtual int32_t StartCastDiscovery(int32_t castDeviceCapability) = 0;

    virtual int32_t StopCastDiscovery() = 0;

    /**
     * Notify Router that the device has been discovered.
     *
     * @param { OutputDeviceInfo } castOutputDeviceInfo - Discovered device infos.
     * @return { number } Whether the notify operation was successful
     * @since 10
    */
    virtual int32_t OnDeviceAvailable(OutputDeviceInfo& castOutputDeviceInfo) = 0;

    virtual int32_t OnCastServerDied(int32_t providerId) = 0;

    virtual std::shared_ptr<IAVCastControllerProxy> GetRemoteController(const int64_t castHandle) = 0;

    /**
     * Start cast process.
     *
     * @param { OutputDeviceInfo } outputDeviceInfo - .
     * @return { number } Whether the start cast operation was successful
     * @since 10
    */
    virtual int64_t StartCast(const OutputDeviceInfo& outputDeviceInfo) = 0;
    virtual int32_t AddDevice(const int32_t castId, const OutputDeviceInfo& outputDeviceInfo) = 0;

    /**
     * Start cast process.
     *
     * @param { OutputDeviceInfo } outputDeviceInfo - .
     * @return { number } Whether the start cast operation was successful
     * @since 10
    */
    virtual int32_t StopCast(const int64_t castHandle) = 0;

    /**
     * @brief Listen for AVRouter Callback event.
     *
     * @param callback Listen for AVSession Callback event{@link AVSessionCallback}.
     * @return Returns whether the return is successful.
     * @since 10
    */
    virtual int32_t RegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVCastSessionStateListener> callback) = 0;

    virtual int32_t UnRegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVCastSessionStateListener> callback) = 0;
#endif
};
} // namespace OHOS::AVSession
#endif // OHOS_AVROUTER_H
