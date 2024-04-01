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

    /**
     * Release AVRouter instance.
     *
     * @since 10
    */
    virtual bool Release() = 0;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    /**
     * @brief Starting to discover devices.
     *
     * @param { int32_t } castDeviceCapability - The type of device want to discover.
     * @return { int32_t } Whether the device discovery operation was successful.
     * @since 10
    */
    virtual int32_t StartCastDiscovery(int32_t castDeviceCapability) = 0;

    /**
     * @brief Stop Discovering Devices
     *
     * @return { int32_t } Whether the stop operation was successful
     * @since 10
    */
    virtual int32_t StopCastDiscovery() = 0;

    /**
     * @brief Used on the Sink end to set whether it can be discovered or not.
     *
     * @param { const bool } enable - whether the sink device can be discovered or not.
     * @return { int32_t } Whether the operation was successful
     * @since 10
    */
    virtual int32_t SetDiscoverable(const bool enable) = 0;

    /**
     * @brief Notify Router that the device has been discovered (device is available).
     *
     * @param { OutputDeviceInfo } castOutputDeviceInfo - Discovered device infos.
     * @return { int32_t } Whether the notify operation was successful.
     * @since 10
    */
    virtual int32_t OnDeviceAvailable(OutputDeviceInfo& castOutputDeviceInfo) = 0;

    /**
     * @brief Notify Router that the device is offline.
     *
     * @param { std::string& } deviceId - Offlined device ID.
     * @return { int32_t } Whether the notify operation was successful.
     * @since 10
    */
    virtual int32_t OnDeviceOffline(const std::string& deviceId) = 0;

    /**
     * @brief Release current cast session.
     *
     * @since 10
    */
    virtual void ReleaseCurrentCastSession() = 0;

    /**
     * @brief Notify Router that the cast session has created.
     *
     * @param { int32_t } castId - Cast id for AVRouter's control.
     * @return { int32_t } Whether the notify operation was successful.
     * @since 10
    */
    virtual int32_t OnCastSessionCreated(const int32_t castId) = 0;

    /**
     * @brief Notify Router that the the cast engine servie has died.
     *
     * @param { int32_t } providerId - Provider ID corresponding to cast engine service.
     * @return { int32_t } Whether the notify operation was successful.
     * @since 10
    */
    virtual int32_t OnCastServerDied(int32_t providerId) = 0;

    /**
     * @brief Get the cast controller specified by castHandle.
     *
     * @param { const int64_t } castHandle - castHandle corresponding to cast engine session.
     * @return { std::shared_ptr<IAVCastControllerProxy> } Obtained cast controller.
     * @since 10
    */
    virtual std::shared_ptr<IAVCastControllerProxy> GetRemoteController(const int64_t castHandle) = 0;

    /**
     * @brief Start cast process.
     *
     * @param { OutputDeviceInfo } outputDeviceInfo - Output device ready for use.
     * @return { int64_t } ID returned after successful start of cast.
     * @since 10
    */
    virtual int64_t StartCast(const OutputDeviceInfo& outputDeviceInfo) = 0;
    
    /**
     * @brief Notify CastEngine to add (connect) remote devices.
     *
     * @param { int32_t } castId - Find the corresponding provider through this ID.
     * @param { OutputDeviceInfo } outputDeviceInfo - Devices to be connected.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t AddDevice(const int32_t castId, const OutputDeviceInfo& outputDeviceInfo) = 0;

    /**
     * @brief Stop cast process.
     *
     * @param { const int64_t } castHandle - The ID corresponding to the provider that needs to be stopped.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t StopCast(const int64_t castHandle) = 0;

    /**
     * @brief Stop cast session process.
     *
     * @param { const int64_t } castHandle - The ID corresponding to the provider that needs to be stopped.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t StopCastSession(const int64_t castHandle) = 0;

    /**
     * @brief Listen for AVRouter Callback event.
     *
     * @param { int64_t } castHandleconst - The ID corresponding to the provider.
     * @param { std::shared_ptr<IAVCastSessionStateListener> } callback - Callback function.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t RegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVCastSessionStateListener> callback) = 0;

    /**
     * @brief Cancel listening for AVRouter Callback event.
     *
     * @param { int64_t } castHandleconst - The ID corresponding to the provider.
     * @param { std::shared_ptr<IAVCastSessionStateListener> } callback - Callback function.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t UnRegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVCastSessionStateListener> callback) = 0;

    virtual void SetServiceAllConnectState(int64_t castHandle,
        std::map<std::string, int32_t>& serviceNameMapState) = 0;
#endif
};
} // namespace OHOS::AVSession
#endif // OHOS_AVROUTER_H
