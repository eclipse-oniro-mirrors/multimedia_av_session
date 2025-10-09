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
     * @return {int32_t} Returns whether init successfully.
     * @since 10
    */
    virtual int32_t Init(IAVSessionServiceListener *servicePtr) = 0;

    /**
     * Release AVRouter instance.
     *
     * @since 10
    */
    virtual bool Release() = 0;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    /**
     * Transmission fd
     *
     * @param fd file descriptor
     * @param maxSize file max size
     * @return Returns whether the fd was transport successfully
     * @since 13
    */
    virtual int32_t StartDeviceLogging(int32_t fd, uint32_t maxSize) = 0;

    /**
     * Stop transmission fd
     *
     * @return Returns whether stop transport successfully
     * @since 13
    */
    virtual int32_t StopDeviceLogging() = 0;

    /**
     * @brief Starting to discover devices.
     *
     * @param { int32_t } castDeviceCapability - The type of device want to discover.
     * @return { int32_t } Whether the device discovery operation was successful.
     * @since 10
    */
    virtual int32_t StartCastDiscovery(int32_t castDeviceCapability, std::vector<std::string> drmSchemes) = 0;

    /**
     * @brief Stop Discovering Devices
     *
     * @return { int32_t } Whether the stop operation was successful
     * @since 10
    */
    virtual int32_t StopCastDiscovery() = 0;

    /**
     * @brief Is stop Discovering Devices
     *
     * @return { bool } Whether execute StopCastDiscovery func
     * @since 10
    */
    virtual bool IsStopCastDiscovery(pid_t pid) = 0;

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
     * @brief Listen for the event of device logging.
     *
     * @param { DeviceLogEventCode } eventId - Event ID.
     * @param { int64_t } int64_t - Param.
     * @since 13
    */
    virtual int32_t OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) = 0;

    /**
     * @brief Notify Router that the device is offline.
     *
     * @param { std::string& } deviceId - Offlined device ID.
     * @return { int32_t } Whether the notify operation was successful.
     * @since 10
    */
    virtual int32_t OnDeviceOffline(const std::string& deviceId) = 0;

    /**
     * @brief Listen for the event of device changed.
     *
     * @param { DeviceState& } device state info.
     * @return { int32_t } Whether the device state changed was successful.
     * @since 20
    */
    virtual int32_t OnDeviceStateChange(const DeviceState& deviceState) = 0;

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
     * @param { std::pair<std::string, std::string>& } serviceNameStatePair - serviceName state.
     * @param { std::string } sessionId - avsession id.
     * @return { int64_t } ID returned after successful start of cast.
     * @since 10
    */
    virtual int64_t StartCast(const OutputDeviceInfo& outputDeviceInfo,
        std::pair<std::string, std::string>& serviceNameStatePair, std::string sessionId) = 0;
    
    /**
     * @brief Notify CastEngine to add (connect) remote devices.
     *
     * @param { int32_t } castId - Find the corresponding provider through this ID.
     * @param { OutputDeviceInfo } outputDeviceInfo - Devices to be connected.
     * @param { uint32_t } spid - app id for pulling client.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t AddDevice(const int32_t castId, const OutputDeviceInfo& outputDeviceInfo,
        uint32_t spid) = 0;

    /**
     * @brief Stop cast process.
     *
     * @param { const int64_t } castHandle - The ID corresponding to the provider that needs to be stopped.
     * @param { bool } continuePlay - whether continue play when stop cast.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t StopCast(const int64_t castHandle, bool continuePlay = false) = 0;

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
     * @param { std::shared_ptr<IAVRouterListener> } callback - Callback function.
     * @param { std::string } sessionId - avsession id.
     * @param { DeviceInfo } deviceInfo The device info.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t RegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVRouterListener> callback, std::string sessionId, DeviceInfo deviceInfo) = 0;

    /**
     * @brief Cancel listening for AVRouter Callback event.
     *
     * @param { int64_t } castHandleconst - The ID corresponding to the provider.
     * @param { std::shared_ptr<IAVRouterListener> } callback - Callback function.
     * @param { std::string } sessionId - avsession id.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t UnRegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVRouterListener> callback, std::string sessionId) = 0;

    /**
     * @brief set allconnect state.
     *
     * @param { int64_t } castHandle const - The ID corresponding to the provider.
     * @param { DeviceInfo } cast deviceinfo - The deviceinfo to the castprovider.
     * @return { int32_t } Whether the operation was successful.
     * @since 11
    */
    virtual int32_t SetServiceAllConnectState(int64_t castHandle, DeviceInfo deviceInfo) = 0;

    /**
     * @brief get remote networkId.
     *
     * @param { int64_t } castHandle const - The ID corresponding to the castprovider.
     * @param { string } cast deviceId - The deviceId give cast+ to get remote networkId.
     * @param { string } cast networkId - The networkId to transmit remote networkId.
     * @return { int32_t } Whether the operation was successful.
     * @since 11
    */
    virtual int32_t GetRemoteNetWorkId(int64_t castHandle, std::string deviceId, std::string &networkId) = 0;

    /**
     * @brief get remote DrmCapabilities.
     *
     * @param { int64_t } castHandle const - The ID corresponding to the castprovider.
     * @param { string } cast deviceId - The deviceId give cast+ to get remote DrmCapabilities.
     * @param { string } cast DrmCapabilities - The DrmCapabilities to transmit remote DrmCapabilities.
     * @return { int32_t } Whether the operation was successful.
     * @since 11
    */
    virtual int32_t GetRemoteDrmCapabilities(int64_t castHandle, std::string deviceId,
        std::vector<std::string> &drmCapabilities) = 0;

    /**
     * @brief get mirror castHandle.
     *
     * @return { int64_t } mirror castHandle.
     * @since 13
    */
    virtual int64_t GetMirrorCastHandle() = 0;

    /**
     * @brief Listen to the change of cast state change.
     *
     * @param castState The cast state of device info.
     * @param deviceInfo The device info.
     * @param isNeedRemove is need remove cast device
     * @since 13
    */
    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove);

    /**
     * @brief Listen to the change of cast event.
     *
     * @param errorCode The error code of cast event.
     * @param errorMsg The error message of cast event.
     * @since 13
    */
    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg);

    /**
     * @brief disconnect other session.
     *
     * @param { std::string } sessionId - avsession id.
     * @param { DeviceInfo } deviceinfo - The deviceinfo to the castprovider.
     * @since 13
    */
    virtual void DisconnectOtherSession(std::string sessionId, DeviceInfo deviceInfo) = 0;

    /**
     * @brief check is in mirror to stream state.
     *
     * @return { bool } is in mirror to stream state.
     * @since 20
    */
    virtual bool IsInMirrorToStreamState() = 0;

    /**
     * @brief check is in stream state.
     *
     * @return { bool } is in stream state.
     * @since 20
    */
    virtual bool IsRemoteCasting() = 0;

    /**
     * @brief set mirror castHandle.
     *
     * @param castHandle The mirror cast handle.
     * @since 20
    */
    virtual void SetMirrorCastHandle(int64_t castHandle) = 0;

    /**
     * @brief notify cast session created.
     *
     * @param castSessionId The cast session id.
     * @since 20
    */
    virtual void NotifyCastSessionCreated(const std::string castSessionId) = 0;

struct CastHandleInfo {
    OutputDeviceInfo outputDeviceInfo_;
    std::string sessionId_ = "-1";
    std::shared_ptr<IAVCastControllerProxy> avCastControllerProxy_ = nullptr;
    std::shared_ptr<IAVRouterListener> avRouterListener_ = nullptr;
};
#endif
};
} // namespace OHOS::AVSession
#endif // OHOS_AVROUTER_H
