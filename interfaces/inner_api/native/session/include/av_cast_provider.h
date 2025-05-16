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

#ifndef AV_CAST_PROVIDER_H
#define AV_CAST_PROVIDER_H

#include "cast_engine_common.h"
#include "i_avcast_state_listener.h"
#include "avsession_descriptor.h"
#include "i_avcast_controller_proxy.h"

namespace OHOS::AVSession {
class AVCastProvider {
public:
    /**
     * @brief Construct AVCastProvider object.
     *
     * @since 10
    */
    AVCastProvider() = default;

    /**
     * @brief Deconstruct AVCastProvider object.
     *
     * @since 10
    */
    virtual ~AVCastProvider() = default;

    /**
     * @brief Initialize AVCastProvider object.
     *
     * @return {int32_t} Returns whether init successfully.
     * @since 10
    */
    virtual int32_t Init() = 0;

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
     * @brief Start searching for sink end devices.
     *
     * @param { int } castCapability - The type of device want to discover.
     * @return { bool } Whether the device discovery operation was successful.
     * @since 10
    */
    virtual bool StartDiscovery(int castCapability, std::vector<std::string> drmSchemes) = 0;

    /**
     * @brief Stop Discovering Devices
     *
     * @since 10
    */
    virtual void StopDiscovery() = 0;

    /**
     * @brief Used on the Sink end to set whether it can be discovered or not.
     *
     * @param { const bool } enable - whether the sink device can be discovered or not.
     * @return { int32_t } Whether the operation was successful
     * @since 10
    */
    virtual int32_t SetDiscoverable(const bool enable) = 0;

    /**
     * @brief Release AVCastProvider object.
     *
     * @since 10
    */
    virtual void Release() = 0;

    /**
     * @brief Register listener for AVCast state callback event.
     *
     * @param { std::shared_ptr<IAVCastStateListener> } listener - Register the pointer.
     * @return { bool } Whether the operation was successful.
     * @since 10
    */
    virtual bool RegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener) = 0;

    /**
     * @brief Unregister listener for AVCast state callback event.
     *
     * @param { std::shared_ptr<IAVCastSessionStateListener> } callback - The pointer want unregistered.
     * @return { bool } Whether the operation was successful.
     * @since 10
    */
    virtual bool UnRegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener) = 0;
    
    /**
     * @brief Notify CastEngine to add (connect) remote devices.
     *
     * @param { int32_t } castId - Find the corresponding provider through this ID.
     * @param { DeviceInfo } deviceInfo - Devices to be connected.
     * @return { bool } Whether the operation was successful.
     * @since 10
    */
    virtual bool AddCastDevice(int castId, DeviceInfo deviceInfo) = 0;

    /**
     * @brief Notify CastEngine to remove (disconnect) remote devices.
     *
     * @param { int32_t } castId - Find the corresponding provider through this ID.
     * @param { OutputDeviceInfo } outputDeviceInfo - Devices to be disconnected.
     * @param { bool } continuePlay - whether continue play when disconnect device.
     * @return { bool } Whether the operation was successful.
     * @since 10
    */
    virtual bool RemoveCastDevice(int castId, DeviceInfo deviceInfo, bool continuePlay = false) = 0;

    /**
     * @brief Start cast process.
     *
     * @param { bool } isHiStream - whether session is hi stream.
     * @return { int } Whether the operation was successful.
     * @since 10
    */
    virtual int StartCastSession(bool isHiStream) = 0;

    /**
     * @brief Stop cast process.
     *
     * @param { int } castId - The ID corresponding to the provider that needs to be stopped.
     * @since 10
    */
    virtual void StopCastSession(int castId) = 0;

    /**
     * @brief Get the cast controller specified by castHandle.
     *
     * @param { int } castId - castId corresponding to cast engine session.
     * @return { std::shared_ptr<IAVCastControllerProxy> } Obtained cast controller.
     * @since 10
    */
    virtual std::shared_ptr<IAVCastControllerProxy> GetRemoteController(int castId) = 0;

    /**
     * @brief Register listener for AVCast session state callback event.
     *
     * @param { int } castId - The ID corresponding to the provider.
     * @param { std::shared_ptr<IAVCastSessionStateListener> } callback - Callback function.
     * @return { bool } Whether the operation was successful.
     * @since 10
    */
    virtual bool RegisterCastSessionStateListener(int castId,
        std::shared_ptr<IAVCastSessionStateListener> listener) = 0;

    /**
     * @brief Unregister listener for AVCast session state callback event.
     *
     * @param { int } castId - The ID corresponding to the provider.
     * @param { std::shared_ptr<IAVCastSessionStateListener> } callback - Callback function.
     * @return { bool } Whether the operation was successful.
     * @since 10
    */
    virtual bool UnRegisterCastSessionStateListener(int castId,
        std::shared_ptr<IAVCastSessionStateListener> listener) = 0;

    /**
     * @brief set allconnect state.
     *
     * @param { int64_t } castHandle const - The ID corresponding to the castprovider.
     * @param { DeviceInfo } cast deviceinfo - The deviceinfo to the castprovider.
     * @return { bool } Whether the operation was successful.
     * @since 11
    */
    virtual bool SetStreamState(int64_t castHandle, DeviceInfo deviceInfo) = 0;

    /**
     * @brief get mirror castHandle.
     *
     * @return { int64_t } mirror castHandle.
     * @since 11
    */
    virtual int64_t GetMirrorCastHandle() = 0;

    /**
     * @brief get remote networkId.
     *
     * @param { int32_t } castHandle const - The ID corresponding to the castprovider.
     * @param { string } cast deviceId - The deviceId give cast+ to get remote networkId.
     * @param { string } cast networkId - The networkId to transmit remote networkId.
     * @return { bool } Whether the operation was successful.
     * @since 11
    */
    virtual bool GetRemoteNetWorkId(int32_t castId, std::string deviceId, std::string &networkId) = 0;

    /**
     * @brief get protocol type.
     *
     * @param { uint32_t } cast protocol type - The type of cast protocol.
     * @return { int32_t } The type of avsession protocol.
     * @since 13
    */
    virtual int32_t GetProtocolType(uint32_t castProtocolType) = 0;
};
} // namespace OHOS::AVSession
#endif
