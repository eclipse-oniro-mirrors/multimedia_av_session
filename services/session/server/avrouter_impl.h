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

#ifndef OHOS_AVROUTER_IMPL_H
#define OHOS_AVROUTER_IMPL_H

#include "av_router.h"
#include "avcast_provider_manager.h"
#include "hw_cast_provider.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {
class AVRouterImpl : public AVRouter {
class CastSessionListener : public IAVCastSessionStateListener {
public:
    explicit CastSessionListener(AVRouterImpl *ptr)
    {
        ptr_ = ptr;
    }

    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo)
    {
        ptr_->OnCastStateChange(castState, deviceInfo);
    }

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
    {
        ptr_->OnCastEventRecv(errorCode, errorMsg);
    }

    AVRouterImpl *ptr_;
};
public:
    AVRouterImpl();

    int32_t Init(IAVSessionServiceListener *servicePtr) override;

    bool Release() override;

    int32_t StartDeviceLogging(int32_t fd, uint32_t maxSize) override;

    int32_t StopDeviceLogging() override;

    int32_t StartCastDiscovery(int32_t castDeviceCapability, std::vector<std::string> drmSchemes) override;

    int32_t StopCastDiscovery() override;

    int32_t SetDiscoverable(const bool enable) override;

    int32_t OnDeviceAvailable(OutputDeviceInfo& castOutputDeviceInfo) override;

    int32_t OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) override;

    int32_t OnDeviceOffline(const std::string& deviceId) override;

    void ReleaseCurrentCastSession() override;

    int32_t OnCastSessionCreated(const int32_t castId) override;

    int32_t OnCastServerDied(int32_t providerNumber) override;

    std::shared_ptr<IAVCastControllerProxy> GetRemoteController(const int64_t castHandle) override;

    int64_t StartCast(const OutputDeviceInfo& outputDeviceInfo,
        std::map<std::string, std::string>& serviceNameMapState, std::string sessionId) override;

    int32_t AddDevice(const int32_t castId, const OutputDeviceInfo& outputDeviceInfo) override;

    int32_t StopCast(const int64_t castHandle, bool continuePlay = false) override;

    int32_t StopCastSession(const int64_t castHandle) override;

    int32_t RegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVRouterListener> callback, std::string sessionId, DeviceInfo deviceInfo) override;

    int32_t UnRegisterCallback(int64_t castHandleconst,
        std::shared_ptr<IAVRouterListener> callback, std::string sessionId) override;

    int32_t SetServiceAllConnectState(int64_t castHandle, DeviceInfo deviceInfo) override;

    int32_t GetRemoteNetWorkId(int64_t castHandle, std::string deviceId, std::string &networkId) override;

    int64_t GetMirrorCastHandle() override;

    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo);

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg);

    void DisconnetOtherSession(std::string sessionId, DeviceInfo deviceInfo) override;

protected:

private:
    std::recursive_mutex servicePtrLock_;
    IAVSessionServiceListener *servicePtr_ = nullptr;
    std::recursive_mutex providerManagerLock_;
    std::map<int32_t, std::shared_ptr<AVCastProviderManager>> providerManagerMap_;
    std::map<std::string, std::string> castServiceNameMapState_;
    const std::string deviceStateConnection = "CONNECT_SUCC";
    int32_t providerNumber_ = 0;
    std::map<int64_t, CastHandleInfo> castHandleToInfoMap_;
    std::map<std::string, std::shared_ptr<IAVRouterListener>> mirrorSessionMap_;
    bool hasSessionAlive_ = false;
    int32_t providerNumberEnableDefault_ = 1;
    int32_t providerNumberDisable_ = 0;
    bool cacheStartDiscovery_ = false;
    bool cacheStartDeviceLogging_ = false;
    int32_t cacheCastDeviceCapability_ = -1;
    std::vector<std::string> cacheDrmSchemes_;
    std::shared_ptr<CastSessionListener> castSessionListener_;
    int32_t castConnectStateForDisconnect_ = 5;
    int32_t castConnectStateForConnected_ = 6;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVROUTER_IMPL_H
