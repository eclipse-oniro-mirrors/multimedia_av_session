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

#ifndef HW_CAST_PROVIDER_H
#define HW_CAST_PROVIDER_H

#include <mutex>
#include "cast_session_manager.h"
#include "i_avcast_controller_proxy.h"
#include "i_cast_session.h"
#include "i_stream_player.h"
#include "i_cast_session_manager_listener.h"
#include "hw_cast_provider_session.h"
#include "avsession_info.h"
#include "av_cast_provider.h"

namespace OHOS::AVSession {
class HwCastProvider : public AVCastProvider, public CastEngine::ICastSessionManagerListener,
    public std::enable_shared_from_this<HwCastProvider> {
public:
    HwCastProvider();
    ~HwCastProvider() override;

    int32_t Init() override;
    int32_t StartDeviceLogging(int32_t fd, uint32_t maxSize) override;
    int32_t StopDeviceLogging() override;
    bool StartDiscovery(int castCapability, std::vector<std::string> drmSchemes) override;
    void StopDiscovery() override;
    int32_t SetDiscoverable(const bool enable) override;
    void Release() override;
    int StartCastSession(bool isHiStream) override;
    void StopCastSession(int castId) override;
    bool AddCastDevice(int castId, DeviceInfo deviceInfo, uint32_t spid) override;
    bool RemoveCastDevice(int castId, DeviceInfo deviceInfo,
        const DeviceRemoveAction deviceRemoveAction = DeviceRemoveAction::ACTION_DISCONNECT) override;
    std::shared_ptr<IAVCastControllerProxy> GetRemoteController(int castId) override;
    bool RegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener) override;
    bool UnRegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener) override;
    bool RegisterCastSessionStateListener(int castId, std::shared_ptr<IAVCastSessionStateListener> listener) override;
    bool UnRegisterCastSessionStateListener(int castId, std::shared_ptr<IAVCastSessionStateListener> listener) override;

    void OnDeviceFound(const std::vector<CastEngine::CastRemoteDevice> &deviceList) override;
    void OnLogEvent(const int32_t eventId, const int64_t param) override;
    void OnDeviceOffline(const std::string &deviceId) override;
    void OnSessionCreated(const std::shared_ptr<CastEngine::ICastSession> &castSession) override;
    void NotifyCastSessionCreated(const std::string castSessionId);
    void DestroyCastSessionCreated(const std::string castSessionId);
    void OnServiceDied() override;
    bool SetStreamState(int64_t castHandle, DeviceInfo deviceInfo) override;
    int64_t GetMirrorCastHandle() override;
    bool GetRemoteNetWorkId(int32_t castId, std::string deviceId, std::string &networkId) override;
    bool GetRemoteDrmCapabilities(int32_t castId, std::string deviceId,
        std::vector<std::string> &drmCapabilities) override;
    int32_t GetProtocolType(uint32_t castProtocolType) override;

    int GetCastProtocolType(int castCapability);

    void SetMirrorCastHandle(int64_t castHandle);

private:
    std::vector<uint32_t> ParsePullClients(const std::string& str);
    static const int maxCastSessionSize = 256;
    std::vector<bool> castFlag_ = std::vector<bool>(maxCastSessionSize, false);
    std::map<int, std::shared_ptr<HwCastProviderSession>> hwCastProviderSessionMap_;
    std::map<int, std::shared_ptr<IAVCastControllerProxy>> avCastControllerMap_;
    std::vector<std::shared_ptr<IAVCastStateListener>> castStateListenerList_;
    std::recursive_mutex mutexLock_;
    bool isRelease_ = false;
    int64_t mirrorCastHandle = -1;
};
} // namespace OHOS::AVSession

#endif