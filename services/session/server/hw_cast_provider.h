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

namespace OHOS::AVSession {
class HwCastProvider: public AVCastProvider, public CastEngine::ICaseSessionManagerListener,
    public std::enable_shared_from_this<HwCastProvider> {
public:
    HwCastProvider() = default;
    ~HwCastProvider() override; 

    void Init() override;
    bool StartDiscovery(int castCapability) override;
    void StopDiscovery() override;
    void Release() override;
    int StartCastSession() override;
    void StopCastSession(int castId) override;
    bool AddCastDevice(int castId, DeviceInfo deviceInfo) override;
    bool RemoveCastDevice(int castId, DeviceInfo deviceInfo) override;
    std::shared_ptr<IAVCastControllerProxy> GetRemoteController(int castId) override;
    bool RegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener) override;
    bool UnRegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener) override;
    bool RegisterCastSessionStateListener(int castId, std::shared_ptr<IAVCastSessionStateListener> listener) override;
    bool UnRegisterCastSessionStateListener(int castId, std::shared_ptr<IAVCastSessionStateListener> listener) override;

    void OnDeviceFound(const std::vector<CastEngine::CastRemoteDevice> &deviceList) override;
    void OnSessionCreated(const std::shared_ptr<CastEngine::ICastSession> &castSession) override;
    void OnServiceDied() override;

private:
    static const int MAX_CAST_SESSION_SIZE = 16;
    std::vector<bool> castFlag_ = std::vector<bool>(MAX_CAST_SESSION_SIZE, false);
    std::map<int, std::shared_ptr<HwCastProviderSession>> hwCastProviderSessionMap_;
    std::map<int, std::shared_ptr<IAVCastControllerProxy>> avCastControllerMap_;
    std::vector<std::shared_ptr<IAVCastStateListener>> castStateListenerList_;
    std::mutex mutex_;
};
} // namespace OHOS::AVSession

#endif