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

#ifndef HW_CAST_PROVIDER_SESSION_H
#define HW_CAST_PROVIDER_SESSION_H

#include <mutex>

#include "i_cast_session.h"
#include "cast_engine_common.h"
#include "avsession_info.h"
#include "avsession_utils.h"

namespace OHOS::AVSession {
class HwCastProviderSession : public CastEngine::ICastSessionListener,
    public std::enable_shared_from_this<HwCastProviderSession> {
public:
    explicit HwCastProviderSession(std::shared_ptr<CastEngine::ICastSession> castSession) : castSession_(castSession) {}
    ~HwCastProviderSession() override;

    void OnDeviceState(const CastEngine::DeviceStateInfo &stateInfo) override;
    void OnEvent(const CastEngine::EventId &eventId, const std::string &jsonParam) override;

    int32_t Init();
    void Release();
    bool AddDevice(const std::string deviceId, uint32_t spid);
    bool RemoveDevice(std::string deviceId, bool continuePlay = false);
    std::shared_ptr<CastEngine::IStreamPlayer> CreateStreamPlayer();
    bool RegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener);
    bool UnRegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener);
    bool SetStreamState(DeviceInfo deviceInfo);
    bool GetRemoteNetWorkId(std::string deviceId, std::string &networkId);
    void SetProtocolType(CastEngine::ProtocolType);
    void OnDeviceStateChange(const CastEngine::DeviceStateInfo &stateInfo);

private:
    void computeToastOnDeviceState(CastEngine::DeviceState state);

    std::shared_ptr<CastEngine::ICastSession> castSession_;
    std::vector<std::shared_ptr<IAVCastSessionStateListener>> castSessionStateListenerList_;
    std::recursive_mutex mutex_;
    int32_t stashDeviceState_ = -1;
    std::string stashDeviceId_;
    CastEngine::ProtocolType protocolType_ = CastEngine::ProtocolType::CAST_PLUS_STREAM;
    int32_t avToastDeviceState_ = ConnectionState::STATE_DISCONNECTED;

    const int32_t deviceStateConnection = 6;
    const int32_t eventIdStart = 2000;
    const int32_t eventIdEnd = 2999;
    const std::string MEDIA_CAST_DISCONNECT = "usual.event.MEDIA_CAST_DISCONNECT";
    const std::string MEDIA_CAST_ERROR = "usual.event.MEDIA_CAST_ERROR";
};
} // namespace OHOS::AVSession

#endif
