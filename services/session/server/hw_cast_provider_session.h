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

namespace OHOS::AVSession {
class HwCastProviderSession : public CastEngine::ICastSessionListener,
    public std::enable_shared_from_this<HwCastProviderSession> {
public:
    explicit HwCastProviderSession(std::shared_ptr<CastEngine::ICastSession> castSession) : castSession_(castSession) {}
    ~HwCastProviderSession() override;

    void OnDeviceState(const CastEngine::DeviceStateInfo &stateInfo) override;
    void OnEvent(const CastEngine::EventId &eventId, const std::string &jsonParam) override;

    void Init();
    void Release();
    bool AddDevice(const std::string deviceId);
    bool RemoveDevice(std::string deviceId);
    std::shared_ptr<CastEngine::IStreamPlayer> CreateStreamPlayer();
    bool RegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener);
    bool UnRegisterCastSessionStateListener(std::shared_ptr<IAVCastSessionStateListener> listener);
    void CheckProcessDone();
    bool SetStreamState();

private:
    std::shared_ptr<CastEngine::ICastSession> castSession_;
    std::vector<std::shared_ptr<IAVCastSessionStateListener>> castSessionStateListenerList_;
    std::recursive_mutex mutex_;
    int32_t stashDeviceState_ = -1;
    std::string stashDeviceId_;

    const int32_t deviceStateConnection = 6;
};
} // namespace OHOS::AVSession

#endif
