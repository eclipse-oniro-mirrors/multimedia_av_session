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

#include "cast_engine_common_h"
#include "i_avcast_state_listener.h"
#include "avsession_descriptor.h"
#include "i_avcast_controller_proxy.h"

namespace OHOS::AVSession {
class AVCastProvider {
public:
    AVCastProvider() = default;
    virtual ~AVCastProvider() = default; 

    virtual void Init() = 0;
    virtual bool StartDiscovery(int castCapability) = 0;
    virtual void StopDiscovery() = 0;
    virtual void Release() = 0;
    virtual bool RegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener) = 0;
    virtual bool UnRegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener) = 0;
    virtual bool AddCastDevice(int castId, DeviceInfo deviceInfo) = 0;
    virtual bool RemoveCastDevice(int castId, DeviceInfo deviceInfo) = 0;
    virtual int StartCastSession() = 0;
    virtual void StopCastSession(int castId) = 0;
    virtual std::shared_ptr<IAVCastControllerProxy> GetRemoteController(int castId) = 0;
    virtual bool RegisterCastSessionStateListener(int castId, std::shared_ptr<IAVCastSessionStateListener> listener) = 0;
    virtual bool UnRegisterCastSessionStateListener(int castId, std::shared_ptr<IAVCastSessionStateListener> listener) = 0;
};
} // namespace OHOS::AVSession

#endif