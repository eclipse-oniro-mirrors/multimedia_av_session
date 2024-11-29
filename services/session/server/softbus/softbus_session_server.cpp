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

#include "softbus_session_server.h"

#include "avsession_log.h"
#include "avsession_errors.h"
#include "softbus_session_manager.h"
#include "softbus_session_utils.h"

namespace OHOS::AVSession {
SoftbusSessionServer::~SoftbusSessionServer() {}

void SoftbusSessionServer::ConnectProxy(int sessionId)
{
    std::string deviceId;
    int ret = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(sessionId, deviceId);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "obtain peer device id failed");
    SLOGI("connectProxy for device: %{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    OnConnectSession(sessionId);
    OnConnectProxy(deviceId);
}

// LCOV_EXCL_START
void SoftbusSessionServer::DisconnectProxy(int sessionId)
{
    std::string deviceId;
    int ret = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(sessionId, deviceId);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "obtain peer device id failed");
    SLOGI("disconnectProxy for device: %{public}s.", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    OnDisConnectSession(sessionId);
    OnDisconnectProxy(deviceId);
}

void SoftbusSessionServer::DisconnectAllProxy()
{
    SLOGI("DisConnectAllProxy");
    for (auto it = deviceToSessionMap_.begin(); it != deviceToSessionMap_.end(); it++) {
        SLOGI("disConnectAllProxy anonymizeDeviceId: %{public}s.",
            SoftbusSessionUtils::AnonymizeDeviceId(it->first).c_str());
        OnDisconnectProxy(it->first);
        it = deviceToSessionMap_.erase(it);
    }
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession