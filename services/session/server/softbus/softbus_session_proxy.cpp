/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_session_proxy.h"

#include "avsession_log.h"
#include "avsession_errors.h"
#include "softbus_session_manager.h"
#include "softbus_session_utils.h"
#include "migrate_avsession_constant.h"

namespace OHOS::AVSession {
SoftbusSessionProxy::~SoftbusSessionProxy() {}

void SoftbusSessionProxy::ConnectServer(int socketId)
{
    std::string networkId;
    int ret = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(socketId, networkId);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "obtain peer network id failed");
    SLOGI("ConnectServer for device:%{public}s",
        SoftbusSessionUtils::AnonymizeDeviceId(networkId).c_str());
    OnConnectSession(socketId);
    char message[] = {GetCharacteristic(), MESSAGE_CODE_CONNECT_SERVER, '\0'};
    SendByte(socketId, std::string(message));
    OnConnectServer(networkId);
}

//LCOV_EXCL_START
void SoftbusSessionProxy::DisconnectServer(int socketId)
{
    std::string networkId;
    int ret = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(socketId, networkId);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "obtain peer network id failed");
    SLOGI("DisconnectServer for device:%{public}s",
        SoftbusSessionUtils::AnonymizeDeviceId(networkId).c_str());
    OnDisConnectSession(socketId);
    OnDisconnectServer(networkId);
}
//LCOV_EXCL_STOP
} // namespace OHOS::AVSession