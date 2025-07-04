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

#include "softbus_session.h"

#include "avsession_log.h"
#include "avsession_errors.h"
#include "softbus_session_manager.h"
#include "softbus_session_utils.h"

namespace OHOS::AVSession {
void SoftbusSession::OnConnectSession(int32_t sessionId)
{
    std::string deviceId;
    int ret = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(sessionId, deviceId);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "obtain peer device id failed");
    std::lock_guard lockGuard(deviceMapLock_);
    SLOGI("OnConnectSession sessionId:%{public}d|deviceId:%{public}s", sessionId,
        SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    deviceToSessionMap_.insert({ deviceId, sessionId });
}

// LCOV_EXCL_START
void SoftbusSession::OnDisConnectSession(int32_t sessionId)
{
    std::string deviceId;
    int ret = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(sessionId, deviceId);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "obtain peer device id failed");
    std::lock_guard lockGuard(deviceMapLock_);
    SLOGI("OnDisConnectSession sessionId:%{public}d|deviceId:%{public}s", sessionId,
        SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    deviceToSessionMap_.erase(deviceId);
}

void SoftbusSession::SendByteToAll(const std::string &data)
{
    SLOGI("SendByteToAll: %{public}s", data.c_str());
    std::lock_guard lockGuard(deviceMapLock_);
    for (auto it = deviceToSessionMap_.begin(); it != deviceToSessionMap_.end(); it++) {
        SLOGI("SendByteToAll : %{public}s", data.c_str());
        SoftbusSessionManager::GetInstance().SendBytes(it->second, data);
    }
}

void SoftbusSession::SendByte(const std::string &deviceId, const std::string &data)
{
    SLOGI("SendByte: %{public}s", data.c_str());
    std::lock_guard lockGuard(deviceMapLock_);
    auto iter = deviceToSessionMap_.find(deviceId);
    if (iter != deviceToSessionMap_.end()) {
        SoftbusSessionManager::GetInstance().SendBytes(iter->second, data);
    }
}

void SoftbusSession::SendJsonStringByte(const std::string &deviceId, const std::string &data)
{
    SLOGI("SendByte: %{public}s", SoftbusSessionUtils::AnonymizeMacAddressInSoftBusMsg(data).c_str());
    std::lock_guard lockGuard(deviceMapLock_);
    auto iter = deviceToSessionMap_.find(deviceId);
    if (iter != deviceToSessionMap_.end()) {
        SoftbusSessionManager::GetInstance().SendBytesForNext(iter->second, data);
    } else {
        SLOGE("SendJsonStringByte findNoDevice:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    }
}

void SoftbusSession::SendByteForNext(const std::string &deviceId, const std::string &data)
{
    std::lock_guard lockGuard(deviceMapLock_);
    SLOGI("SendByteLength: %{public}d", static_cast<int>(data.size()));
    auto iter = deviceToSessionMap_.find(deviceId);
    if (iter != deviceToSessionMap_.end()) {
        SoftbusSessionManager::GetInstance().SendBytesForNext(iter->second, data);
    } else {
        SLOGE("SendByteForNext findNoDevice:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    }
}

void SoftbusSession::SendByte(int32_t sessionId, const std::string &data)
{
    SLOGI("SendByte: %{public}s", data.c_str());
    SoftbusSessionManager::GetInstance().SendBytes(sessionId, data);
}

void SoftbusSession::SendByteForNext(int32_t sessionId, const std::string &data)
{
    SLOGI("SendByteForNext: %{public}d", static_cast<int>(data.size()));
    int ret = SoftbusSessionManager::GetInstance().SendBytesForNext(sessionId, data);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("SendbyteNext with ret:%{public}d fail!", ret);
    }
}

void SoftbusSession::SendMessage(const std::string &deviceId, const std::string &data)
{
    SLOGI("SendMessage: %{public}s", data.c_str());
    std::lock_guard lockGuard(deviceMapLock_);
    auto iter = deviceToSessionMap_.find(deviceId);
    if (iter != deviceToSessionMap_.end()) {
        SoftbusSessionManager::GetInstance().SendMessage(iter->second, data);
    }
}

void SoftbusSession::SendMessage(int32_t sessionId, const std::string &data)
{
    SLOGI("SendMessage: %{public}s", data.c_str());
    SoftbusSessionManager::GetInstance().SendMessage(sessionId, data);
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession