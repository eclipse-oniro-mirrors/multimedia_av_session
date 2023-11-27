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

#include "softbus_distributed_data_manager.h"

#include "avsession_log.h"
#include "avsession_errors.h"
#include "migrate_avsession_constant.h"
#include "softbus_session_utils.h"


namespace OHOS::AVSession {
SoftbusDistributedDataManager::SoftbusDistributedDataManager() {}

SoftbusDistributedDataManager::~SoftbusDistributedDataManager() {}

void SoftbusDistributedDataManager::Init()
{
    std::weak_ptr<SoftbusDistributedDataManager> managerWeak(shared_from_this());
    ssListener_ = std::make_shared<SSListener>(managerWeak);
    SoftbusSessionManager::GetInstance().AddSessionListener(ssListener_);
}

void SoftbusDistributedDataManager::SessionOpened(int32_t sessionId)
{
    std::string sessionName;
    int32_t ret = SoftbusSessionManager::GetInstance().GetPeerSessionName(sessionId, sessionName);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "GetPeerSessionName failed");
    if (sessionName != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionOpened: the group id is not match the media session group. sessionName is %{public}s",
            sessionName.c_str());
        return;
    }
    if (SoftbusSessionManager::GetInstance().IsServerSide(sessionId)) {
        OnSessionServerOpened(sessionId);
    }
}

void SoftbusDistributedDataManager::SessionClosed(int32_t sessionId)
{
    std::string sessionName;
    int32_t ret = SoftbusSessionManager::GetInstance().GetPeerSessionName(sessionId, sessionName);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "GetPeerSessionName failed");
    if (sessionName != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionOpened: the group id is not match the media session group.");
        return;
    }
    std::string deviceId;
    ret = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(sessionId, deviceId);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "ObtainPeerDeviceId failed");
    if (SoftbusSessionManager::GetInstance().IsServerSide(sessionId)) {
        OnSessionServerClosed(sessionId, deviceId);
    }
}

void SoftbusDistributedDataManager::MessageReceived(int32_t sessionId, const std::string &data)
{
    std::string sessionName;
    int32_t ret = SoftbusSessionManager::GetInstance().GetPeerSessionName(sessionId, sessionName);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "GetPeerSessionName failed");
    if (sessionName != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionOpened: the group id is not match the media session group. sessionName is %{public}s",
            sessionName.c_str());
        return;
    }
    OnMessageHandleReceived(sessionId, data);
}

void SoftbusDistributedDataManager::BytesReceived(int32_t sessionId, const std::string &data)
{
    std::string sessionName;
    int32_t ret = SoftbusSessionManager::GetInstance().GetPeerSessionName(sessionId, sessionName);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "GetPeerSessionName failed");
    if (sessionName != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionOpened: the group id is not match the media session group. sessionName is %{public}s",
            sessionName.c_str());
        return;
    }
    if (SoftbusSessionManager::GetInstance().IsServerSide(sessionId)) {
        OnBytesServerReceived(sessionId, data);
    }
}

void SoftbusDistributedDataManager::InitSessionServer(const std::string &pkg)
{
    SLOGI("init session server...");
    SoftbusSessionManager::GetInstance().CreateSessionServer(pkg);
}

void SoftbusDistributedDataManager::CreateServer(const std::shared_ptr<SoftbusSessionServer> &server)
{
    if (server == nullptr) {
        SLOGE("createServer fail for server is null.");
        return;
    }
    int characteristic = server->GetCharacteristic();
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    serverMap_.insert({ characteristic, server });
}

void SoftbusDistributedDataManager::DestroySessionServer(const std::string &pkg)
{
    SLOGI("destroy session server...");
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    for (auto it = serverMap_.begin(); it != serverMap_.end();) {
        it->second->DisconnectAllProxy();
        serverMap_.erase(it++);
    }
    SoftbusSessionManager::GetInstance().RemoveSessionServer(pkg);
}

void SoftbusDistributedDataManager::ReleaseServer(const std::shared_ptr<SoftbusSessionServer> &server)
{
    int characteristic = server->GetCharacteristic();
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    auto iter = serverMap_.find(characteristic);
    if (iter != serverMap_.end() && iter->second == server) {
        server->DisconnectAllProxy();
        serverMap_.erase(characteristic);
    }
}

void SoftbusDistributedDataManager::OnSessionServerOpened(int32_t sessionId)
{
    std::string deviceId;
    SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(sessionId, deviceId);
    SLOGI("OnSessionServerOpened: the peer device id is %{public}s.",
        SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
}

void SoftbusDistributedDataManager::OnSessionServerClosed(int32_t sessionId, const std::string &deviceId)
{
    SLOGI("OnSessionServerClosed: the peer device id is %{public}s.",
        SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    for (auto it = serverMap_.begin(); it != serverMap_.end(); it++) {
        it->second->DisconnectProxy(sessionId);
    }
}

void SoftbusDistributedDataManager::OnMessageHandleReceived(int32_t sessionId, const std::string &data)
{
    std::string deviceId;
    SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(sessionId, deviceId);
    std::string anonymizeDeviceId = SoftbusSessionUtils::AnonymizeDeviceId(deviceId);
    SLOGI("onMessageHandleReceived: %{public}s", anonymizeDeviceId.c_str());
    if (data.length() > 1 && data[0] == MESSAGE_CODE_CONNECT_SERVER) {
        std::lock_guard lockGuard(softbusDistributedDataLock_);
        auto iter = serverMap_.find(data[1]);
        if (iter == serverMap_.end()) {
            SLOGE("onMessageHandleReceived: server is invalid deviceId %{public}s", anonymizeDeviceId.c_str());
            return;
        }
        iter->second->ConnectProxy(sessionId);
    }
}

void SoftbusDistributedDataManager::OnBytesServerReceived(int32_t sessionId, const std::string &data)
{
    std::string deviceId;
    SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(sessionId, deviceId);
    std::string anonymizeDeviceId = SoftbusSessionUtils::AnonymizeDeviceId(deviceId);
    SLOGI("onBytesServerReceived: %{public}s", anonymizeDeviceId.c_str());
    if (data.length() > 0) {
        std::lock_guard lockGuard(softbusDistributedDataLock_);
        auto iter = serverMap_.find(data[0]);
        if (iter == serverMap_.end()) {
            SLOGE("onBytesServerReceived: server is invalid deviceId %{public}s", anonymizeDeviceId.c_str());
            return;
        }
        iter->second->OnBytesReceived(deviceId, data);
    }
}
} // namespace OHOS::AVSession