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

// LCOV_EXCL_START
void SoftbusDistributedDataManager::Init()
{
    std::weak_ptr<SoftbusDistributedDataManager> managerWeak(shared_from_this());
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    ssListener_ = std::make_shared<SSListener>(managerWeak);
    SoftbusSessionManager::GetInstance().AddSessionListener(ssListener_);
}

void SoftbusDistributedDataManager::SessionOpened(int32_t socket, PeerSocketInfo info)
{
    std::string sessionName = info.name;
    peerSocketInfo.name = info.name;
    peerSocketInfo.networkId = info.networkId;
    peerSocketInfo.pkgName = info.pkgName;
    peerSocketInfo.dataType = info.dataType;
    if (sessionName != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionOpened: the group id is not match the media session group. sessionName is %{public}s",
            sessionName.c_str());
        return;
    }
    OnSessionServerOpened();
}

void SoftbusDistributedDataManager::SessionClosed(int32_t socket)
{
    if (peerSocketInfo.name != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionOpened: the group id is not match the media session group.");
        return;
    }
    OnSessionServerClosed(socket);
}

void SoftbusDistributedDataManager::MessageReceived(int32_t socket, const std::string &data)
{
    if (peerSocketInfo.name != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionOpened: the group id is not match the media session group. sessionName is %{public}s",
            peerSocketInfo.name);
        return;
    }
    OnMessageHandleReceived(socket, data);
}
// LCOV_EXCL_STOP

void SoftbusDistributedDataManager::BytesReceived(int32_t socket, const std::string &data)
{
    if (peerSocketInfo.name != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionOpened: the group id is not match the media session group. sessionName is %{public}s",
            peerSocketInfo.name);
        return;
    }
    OnBytesServerReceived(data);
}

void SoftbusDistributedDataManager::InitSessionServer(const std::string &pkg)
{
    SLOGI("init session server...");
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    int32_t socket = SoftbusSessionManager::GetInstance().Socket(pkg);
    mMap_.insert({pkg, socket});
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
    int32_t mSocket = mMap_[pkg];
    mMap_.erase(pkg);
    SoftbusSessionManager::GetInstance().Shutdown(mSocket);
}

void SoftbusDistributedDataManager::ReleaseServer(const std::shared_ptr<SoftbusSessionServer> &server)
{
    CHECK_AND_RETURN_LOG(server != nullptr, "server is nullptr");
    int characteristic = server->GetCharacteristic();
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    auto iter = serverMap_.find(characteristic);
    if (iter != serverMap_.end() && iter->second == server) {
        server->DisconnectAllProxy();
        serverMap_.erase(characteristic);
    }
}

// LCOV_EXCL_START
void SoftbusDistributedDataManager::OnSessionServerOpened()
{
    SLOGI("OnSessionServerOpened: the peer device id is %{public}s.",
        SoftbusSessionUtils::AnonymizeDeviceId(peerSocketInfo.networkId).c_str());
}

void SoftbusDistributedDataManager::OnSessionServerClosed(int32_t socket)
{
    SLOGI("OnSessionServerClosed: the peer device id is %{public}s.",
        SoftbusSessionUtils::AnonymizeDeviceId(peerSocketInfo.networkId).c_str());
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    for (auto it = serverMap_.begin(); it != serverMap_.end(); it++) {
        it->second->DisconnectProxy(socket);
    }
}

void SoftbusDistributedDataManager::OnMessageHandleReceived(int32_t socket, const std::string &data)
{
    std::string deviceId = peerSocketInfo.networkId;
    std::string anonymizeDeviceId = SoftbusSessionUtils::AnonymizeDeviceId(deviceId);
    SLOGI("onMessageHandleReceived: %{public}s", anonymizeDeviceId.c_str());
    if (data.length() > 1 && data[0] == MESSAGE_CODE_CONNECT_SERVER) {
        std::lock_guard lockGuard(softbusDistributedDataLock_);
        auto iter = serverMap_.find(data[1]);
        if (iter == serverMap_.end()) {
            SLOGE("onMessageHandleReceived: server is invalid deviceId %{public}s", anonymizeDeviceId.c_str());
            return;
        }
        iter->second->ConnectProxy(socket);
    }
}

void SoftbusDistributedDataManager::OnBytesServerReceived(const std::string &data)
{
    std::string deviceId = peerSocketInfo.networkId;
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
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession