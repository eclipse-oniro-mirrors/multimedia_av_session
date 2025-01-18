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

#include <thread>
#include <chrono>
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
    if (isServer_) {
        OnSessionServerOpened();
    }
}

void SoftbusDistributedDataManager::SessionClosed(int32_t socket)
{
    if (isServer_ && peerSocketInfo.name != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onSessionClosed: the group id is not match the media session group.");
        return;
    }
    if (isServer_) {
        OnSessionServerClosed(socket);
    } else {
        OnSessionProxyClosed(socket);
    }
}

void SoftbusDistributedDataManager::MessageReceived(int32_t socket, const std::string &data)
{
    if (peerSocketInfo.name != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onMessageReceived: the group id is not match the media session group. sessionName is %{public}s",
            peerSocketInfo.name);
        return;
    }
    if (isServer_) {
        OnMessageHandleReceived(socket, data);
    }
}
// LCOV_EXCL_STOP

void SoftbusDistributedDataManager::BytesReceived(int32_t socket, const std::string &data)
{
    if (peerSocketInfo.name != CONFIG_SOFTBUS_SESSION_TAG) {
        SLOGE("onBytesReceived: the group id is not match the media session group. sessionName is %{public}s",
            peerSocketInfo.name);
        return;
    }
    if (isServer_) {
        OnBytesServerReceived(socket, data);
    } else {
        OnBytesProxyReceived(socket, data);
    }
}

void SoftbusDistributedDataManager::InitSessionServer(const std::string &pkg)
{
    SLOGI("init session server...");
    isServer_ = true;
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    int32_t socket = SoftbusSessionManager::GetInstance().Socket(pkg);
    mServerSocketMap_.insert({pkg, socket});
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

bool SoftbusDistributedDataManager::CreateProxy(const std::shared_ptr<SoftbusSessionProxy> &proxy,
    const std::string &peerNetworkId, const std::string &packageName)
{
    SLOGI("create session proxy...");
    if (proxy == nullptr || peerNetworkId.c_str() == nullptr || peerNetworkId.empty() ||
        packageName.c_str() == nullptr || packageName.empty()) {
        SLOGW("createProxy fail for params invalid.");
        return false;
    }
    isServer_ = false;
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    if (mProxySocketMap_.find(peerNetworkId) != mProxySocketMap_.end()) {
        int32_t socketId = mProxySocketMap_[peerNetworkId];
        if (socketId > 0) {
            std::string softbusNetworkId;
            SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(socketId, softbusNetworkId);
            if (peerNetworkId == softbusNetworkId) {
                proxy->ConnectServer(socketId);
                return true;
            }
            mProxySocketMap_.erase(peerNetworkId);
        }
    }
    std::string anonymizeNetworkId = SoftbusSessionUtils::AnonymizeDeviceId(peerNetworkId);
    int32_t characteristic = proxy->GetCharacteristic();
    SLOGI("createProxy for device %{public}s characteristic:%{public}d",
        anonymizeNetworkId.c_str(), characteristic);
    std::map<int32_t, std::shared_ptr<SoftbusSessionProxy>> proxyMap;
    if (mDeviceToProxyMap_.find(peerNetworkId) == mDeviceToProxyMap_.end()) {
        proxyMap.insert({characteristic, proxy});
        mDeviceToProxyMap_.insert({peerNetworkId, proxyMap});
    } else {
        proxyMap = mDeviceToProxyMap_[peerNetworkId];
        proxyMap[characteristic] = proxy;
        int32_t socketId = ConnectRemoteDevice(peerNetworkId, packageName, softbusLinkMaxRetryTimes);
        if (socketId <= 0) {
            proxyMap.erase(characteristic);
            if (proxyMap.empty()) {
                mDeviceToProxyMap_.erase(peerNetworkId);
            }
            SLOGI("createProxy failed for no remote device connected");
            return false;
        } else {
            OnSessionProxyOpened(socketId);
            return true;
        }
    }
    return true;
}

bool SoftbusDistributedDataManager::ReleaseProxy(const std::shared_ptr<SoftbusSessionProxy> &proxy,
    const std::string &peerNetworkId)
{
    if (proxy == nullptr) {
        SLOGE("ReleaseProxy fail for proxy is null.");
        return true;
    }
    if (peerNetworkId.c_str() == nullptr || peerNetworkId.empty()) {
        SLOGE("ReleaseProxy fail for networkid is invalid.");
        return false;
    }
    std::string anonymizeNetworkId = SoftbusSessionUtils::AnonymizeDeviceId(peerNetworkId);
    SLOGI("ReleaseProxy for device %{public}s", anonymizeNetworkId.c_str());
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    if (mDeviceToProxyMap_.find(peerNetworkId) == mDeviceToProxyMap_.end()) {
        SLOGE("ReleaseProxy fail fo proxyMap is null");
        return true;
    }

    auto proxyMap = mDeviceToProxyMap_[peerNetworkId];
    int32_t characteristic = proxy->GetCharacteristic();
    if (proxyMap.find(characteristic) != proxyMap.end()) {
        auto proxy = proxyMap[characteristic];
        if (mProxySocketMap_.find(peerNetworkId) != mProxySocketMap_.end()) {
            int32_t socket = mProxySocketMap_[peerNetworkId];
            proxy->DisconnectServer(socket);
        }
        proxyMap.erase(characteristic);
    }
    if (proxyMap.empty()) {
        if (mProxySocketMap_.find(peerNetworkId) != mProxySocketMap_.end()) {
            int32_t socket = mProxySocketMap_[peerNetworkId];
            OnSessionProxyClosed(socket);
            SoftbusSessionManager::GetInstance().Shutdown(socket);
        }
        mDeviceToProxyMap_.erase(peerNetworkId);
        return true;
    }
    return false;
}

void SoftbusDistributedDataManager::DestroySessionServer(const std::string &pkg)
{
    SLOGI("destroy session server...");
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    if  (isServer_) {
        for (auto it = serverMap_.begin(); it != serverMap_.end();) {
            it->second->DisconnectAllProxy();
            it = serverMap_.erase(it);
        }
        int32_t mSocket = mServerSocketMap_[pkg];
        mServerSocketMap_.erase(pkg);
        SoftbusSessionManager::GetInstance().Shutdown(mSocket);
    } else {
        for (auto proxyMap = mDeviceToProxyMap_.begin(); proxyMap != mDeviceToProxyMap_.end(); proxyMap++) {
            for (auto it = proxyMap->second.begin(); it != proxyMap->second.end(); it++) {
                ReleaseProxy(it->second, proxyMap->first);
            }
        }
    }
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

void SoftbusDistributedDataManager::OnBytesServerReceived(int32_t socket, const std::string &data)
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
        if (data.length() > 1 && data[1] == MESSAGE_CODE_CONNECT_SERVER) {
            iter->second->ConnectProxy(socket);
            return;
        }
        iter->second->OnBytesReceived(deviceId, data);
    }
}

int32_t SoftbusDistributedDataManager::ConnectRemoteDevice(const std::string &peerNetworkId,
    const std::string &packageName, int32_t retryCount)
{
    std::string anonymizeNetworkId = SoftbusSessionUtils::AnonymizeDeviceId(peerNetworkId);
    SLOGI("ConnectRemoteDevice remote device %{public}s, retryCount: %{pulic}d",
        anonymizeNetworkId.c_str(), retryCount);
    if (mProxySocketMap_.find(peerNetworkId) == mProxySocketMap_.end()) {
        SLOGI("%{public}s is connected, no need to connect.", anonymizeNetworkId.c_str());
        return mProxySocketMap_[peerNetworkId];
    }
    int32_t socket = SoftbusSessionManager::GetInstance().Bind(peerNetworkId, packageName);
    if (socket <= 0 && retryCount > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(retryIntervalTime));
        socket = ConnectRemoteDevice(peerNetworkId, packageName, retryCount - 1);
    }
    return socket;
}

void SoftbusDistributedDataManager::OnSessionProxyOpened(int32_t socket)
{
    std::string softbusNetworkId;
    int32_t result = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(socket, softbusNetworkId);
    if (result < 0) {
        SLOGE("OnSessionProxyOpened: get softbus peer network id failed.");
        return;
    }
    std::string anonymizeNetworkId = SoftbusSessionUtils::AnonymizeDeviceId(softbusNetworkId);
    if (mProxySocketMap_.find(softbusNetworkId) == mProxySocketMap_.end()) {
        mProxySocketMap_.insert({softbusNetworkId, socket});
    } else {
        SLOGI("OnSessionProxyOpened: session exit, no need to add for %{public}s", anonymizeNetworkId.c_str());
        if (mDeviceToProxyMap_.find(softbusNetworkId) == mDeviceToProxyMap_.end()) {
            return;
        }
        std::map<int32_t, std::shared_ptr<SoftbusSessionProxy>> proxyMap = mDeviceToProxyMap_[softbusNetworkId];
        for (auto it = proxyMap.begin(); it != proxyMap.end(); it++) {
            it->second->ConnectServer(socket);
        }
    }
}

void SoftbusDistributedDataManager::OnSessionProxyClosed(int32_t socket)
{
    std::string networkId;
    int32_t result = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(socket, networkId);
    if (result < 0) {
        SLOGE("OnSessionProxyClosed: get softbus peer network id failed.");
        return;
    }
    std::string anonymizeNetworkId = SoftbusSessionUtils::AnonymizeDeviceId(networkId);
    SLOGI("OnSessionProxyClosed: the peer network id is %{public}s.", anonymizeNetworkId.c_str());
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    mDeviceToProxyMap_.erase(networkId);
    if (mDeviceToProxyMap_.find(networkId) != mDeviceToProxyMap_.end()) {
        SLOGW("OnSessionProxyClosed: found no socket for device %{public}s", anonymizeNetworkId.c_str());
        return;
    }
    auto proxyMap = mDeviceToProxyMap_[networkId];
    if (proxyMap.empty()) {
        return;
    }
    for (auto it = proxyMap.begin(); it != proxyMap.end(); it++) {
            it->second->DisconnectServer(socket);
        }
}

void SoftbusDistributedDataManager::OnBytesProxyReceived(int32_t socket, const std::string &data)
{
    if (data.length() <= 0) {
        SLOGE("OnBytesProxyReceived invalid data.");
        return;
    }
    std::string networkId;
    int32_t result = SoftbusSessionManager::GetInstance().ObtainPeerDeviceId(socket, networkId);
    if (result < 0) {
        SLOGE("OnBytesProxyReceived: get no softbus peer network");
        return;
    }
    std::string anonymizeNetworkId = SoftbusSessionUtils::AnonymizeDeviceId(networkId);
    SLOGI("OnBytesProxyReceived: %{public}s.", anonymizeNetworkId.c_str());
    std::lock_guard lockGuard(softbusDistributedDataLock_);
    if (mDeviceToProxyMap_.find(networkId) == mDeviceToProxyMap_.end()) {
        SLOGW("OnBytesProxyReceived no proxy for the device");
        return;
    }
    auto proxyMap = mDeviceToProxyMap_[networkId];
    auto iter = proxyMap.find(data[0]);
    if (iter == proxyMap.end()) {
        SLOGE("OnBytesProxyReceived: found no match characteristic");
        return;
    }
    iter->second->OnBytesReceived(networkId, data);
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession