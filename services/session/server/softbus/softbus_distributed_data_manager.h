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

#ifndef SOFTBUS_DISTRIBUTED_DATA_MANAGER_H
#define SOFTBUS_DISTRIBUTED_DATA_MANAGER_H

#include <mutex>

#include "softbus_session_manager.h"
#include "softbus_session_server.h"
#include "softbus_session_proxy.h"

namespace OHOS::AVSession {
class SoftbusDistributedDataManager : public std::enable_shared_from_this<SoftbusDistributedDataManager> {
    class SSListener : public SoftbusSessionListener {
    public:
        explicit SSListener(std::weak_ptr<SoftbusDistributedDataManager> ptr)
        {
            ptr_ = ptr;
        }

        void OnBind(int32_t socket, PeerSocketInfo info) override
        {
            std::shared_ptr<SoftbusDistributedDataManager> manager = ptr_.lock();
            if (manager != nullptr) {
                manager->SessionOpened(socket, info);
            }
        }

        void OnShutdown(int32_t socket, ShutdownReason reason) override
        {
            std::shared_ptr<SoftbusDistributedDataManager> manager = ptr_.lock();
            if (manager != nullptr) {
                manager->SessionClosed(socket);
            }
        }

        void OnMessage(int32_t socket, const void *data, int32_t dataLen) override
        {
            std::shared_ptr<SoftbusDistributedDataManager> manager = ptr_.lock();
            std::string msg = std::string(static_cast<const char*>(data), dataLen);
            if (manager != nullptr) {
                manager->MessageReceived(socket, msg);
            }
        }

        void OnBytes(int32_t socket, const void *data, int32_t dataLen) override
        {
            std::shared_ptr<SoftbusDistributedDataManager> manager = ptr_.lock();
            std::string msg = std::string(static_cast<const char*>(data), dataLen);
            if (manager != nullptr) {
                manager->BytesReceived(socket, msg);
            }
        }

        std::weak_ptr<SoftbusDistributedDataManager> ptr_;
    };

public:
    SoftbusDistributedDataManager();

    ~SoftbusDistributedDataManager();

    void Init();

    void InitSessionServer(const std::string &pkg);

    void CreateServer(const std::shared_ptr<SoftbusSessionServer> &server);

    void DestroySessionServer(const std::string &pkg);

    void ReleaseServer(const std::shared_ptr<SoftbusSessionServer> &server);

    bool CreateProxy(const std::shared_ptr<SoftbusSessionProxy> &proxy,
        const std::string &peerNetworkId, const std::string &packageName);

    bool ReleaseProxy(const std::shared_ptr<SoftbusSessionProxy> &proxy, const std::string &peerNetworkId);

private:
    void SessionOpened(int32_t socket, PeerSocketInfo info);
    void SessionClosed(int32_t socket);
    void MessageReceived(int32_t socket, const std::string &data);
    void BytesReceived(int32_t socket, const std::string &data);
    void OnSessionServerOpened();
    void OnSessionServerClosed(int32_t socket);
    void OnMessageHandleReceived(int32_t socket, const std::string &data);
    void OnBytesServerReceived(int32_t socket, const std::string &data);
    int32_t ConnectRemoteDevice(const std::string &peerNetworkId,
        const std::string &packageName, int32_t retryCount);
    void OnSessionProxyOpened(int32_t socket);
    void OnSessionProxyClosed(int32_t socket);
    void OnBytesProxyReceived(int32_t socket, const std::string &data);

    std::map<int32_t, std::shared_ptr<SoftbusSessionServer>> serverMap_;
    std::shared_ptr<SSListener> ssListener_;
    std::recursive_mutex softbusDistributedDataLock_;
    std::map<const std::string, int32_t> mServerSocketMap_;

    static constexpr const int MESSAGE_CODE_CONNECT_SERVER = 1;

    PeerSocketInfo peerSocketInfo = {
        .name = nullptr,
        .networkId = nullptr,
        .pkgName = nullptr,
        .dataType = DATA_TYPE_BYTES,
    };

    bool isServer_ = true;
    std::map<const std::string, int32_t> mProxySocketMap_;
    std::map<const std::string, std::map<int32_t, std::shared_ptr<SoftbusSessionProxy>>> mDeviceToProxyMap_;
    static constexpr const int softbusLinkMaxRetryTimes = 5;
    static constexpr int retryIntervalTime = 500;
    std::map<const std::string, int32_t> mMap_;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_DISTRIBUTED_DATA_MANAGER_H