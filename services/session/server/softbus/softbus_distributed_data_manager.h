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

namespace OHOS::AVSession {
class SoftbusDistributedDataManager : public std::enable_shared_from_this<SoftbusDistributedDataManager> {
    class SSListener : public SoftbusSessionListener {
    public:
        explicit SSListener(std::weak_ptr<SoftbusDistributedDataManager> ptr)
        {
            ptr_ = ptr;
        }

        void OnSessionOpened(int32_t sessionId) override
        {
            std::shared_ptr<SoftbusDistributedDataManager> manager = ptr_.lock();
            if (manager != nullptr) {
                manager->SessionOpened(sessionId);
            }
        }

        void OnSessionClosed(int32_t sessionId) override
        {
            std::shared_ptr<SoftbusDistributedDataManager> manager = ptr_.lock();
            if (manager != nullptr) {
                manager->SessionClosed(sessionId);
            }
        }

        void OnMessageReceived(int32_t sessionId, const std::string &data) override
        {
            std::shared_ptr<SoftbusDistributedDataManager> manager = ptr_.lock();
            if (manager != nullptr) {
                manager->MessageReceived(sessionId, data);
            }
        }

        void OnBytesReceived(int32_t sessionId, const std::string &data) override
        {
            std::shared_ptr<SoftbusDistributedDataManager> manager = ptr_.lock();
            if (manager != nullptr) {
                manager->BytesReceived(sessionId, data);
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

private:
    void SessionOpened(int32_t sessionId);
    void SessionClosed(int32_t sessionId);
    void MessageReceived(int32_t sessionId, const std::string &data);
    void BytesReceived(int32_t sessionId, const std::string &data);
    void OnSessionServerOpened(int32_t sessionId);
    void OnSessionServerClosed(int32_t sessionId, const std::string &deviceId);
    void OnMessageHandleReceived(int32_t sessionId, const std::string &data);
    void OnBytesServerReceived(int32_t sessionId, const std::string &data);

    std::map<int32_t, std::shared_ptr<SoftbusSessionServer>> serverMap_;
    std::shared_ptr<SSListener> ssListener_;
    std::recursive_mutex softbusDistributedDataLock_;

    static constexpr const int MESSAGE_CODE_CONNECT_SERVER = 1;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_DISTRIBUTED_DATA_MANAGER_H