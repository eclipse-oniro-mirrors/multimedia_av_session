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

#ifndef SOFTBUS_SESSION_MANAGER_H
#define SOFTBUS_SESSION_MANAGER_H

#include <string>
#include <mutex>
#include <map>

#include "socket.h"

namespace OHOS::AVSession {
class SoftbusSessionListener {
public:
    virtual void OnBind(int32_t socket, PeerSocketInfo info) = 0;
    virtual void OnShutdown(int32_t socket, ShutdownReason reason) = 0;
    virtual void OnBytes(int32_t socket, const void *data, int32_t dataLen) = 0;
    virtual void OnMessage(int32_t socket, const void *data, int32_t dataLen) = 0;
    virtual ~SoftbusSessionListener() = default;
};

class SoftbusSessionManager {
public:
    static SoftbusSessionManager& GetInstance();

    int32_t Socket(const std::string &pkgName);

    int32_t Bind(const std::string &peerNetworkId, const std::string &pkgName);

    void Shutdown(int32_t socket);

    int32_t SendMessage(int32_t socket, const std::string &data);

    int32_t SendBytes(int32_t socket, const std::string &data);

    int32_t ObtainPeerDeviceId(int32_t socket, std::string &deviceId);

    void AddSessionListener(std::shared_ptr<SoftbusSessionListener> softbusSessionListener);

    /* *
     * Callback adaptation for session channel opened.
     *
     * @param socket socket
     */
    void OnBind(int32_t socket, PeerSocketInfo info);

    /* *
     * Callback adaptation for session channel closed.
     *
     * @param socket socket
     */
    void OnShutdown(int32_t socket, ShutdownReason reason);

    /* *
     * Callback adaptation for data received by the session channel.
     *
     * @param socket socket
     * @param data data received by the session channel
     */
    void OnMessage(int32_t socket, const void *data, int32_t dataLen);
    void OnBytes(int32_t socket, const void *data, int32_t dataLen);

private:
    std::recursive_mutex socketLock_;

    std::vector<std::shared_ptr<SoftbusSessionListener>> sessionListeners_;
    std::map<int32_t, std::string> mMap_;
    static constexpr const int QOS_COUNT = 3;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_SESSION_MANAGER_H
