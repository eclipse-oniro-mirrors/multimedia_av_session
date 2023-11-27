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

namespace OHOS::AVSession {
class SoftbusSessionListener {
public:
    virtual void OnSessionOpened(int32_t sessionId) = 0;
    virtual void OnSessionClosed(int32_t sessionId) = 0;
    virtual void OnMessageReceived(int32_t sessionId, const std::string &data) = 0;
    virtual void OnBytesReceived(int32_t sessionId, const std::string &data) = 0;
    virtual ~SoftbusSessionListener() = default;
};

class SoftbusSessionManager {
public:
    static SoftbusSessionManager& GetInstance();

    int32_t CreateSessionServer(const std::string &pkg);

    int32_t RemoveSessionServer(const std::string &pkg);

    int32_t OpenSession(const std::string &deviceId, const std::string &groupId);

    int32_t CloseSession(int32_t sessionId);

    int32_t SendMessage(int32_t sessionId, const std::string &data);

    int32_t SendBytes(int32_t sessionId, const std::string &data);

    int32_t ObtainPeerDeviceId(int32_t sessionId, std::string &deviceId);

    int32_t GetPeerSessionName(int32_t sessionId, std::string &sessionName);

    bool IsServerSide(int32_t sessionId);

    void AddSessionListener(std::shared_ptr<SoftbusSessionListener> softbusSessionListener);

    /* *
     * Callback adaptation for session channel opened.
     *
     * @param sessionId sessionId
     */
    int32_t OnSessionOpened(int32_t sessionId, int32_t result);

    /* *
     * Callback adaptation for session channel closed.
     *
     * @param sessionId sessionId
     */
    void OnSessionClosed(int32_t sessionId);

    /* *
     * Callback adaptation for data received by the session channel.
     *
     * @param sessionId sessionId
     * @param data data received by the session channel
     */
    void OnMessageReceived(int32_t sessionId, const std::string &data);
    void OnBytesReceived(int32_t sessionId, const std::string &data);

private:
    bool isSessionServerRunning_ = false;
    std::recursive_mutex sessionLock_;
    std::vector<std::shared_ptr<SoftbusSessionListener>> sessionListeners_;

    static constexpr const int DEVICE_INFO_MAX_LENGTH = 256;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_SESSION_MANAGER_H
