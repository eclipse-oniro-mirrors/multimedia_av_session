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

#ifndef SOFTBUS_SESSION_H
#define SOFTBUS_SESSION_H

#include <map>
#include <mutex>
#include <string>

namespace OHOS::AVSession {
class SoftbusSession {
public:
    void OnConnectSession(int32_t sessionId);
    void OnDisConnectSession(int32_t sessionId);
    void SendByteToAll(const std::string &data);
    void SendByte(const std::string &deviceId, const std::string &data);
    void SendByte(int32_t sessionId, const std::string &data);
    void SendMessage(const std::string &deviceId, const std::string &data);
    void SendMessage(int32_t sessionId, const std::string &data);
    virtual int32_t GetCharacteristic() = 0;
    virtual void OnBytesReceived(const std::string &deviceId, const std::string &data) = 0;
    virtual ~SoftbusSession() = default;

protected:
    std::map<std::string, int32_t> deviceToSessionMap_;
    std::recursive_mutex deviceMapLock_;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_SESSION_H
