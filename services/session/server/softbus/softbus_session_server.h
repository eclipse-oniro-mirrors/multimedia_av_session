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

#ifndef SOFTBUS_SESSION_SERVER_H
#define SOFTBUS_SESSION_SERVER_H

#include "softbus_session.h"

namespace OHOS::AVSession {
class SoftbusSessionServer : public SoftbusSession {
public:
    void ConnectProxy(int sessionId);
    void DisconnectProxy(int sessionId);
    void DisconnectAllProxy();
    virtual void OnConnectProxy(const std::string &deviceId);
    virtual void OnDisconnectProxy(const std::string &deviceId);
    int32_t GetCharacteristic() override;
    void OnBytesReceived(const std::string &deviceId, const std::string &data) override;

    ~SoftbusSessionServer() override;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_SESSION_SERVER_H
