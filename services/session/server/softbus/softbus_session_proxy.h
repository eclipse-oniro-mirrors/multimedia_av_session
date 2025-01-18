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

#ifndef SOFTBUS_SESSION_PROXY_H
#define SOFTBUS_SESSION_PROXY_H

#include "softbus_session.h"

namespace OHOS::AVSession {
class SoftbusSessionProxy : public SoftbusSession {
public:
    void ConnectServer(int socketId);
    void DisconnectServer(int socketId);
    virtual void OnConnectServer(const std::string &deviceId);
    virtual void OnDisconnectServer(const std::string &deviceId);
    int32_t GetCharacteristic() override;
    void OnBytesReceived(const std::string &deviceId, const std::string &data) override;
    ~SoftbusSessionProxy() override;
};

} // namespace OHOS::AVSession
#endif //SOFTBUS_SESSION_PROXY_H