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

#ifndef OHOS_AVSESSION_PROXY_H
#define OHOS_AVSESSION_PROXY_H

#include "softbus/softbus_session_proxy.h"

namespace OHOS::AVSession {
class MigrateAVSessionProxy : public SoftbusSessionProxy,
    public std::enable_shared_from_this<MigrateAVSessionProxy> {
public:
    explicit MigrateAVSessionProxy(int32_t mode) { mMode_ = mode; }
    ~MigrateAVSessionProxy() {}

    void OnConnectServer(const std::string &deviceId) override;
    void OnDisconnectServer(const std::string &deviceId) override;
    int32_t GetCharacteristic() override;
    void OnBytesReceived(const std::string &deviceId, const std::string &data) override;

private:
    int32_t mMode_;
};
} // namespace OHOS::AVSession

#endif //OHOS_AVSESSION_PROXY_H