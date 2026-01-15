/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_SESSION_MANAGER_DYNAMIC_H
#define SOFTBUS_SESSION_MANAGER_DYNAMIC_H

#include <string>

#ifdef DSOFTBUS_ENABLE
#include "socket.h"
#endif

#include "softbus_session_manager.h"

namespace OHOS::AVSession {
class SoftbusSessionManagerDynamic {
public:
    static SoftbusSessionManagerDynamic& GetInstance();
    ~SoftbusSessionManagerDynamic() = default;

#ifdef DSOFTBUS_ENABLE
    int32_t Socket(const std::string &pkgName);

    int32_t Bind(const std::string &peerNetworkId, const std::string &pkgName);

    void Shutdown(int32_t socket);

    int32_t SendMessage(int32_t socket, const std::string &data);

    int32_t SendBytes(int32_t socket, const std::string &data);

    void RegisterSocketCallback(DynamicSocketCallbackFunc* callbackFunc);
#endif
private:
    static constexpr const int qosCount = 3;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_SESSION_MANAGER_DYNAMIC_H
