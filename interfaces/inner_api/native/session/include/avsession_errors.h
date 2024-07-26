/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_ERRORS_H
#define OHOS_AVSESSION_ERRORS_H

#include <cinttypes>

#include "errors.h"

namespace OHOS::AVSession {
constexpr int32_t  AVSESSION_ERROR = -1;
constexpr int32_t  AVSESSION_SUCCESS = 0;
constexpr int32_t  AVSESSION_ERROR_BASE = 1000;

constexpr int32_t  ERR_NO_MEMORY = -(AVSESSION_ERROR_BASE + 1);
constexpr int32_t  ERR_INVALID_PARAM = -(AVSESSION_ERROR_BASE + 2);
constexpr int32_t  ERR_SERVICE_NOT_EXIST = -(AVSESSION_ERROR_BASE + 3);
constexpr int32_t  ERR_SESSION_LISTENER_EXIST = -(AVSESSION_ERROR_BASE + 4);
constexpr int32_t  ERR_MARSHALLING = -(AVSESSION_ERROR_BASE + 5);
constexpr int32_t  ERR_UNMARSHALLING = -(AVSESSION_ERROR_BASE + 6);
constexpr int32_t  ERR_IPC_SEND_REQUEST = -(AVSESSION_ERROR_BASE + 7);
constexpr int32_t  ERR_SESSION_EXCEED_MAX = -(AVSESSION_ERROR_BASE + 8);
constexpr int32_t  ERR_SESSION_NOT_EXIST = -(AVSESSION_ERROR_BASE + 9);
constexpr int32_t  ERR_COMMAND_NOT_SUPPORT = -(AVSESSION_ERROR_BASE + 10);
constexpr int32_t  ERR_CONTROLLER_NOT_EXIST = -(AVSESSION_ERROR_BASE + 11);
constexpr int32_t  ERR_NO_PERMISSION = -(AVSESSION_ERROR_BASE + 12);
constexpr int32_t  ERR_SESSION_DEACTIVE = -(AVSESSION_ERROR_BASE + 13);
constexpr int32_t  ERR_CONTROLLER_IS_EXIST = -(AVSESSION_ERROR_BASE + 14);
constexpr int32_t  ERR_START_ABILITY_IS_RUNNING = -(AVSESSION_ERROR_BASE + 15);
constexpr int32_t  ERR_ABILITY_NOT_AVAILABLE = -(AVSESSION_ERROR_BASE + 16);
constexpr int32_t  ERR_START_ABILITY_TIMEOUT = -(AVSESSION_ERROR_BASE + 17);
constexpr int32_t  ERR_COMMAND_SEND_EXCEED_MAX = -(AVSESSION_ERROR_BASE + 18);
constexpr int32_t  ERR_RPC_SEND_REQUEST = -(AVSESSION_ERROR_BASE + 19);
constexpr int32_t  ERR_DEVICE_CONNECTION_FAILED = -(AVSESSION_ERROR_BASE + 20);
constexpr int32_t  ERR_REMOTE_CONNECTION_NOT_EXIST = -(AVSESSION_ERROR_BASE + 21);
constexpr int32_t  ERR_SESSION_IS_EXIST = -(AVSESSION_ERROR_BASE + 22);
constexpr int32_t  ERR_WAIT_ALLCONNECT_TIMEOUT = -(AVSESSION_ERROR_BASE + 23);
constexpr int32_t  ERR_ALLCONNECT_CAST_REJECT = -(AVSESSION_ERROR_BASE + 24);
constexpr int32_t  ERR_ALLCONNECT_PREEMPTED_BY_OTHERS = -(AVSESSION_ERROR_BASE + 25);
}  // namespace OHOS::AVSession

#endif  // OHOS_AVSESSION_ERRORS_H
