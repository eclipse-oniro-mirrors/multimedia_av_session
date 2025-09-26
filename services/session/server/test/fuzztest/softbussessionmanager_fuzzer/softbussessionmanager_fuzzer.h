/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_SOFTBUS_SESSIONMANAGER_FUZZER_H
#define OHOS_SOFTBUS_SESSIONMANAGER_FUZZER_H

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "migrate_avsession_constant.h"
#include "migrate_avsession_server.h"

namespace OHOS::AVSession {
void SoftbusSessionManagerOnRemoteRequest(uint8_t* data, size_t size);

class SoftbusSessionManagerFuzzer {
public:
    SoftbusSessionManagerFuzzer() = default;
    ~SoftbusSessionManagerFuzzer() = default;
    void SoftbusSessionManagerFuzzTest(uint8_t* data, size_t size);
    static void SocketFuzzTest();
    static void BindFuzzTest();
    static void SendMessageFuzzTest();
    static void SendBytesFuzzTest();
    static void SendBytesForNextFuzzTest();
    static void OnBindFuzzTest();
    static void OnShutdownFuzzTest();
    static void OnMessageFuzzTest();
    static void OnBytesFuzzTest();
};
}
#endif