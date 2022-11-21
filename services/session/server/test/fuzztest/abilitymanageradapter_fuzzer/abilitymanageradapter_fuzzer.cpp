/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <chrono>
#include <condition_variable>
#include "ability_manager_adapter.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "ability_connect_helper.h"
#include "abilitymanageradapter_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_LEN = 512;
const int32_t MIN_SIZE_NUM = 4;

void OHOS::AVSession::AbilityManagerAdapterTest(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    std::string bundleName(reinterpret_cast<const char *>(data), size);
    std::string abilityName(reinterpret_cast<const char *>(data), size);

    std::string sessionId(reinterpret_cast<const char *>(data), size);

    AbilityManagerAdapter abilityManagerAdapter(bundleName, abilityName);

    abilityManagerAdapter.StartAbilityByCall(sessionId);
    abilityManagerAdapter.StartAbilityByCallDone(sessionId);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AbilityManagerAdapterTest(const_cast<uint8_t*>(data), size);
    return 0;
}