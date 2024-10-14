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

#ifndef ABILITY_MANAGER_ADAPTER_H
#define ABILITY_MANAGER_ADAPTER_H

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>

namespace OHOS::AVSession {
enum class Status {
    ABILITY_STATUS_INIT = 0,
    ABILITY_STATUS_RUNNING = 1,
    ABILITY_STATUS_FAILED = 2,
    ABILITY_STATUS_SUCCESS = 3,
};

class AbilityManagerAdapter {
public:
    AbilityManagerAdapter(const std::string& bundleName, const std::string& abilityName);
    ~AbilityManagerAdapter();

    __attribute__((no_sanitize("cfi"))) int32_t StartAbilityByCall(std::string& sessionId);

    void StartAbilityByCallDone(const std::string& sessionId);

private:
    void WaitForTimeout(uint32_t timeout);

private:
    static constexpr int32_t ABILITY_START_TIMEOUT_MS = 5000;
    static constexpr const char *DEFAULT_BUNDLE_NAME = "com.example.himusicdemo";
    std::condition_variable syncCon_;
    std::mutex syncMutex_;
    Status status_ = Status::ABILITY_STATUS_INIT;
    std::string bundleName_;
    std::string abilityName_;
    std::string sessionId_;
};
} // namespace OHOS::AVSession
#endif // ABILITY_MANAGER_ADAPTER_H