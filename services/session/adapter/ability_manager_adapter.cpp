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

#include "ability_manager_adapter.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "ability_connect_helper.h"

namespace OHOS::AVSession {
AbilityManagerAdapter::AbilityManagerAdapter(const std::string bundleName, const std::string abilityName)
{
    SLOGI("construct bundleName=%{public}s abilityName=%{public}s", bundleName.c_str(), abilityName.c_str());
    bundleName_ = bundleName;
    abilityName_ = abilityName;
}

AbilityManagerAdapter::~AbilityManagerAdapter()
{}

int32_t AbilityManagerAdapter::StartAbilityByCall(std::string &sessionId)
{
    if (status_ != Status::ABILITY_STATUS_INIT) {
        SLOGE("Start Ability is running");
        return ERR_START_ABILITY_IS_RUNNING;
    }
    status_ = Status::ABILITY_STATUS_RUNNING;
    int32_t ret = AbilityConnectHelper::GetInstance().StartAbilityByCall(bundleName_, abilityName_);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("Start Ability failed: %{public}d", ret);
        status_ = Status::ABILITY_STATUS_INIT;
        return ret;
    }

    WaitForTimeout(ABILITY_START_TIMEOUT_MS);
    ret = ERR_START_ABILITY_TIMEOUT;
    if (status_ == Status::ABILITY_STATUS_SUCCESS) {
        ret = AVSESSION_SUCCESS;
        sessionId = sessionId_;
    }
    status_ = Status::ABILITY_STATUS_INIT;
    return ret;
}

void AbilityManagerAdapter::StartAbilityByCallDone(const std::string sessionId)
{
    if (status_ != Status::ABILITY_STATUS_RUNNING) {
        SLOGI("no need to notify");
        return;
    }
    syncCon_.notify_one();
    sessionId_ = sessionId;
}

void AbilityManagerAdapter::WaitForTimeout(uint32_t timeout)
{
    std::unique_lock<std::mutex> lock(syncMutex_);
    auto waitStatus = syncCon_.wait_for(lock, std::chrono::milliseconds(timeout));
    if (waitStatus == std::cv_status::timeout) {
        SLOGE("StartAbilityByCall timeout");
        status_ = Status::ABILITY_STATUS_FAILED;
        return;
    }
    status_ = Status::ABILITY_STATUS_SUCCESS;
}
} // namespace OHOS::AVSession