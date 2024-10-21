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

#include "avsession_dynamic_loader.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "bundle_status_adapter.h"
#include "ability_connect_helper.h"

namespace OHOS::AVSession {
static const std::string AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH = std::string("libavsession_dynamic_insight.z.so");

AbilityManagerAdapter::AbilityManagerAdapter(const std::string& bundleName, const std::string& abilityName)
{
    SLOGI("construct bundleName=%{public}s abilityName=%{public}s", bundleName.c_str(), abilityName.c_str());
    bundleName_ = bundleName;
    abilityName_ = abilityName;
}

AbilityManagerAdapter::~AbilityManagerAdapter()
{}

__attribute__((no_sanitize("cfi"))) int32_t AbilityManagerAdapter::StartAbilityByCall(std::string& sessionId)
{
    std::unique_lock<std::recursive_mutex> lock(syncMutex_);
    if (status_ != Status::ABILITY_STATUS_INIT) {
        SLOGE("Start Ability is running");
        return ERR_START_ABILITY_IS_RUNNING;
    }
    status_ = Status::ABILITY_STATUS_RUNNING;
    int32_t ret = AVSESSION_ERROR;
    bool isSupport = false;

    std::unique_ptr<AVSessionDynamicLoader> dynamicLoader = std::make_unique<AVSessionDynamicLoader>();
    typedef bool (*IsSupportPlayIntentFunc)(const std::string& bundleName, const std::string& assetId);
    IsSupportPlayIntentFunc isSupportPlayIntent =
        reinterpret_cast<IsSupportPlayIntentFunc>(dynamicLoader->GetFuntion(
            AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, "IsSupportPlayIntent"));
    if (isSupportPlayIntent) {
        isSupport = (*isSupportPlayIntent)(bundleName_, "");
    }

    if (isSupport) {
        SLOGI("Start Ability mediaintent");
        typedef int32_t (*StartAVPlaybackFunc)(const std::string& bundleName, const std::string& assetId);
        StartAVPlaybackFunc startAVPlayback =
            reinterpret_cast<StartAVPlaybackFunc>(dynamicLoader->GetFuntion(
                AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, "StartAVPlayback"));
        if (startAVPlayback) {
            ret = (*startAVPlayback)(bundleName_, "");
        }
    } else {
        ret = AbilityConnectHelper::GetInstance().StartAbilityByCall(bundleName_, abilityName_);
    }
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

void AbilityManagerAdapter::StartAbilityByCallDone(const std::string& sessionId)
{
    if (status_ != Status::ABILITY_STATUS_RUNNING) {
        SLOGI("no need to notify");
        return;
    }
    sessionId_ = sessionId;
    syncCon_.notify_one();
}

// LCOV_EXCL_START
void AbilityManagerAdapter::WaitForTimeout(uint32_t timeout)
{
    std::unique_lock<std::recursive_mutex> lock(syncMutex_);
    auto waitStatus = syncCon_.wait_for(lock, std::chrono::milliseconds(timeout));
    if (waitStatus == std::cv_status::timeout) {
        SLOGE("StartAbilityByCall timeout");
        status_ = Status::ABILITY_STATUS_FAILED;
        return;
    }
    status_ = Status::ABILITY_STATUS_SUCCESS;
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
