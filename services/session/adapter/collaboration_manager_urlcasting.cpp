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

#include "collaboration_manager_urlcasting.h"

namespace OHOS::AVSession {
std::shared_ptr<CollaborationManagerURLCasting> CollaborationManagerURLCasting::instance_;
std::recursive_mutex CollaborationManagerURLCasting::instanceLock_;

__attribute__((no_sanitize("cfi")))static int32_t OnStopUrlCasting(const char* peerNetworkId)
{
    SLOGE("enter OnStopUrlCasting");
    CHECK_AND_RETURN_RET_LOG(CollaborationManagerURLCasting::GetInstance().sendCollaborationOnStop_ != nullptr,
        AVSESSION_ERROR, "sendCollaborationOnStop_ function ptr is nullptr");
    CollaborationManagerURLCasting::GetInstance().sendCollaborationOnStop_();
    return AVSESSION_SUCCESS;
}

__attribute__((no_sanitize("cfi")))static int32_t ApplyResultUrlCasting(int32_t errorcode,
    int32_t result, const char* reason)
{
    SLOGI("enter ApplyResultUrlCasting");
    if (result == ServiceCollaborationManagerResultCode::REJECT) {
        SLOGE("return connect reject and reson:%{public}s", reason);
    }
    CHECK_AND_RETURN_RET_LOG(CollaborationManagerURLCasting::GetInstance().sendCollaborationApplyResult_ != nullptr,
        AVSESSION_ERROR, "sendCollaborationApplyResult_ function ptr is nullptr");
    CollaborationManagerURLCasting::GetInstance().sendCollaborationApplyResult_(result);
    return AVSESSION_SUCCESS;
}

static ServiceCollaborationManager_Callback serviceCollaborationUrlCastingCallback {
    .OnStop = OnStopUrlCasting,
    .ApplyResult = ApplyResultUrlCasting
};

CollaborationManagerURLCasting& CollaborationManagerURLCasting::GetInstance()
{
    std::lock_guard lockGuard(instanceLock_);
    if (instance_ != nullptr) {
        return *instance_;
    }
    SLOGI("CollaborationManagerURLCasting GetInstance in");
    instance_ = std::make_shared<CollaborationManagerURLCasting>();
    return *instance_;
}

void CollaborationManagerURLCasting::ReleaseInstance()
{
    std::lock_guard lockGuard(instanceLock_);
    SLOGI("CollaborationManagerURLCasting ReleaseInstance in");
    instance_ = nullptr;
}

CollaborationManagerURLCasting::CollaborationManagerURLCasting()
{
    serviceName_ = "URLCasting";
    serviceCollaborationCallback_ = serviceCollaborationUrlCastingCallback;
}
}   // namespace OHOS::AVSession