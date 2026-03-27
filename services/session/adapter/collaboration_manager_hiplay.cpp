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

#include "collaboration_manager_hiplay.h"

namespace OHOS::AVSession {
std::shared_ptr<CollaborationManagerHiPlay> CollaborationManagerHiPlay::instance_;
std::recursive_mutex CollaborationManagerHiPlay::instanceLock_;

__attribute__((no_sanitize("cfi")))static int32_t OnStopHiPlay(const char* peerNetworkId)
{
    SLOGE("enter OnStopHiPlay");
    CHECK_AND_RETURN_RET_LOG(CollaborationManagerHiPlay::GetInstance().sendCollaborationOnStop_ != nullptr,
        AVSESSION_ERROR, "sendCollaborationOnStop_ function ptr is nullptr");
    CollaborationManagerHiPlay::GetInstance().sendCollaborationOnStop_();
    return AVSESSION_SUCCESS;
}

__attribute__((no_sanitize("cfi")))static int32_t ApplyResultHiPlay(int32_t errorcode,
    int32_t result, const char* reason)
{
    SLOGI("enter ApplyResultHiPlay");
    if (result == ServiceCollaborationManagerResultCode::REJECT) {
        SLOGE("return connect reject and reson:%{public}s", reason);
    }
    CHECK_AND_RETURN_RET_LOG(CollaborationManagerHiPlay::GetInstance().sendCollaborationApplyResult_ != nullptr,
        AVSESSION_ERROR, "sendCollaborationApplyResult_ function ptr is nullptr");
    CollaborationManagerHiPlay::GetInstance().sendCollaborationApplyResult_(result);
    return AVSESSION_SUCCESS;
}

static ServiceCollaborationManager_Callback serviceCollaborationHiPlayCallback {
    .OnStop = OnStopHiPlay,
    .ApplyResult = ApplyResultHiPlay
};

CollaborationManagerHiPlay& CollaborationManagerHiPlay::GetInstance()
{
    std::lock_guard lockGuard(instanceLock_);
    if (instance_ != nullptr) {
        return *instance_;
    }
    SLOGI("CollaborationManagerHiPlay GetInstance in");
    instance_ = std::make_shared<CollaborationManagerHiPlay>();
    return *instance_;
}

void CollaborationManagerHiPlay::ReleaseInstance()
{
    std::lock_guard lockGuard(instanceLock_);
    SLOGI("CollaborationManagerHiPlay ReleaseInstance in");
    instance_ = nullptr;
}

CollaborationManagerHiPlay::CollaborationManagerHiPlay()
{
    SLOGI("CollaborationManagerHiPlay in");
    serviceName_ = "HUAWEIHiPlay-Dual";
    serviceCollaborationCallback_ = serviceCollaborationHiPlayCallback;
}

bool CollaborationManagerHiPlay::IsHiPlayDevice(const DeviceInfo& deviceInfo)
{
    return deviceInfo.supportedProtocols_ == ProtocolType::TYPE_CAST_PLUS_AUDIO;
}

bool CollaborationManagerHiPlay::IsHiPlayP2PDevice(const DeviceInfo& deviceInfo)
{
    return IsHiPlayDevice(deviceInfo) && deviceInfo.ipAddress_.empty();
}

void CollaborationManagerHiPlay::UpdataLinkType(const DeviceInfo& deviceInfo)
{
    resourceRequest_->linkType = ServiceCollaborationManagerLinkType::UNKNOWN;

    if (IsHiPlayDevice(deviceInfo)) {
        resourceRequest_->linkType = ServiceCollaborationManagerLinkType::WLAN;
        if (IsHiPlayP2PDevice(deviceInfo)) {
            resourceRequest_->linkType = ServiceCollaborationManagerLinkType::NATIVE_P2P;
        }
    }
}
}   // namespace OHOS::AVSession