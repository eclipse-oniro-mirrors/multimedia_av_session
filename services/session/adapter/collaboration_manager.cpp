/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "collaboration_manager.h"

namespace OHOS::AVSession {
std::shared_ptr<CollaborationManager> CollaborationManager::instance_;
std::recursive_mutex CollaborationManager::instanceLock_;

CollaborationManager& CollaborationManager::GetInstance()
{
    std::lock_guard lockGuard(instanceLock_);
    if (instance_ != nullptr) {
        return *instance_;
    }
    SLOGI("GetInstance in");
    instance_ = std::make_shared<CollaborationManager>();
    instance_->exportapi_.ServiceCollaborationManager_UnRegisterLifecycleCallback = nullptr;
    instance_->exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback = nullptr;
    instance_->exportapi_.ServiceCollaborationManager_ApplyAdvancedResource = nullptr;
    instance_->exportapi_.ServiceCollaborationManager_PublishServiceState = nullptr;
    return *instance_;
}

void CollaborationManager::ReleaseInstance()
{
    std::lock_guard lockGuard(instanceLock_);
    SLOGI("ReleaseInstance in");
    instance_ = nullptr;
}

CollaborationManager::CollaborationManager()
{
    SLOGI("enter CollaborationManager construct");
    localHardwareList_ = {
        .hardWareType = ServiceCollaborationManagerHardwareType::SCM_UNKNOWN_TYPE,
        .canShare = false
    };
    remoteHardwareList_[0] = {
        .hardWareType = ServiceCollaborationManagerHardwareType::SCM_DISPLAY,
        .canShare = false
    };
    remoteHardwareList_[1] = {
        .hardWareType = ServiceCollaborationManagerHardwareType::SCM_SPEAKER,
        .canShare = false
    };
    communicationRequest_ = {
        .minBandwidth = 80 * 1024 * 1024,
        .maxLatency = 5000,
        .minLatency = 500,
        .maxWaitTime = 60000,
        .dataType = dataType_.c_str()
    };
}

CollaborationManager::~CollaborationManager()
{
    SLOGI("enter ~CollaborationManager");
    delete resourceRequest_;
    resourceRequest_ = nullptr;
}

void CollaborationManager::SendCollaborationOnStop(const std::function<void(void)>& callback)
{
    if (callback == nullptr) {
        SLOGE("SendCollaborationOnStop callback null");
        return;
    }
    sendCollaborationOnStop_ = callback;
}

__attribute__((no_sanitize("cfi")))static int32_t OnStop(const char* peerNetworkId)
{
    SLOGE("enter onstop");
    CHECK_AND_RETURN_RET_LOG(CollaborationManager::GetInstance().sendCollaborationOnStop_ != nullptr,
        AVSESSION_ERROR, "sendCollaborationOnStop_ function ptr is nullptr");
    CollaborationManager::GetInstance().sendCollaborationOnStop_();
    return AVSESSION_SUCCESS;
}

void CollaborationManager::SendCollaborationApplyResult(const std::function<
    void(const int32_t code)>& callback)
{
    if (callback == nullptr) {
        SLOGE("SendCollaborationApplyResult callback null");
        return;
    }
    sendCollaborationApplyResult_ = callback;
}

__attribute__((no_sanitize("cfi")))static int32_t ApplyResult(int32_t errorcode,
    int32_t result, const char* reason)
{
    SLOGI("enter ApplyResult");
    if (result == ServiceCollaborationManagerResultCode::REJECT) {
        SLOGE("return connect reject and reson:%{public}s", reason);
    }
    CHECK_AND_RETURN_RET_LOG(CollaborationManager::GetInstance().sendCollaborationApplyResult_ != nullptr,
        AVSESSION_ERROR, "sendCollaborationApplyResult_ function ptr is nullptr");
    CollaborationManager::GetInstance().sendCollaborationApplyResult_(result);
    return AVSESSION_SUCCESS;
}

static ServiceCollaborationManager_Callback serviceCollaborationCallback {
    .OnStop = OnStop,
    .ApplyResult = ApplyResult
};

__attribute__((no_sanitize("cfi"))) int32_t CollaborationManager::ReadCollaborationManagerSo()
{
    SLOGI("enter ReadCollaborationManagerSo");
    void *collaborationManagerExport = pluginLib_.LoadSymbol("ServiceCollaborationManager_Export");
    if (collaborationManagerExport == nullptr) {
        SLOGE("load libcfwk_allconnect_client.z.so failed");
        return AVSESSION_ERROR;
    }
    collaborationManagerExportFun_ = (reinterpret_cast<CollaborationManagerExportFunType>(
        collaborationManagerExport));
    (*collaborationManagerExportFun_)(&exportapi_);
    return AVSESSION_SUCCESS;
}

int32_t CollaborationManager::RegisterLifecycleCallback()
{
    SLOGI("enter RegisterLifecycleCallback");
    if (exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback == nullptr) {
        SLOGE("RegisterLifecycleCallback function sptr nullptr");
        return AVSESSION_ERROR;
    }
    if (exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback(serviceName_.c_str(),
        &serviceCollaborationCallback)) {
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t CollaborationManager::UnRegisterLifecycleCallback()
{
    SLOGI("enter UnRegisterLifecycleCallback");
    if (exportapi_.ServiceCollaborationManager_UnRegisterLifecycleCallback == nullptr) {
        SLOGE("UnRegisterLifecycleCallback function sptr nullptr");
        return AVSESSION_ERROR;
    }
    if (exportapi_.ServiceCollaborationManager_UnRegisterLifecycleCallback(serviceName_.c_str())) {
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t CollaborationManager::PublishServiceState(const char* peerNetworkId,
    ServiceCollaborationManagerBussinessStatus state)
{
    SLOGI("enter PublishServiceState");
    if (exportapi_.ServiceCollaborationManager_PublishServiceState == nullptr) {
        SLOGE("PublishServiceState function sptr nullptr");
        return AVSESSION_ERROR;
    }
    if (exportapi_.ServiceCollaborationManager_PublishServiceState(peerNetworkId,
        serviceName_.c_str(), "NULL", state)) {
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t CollaborationManager::ApplyAdvancedResource(const char* peerNetworkId)
{
    SLOGI("enter ApplyAdvancedResource");
    if (exportapi_.ServiceCollaborationManager_ApplyAdvancedResource == nullptr) {
        SLOGE("ApplyAdvancedResource function sptr nullptr");
        return AVSESSION_ERROR;
    }
    if (resourceRequest_ == nullptr) {
        SLOGE("resourceRequest_ is nullptr");
        return AVSESSION_ERROR;
    }
    resourceRequest_->localHardwareListSize = localHardwareListSize_;
    resourceRequest_->localHardwareList = &localHardwareList_;
    resourceRequest_->remoteHardwareListSize = remoteHardwareListSize_;
    resourceRequest_->remoteHardwareList = remoteHardwareList_;
    resourceRequest_->communicationRequest = &communicationRequest_;
    if (exportapi_.ServiceCollaborationManager_ApplyAdvancedResource(peerNetworkId,
        serviceName_.c_str(), resourceRequest_, &serviceCollaborationCallback)) {
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}
}   // namespace OHOS::AVSession