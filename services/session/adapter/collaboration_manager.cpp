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
CollaborationManager& CollaborationManager::GetInstance()
{
    static CollaborationManager collaborationManager;
    return collaborationManager;
}

CollaborationManager::~CollaborationManager()
{
    SLOGI("enter ~CollaborationManager");
    delete resourceRequest_;
    resourceRequest_ = nullptr;
}

void CollaborationManager::SendRejectStateToStopCast(const std::function<
    void(const std::string callbackName, bool flag)>& callback)
{
    sendRejectStateToStopCast_ = callback;
}

static int32_t OnStop(const char* peerNetworkId)
{
    CollaborationManager::GetInstance().SendRejectStateToStopCast("OnStop", true);
    return ERR_ALLCONNECT_PREEMPTED_BY_OTHERS;
}

__attribute__((no_sanitize("cfi")))static int32_t ApplyResult(int32_t errorcode,
    int32_t result, const char* reason)
{
    if (result == ServiceCollaborationManagerResultCode::PASS) {
        SLOGI("return can connect");
        CollaborationManager::GetInstance().SendRejectStateToStopCast("ApplyResult", false);
        return AVSESSION_SUCCESS;
    } else if (result == ServiceCollaborationManagerResultCode::REJECT) {
        SLOGE("return connect reject and reson:%{public}s", reason);
        CollaborationManager::GetInstance().SendRejectStateToStopCast("ApplyResult", true);
        return ERR_ALLCONNECT_CAST_REJECT;
    } else {
        SLOGE("unexpect return reslut value");
        CollaborationManager::GetInstance().SendRejectStateToStopCast("ApplyResult", false);
        return AVSESSION_SUCCESS;
    }
}

static ServiceCollaborationManager_Callback serviceCollaborationCallback {
    .OnStop = OnStop,
    .ApplyResult = ApplyResult
};

__attribute__((no_sanitize("cfi"))) int64_t CollaborationManager::ReadCollaborationManagerSo()
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

int64_t CollaborationManager::RegisterLifecycleCallback()
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

int64_t CollaborationManager::UnRegisterLifecycleCallback()
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

int64_t CollaborationManager::PublishServiceState(const char* peerNetworkId,
    ServiceCollaborationManagerBussinessStatus state)
{
    SLOGI("enter PublishServiceState");
    if (exportapi_.ServiceCollaborationManager_PublishServiceState == nullptr) {
        SLOGE("PublishServiceState function sptr nullptr");
        return AVSESSION_ERROR;
    }
    if (exportapi_.ServiceCollaborationManager_PublishServiceState(peerNetworkId, serviceName_.c_str(), "NULL", state)) {
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t CollaborationManager::ApplyAdvancedResource(const char* peerNetworkId)
{
    SLOGI("enter ApplyAdvancedResource");
    ServiceCollaborationManager_HardwareRequestInfo localHardwareList = {
    .hardWareType = ServiceCollaborationManagerHardwareType::SCM_UNKNOWN_TYPE,
    .canShare = false
    };
    ServiceCollaborationManager_HardwareRequestInfo remoteHardwareList[2] = {
    {
        .hardWareType = ServiceCollaborationManagerHardwareType::SCM_DISPLAY,
        .canShare = false
    },
    {
        .hardWareType = ServiceCollaborationManagerHardwareType::SCM_SPEAKER,
        .canShare = false
    }
    };
    ServiceCollaborationManager_CommunicationRequestInfo communicationRequest = {
        .minBandwidth = 80 * 1024 * 1024,
        .maxLatency = 5000,
        .minLatency = 500,
        .maxWaitTime = 60000,
        .dataType = dataType_.c_str()
    };
    resourceRequest_->localHardwareListSize = localHardwareListSize_;
    resourceRequest_->localHardwareList = &localHardwareList;
    resourceRequest_->remoteHardwareListSize = remoteHardwareListSize_;
    resourceRequest_->remoteHardwareList = remoteHardwareList;
    resourceRequest_->communicationRequest = &communicationRequest;
    if (exportapi_.ServiceCollaborationManager_ApplyAdvancedResource == nullptr) {
        SLOGE("ApplyAdvancedResource function sptr nullptr");
        return AVSESSION_ERROR;
    }
    if (exportapi_.ServiceCollaborationManager_ApplyAdvancedResource(peerNetworkId,
        serviceName_.c_str(), resourceRequest_, &serviceCollaborationCallback)) {
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}
}   // namespace OHOS::AVSession