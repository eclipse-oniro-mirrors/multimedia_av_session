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
#include "avsession_descriptor.h"
#include "avsession_info.h"

#include <string>

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

bool CollaborationManager::IsHiPlayDevice(const DeviceInfo& deviceInfo)
{
    return deviceInfo.supportedProtocols_ == ProtocolType::TYPE_CAST_PLUS_AUDIO;
}

bool CollaborationManager::IsHiPlayP2PDevice(const DeviceInfo& deviceInfo)
{
    return IsHiPlayDevice(deviceInfo) && deviceInfo.ipAddress_.empty();
}

int32_t CollaborationManager::ApplyAdvancedResource(const char* peerNetworkId, const DeviceInfo& deviceInfo,
    bool checkLinkConflict)
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
    resourceRequest_->checkConflictType = checkLinkConflict ? ServiceCollaborationManagerCheckConflictType::ALL :
        ServiceCollaborationManagerCheckConflictType::BUSINESS_AND_HARDWARE_CONFLICT;
    if (IsHiPlayP2PDevice(deviceInfo)) {
        resourceRequest_->linkType = ServiceCollaborationManagerLinkType::NATIVE_P2P;
    }
    if (exportapi_.ServiceCollaborationManager_ApplyAdvancedResource(peerNetworkId,
        serviceName_.c_str(), resourceRequest_, &serviceCollaborationCallback)) {
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t CollaborationManager::CastAddToCollaboration(const DeviceInfo& deviceInfo)
{
    SLOGI("enter CastAddToCollaboration");
    ListenCollaborationApplyResult();
    CHECK_AND_RETURN_RET_LOG(deviceInfo.deviceId_ != "", AVSESSION_ERROR, "deviceid is empty");
    SLOGI("supportedProtocols is %{public}d", deviceInfo.supportedProtocols_);
    bool checkLinkConflict = deviceInfo.supportedProtocols_ != ProtocolType::TYPE_DLNA;
    ApplyAdvancedResource(deviceInfo.deviceId_.c_str(), deviceInfo, checkLinkConflict);
    //wait collaboration callback 10s
    std::unique_lock <std::mutex> applyResultLock(collaborationApplyResultMutex_);
    bool flag = connectWaitCallbackCond_.wait_for(applyResultLock, std::chrono::seconds(collaborationCallbackTimeOut_),
        [this]() {
            return applyResultFlag_;
    });
    //wait user decision collaboration callback 60s
    if (waitUserDecisionFlag_) {
        flag = connectWaitCallbackCond_.wait_for(applyResultLock,
            std::chrono::seconds(collaborationUserCallbackTimeOut_),
        [this]() {
            return applyUserResultFlag_;
        });
    }
    applyResultFlag_ = false;
    applyUserResultFlag_ = false;
    waitUserDecisionFlag_ = false;
    CHECK_AND_RETURN_RET_LOG(flag, ERR_WAIT_ALLCONNECT_TIMEOUT, "collaboration callback timeout");
    if (collaborationRejectFlag_) {
        collaborationRejectFlag_ = false;
        SLOGE("collaboration callback reject");
        return ERR_ALLCONNECT_CAST_REJECT;
    }
    return AVSESSION_SUCCESS;
}

void CollaborationManager::ListenCollaborationApplyResult()
{
    SLOGI("enter ListenCollaborationApplyResult");
    SendCollaborationApplyResult([this](const int32_t code) {
        std::unique_lock <std::mutex> applyResultLock(collaborationApplyResultMutex_);
        if (code == ServiceCollaborationManagerResultCode::PASS) {
            SLOGI("ApplyResult can cast");
            applyResultFlag_ = true;
            applyUserResultFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::REJECT) {
            SLOGI("ApplyResult can not cast");
            collaborationRejectFlag_ = true;
            applyResultFlag_ = true;
            applyUserResultFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::USERTIP) {
            SLOGI("ApplyResult user tip");
            applyResultFlag_ = true;
            waitUserDecisionFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::USERAGREE) {
            SLOGI("ApplyResult user agree cast");
        }
    });
}
}   // namespace OHOS::AVSession