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

#ifndef COLLABORATION_MANAGER_H
#define COLLABORATION_MANAGER_H

#include <mutex>
#include <string>
#include "avsession_log.h"
#include "avsession_errors.h"
#include "collaboration_manager_utils.h"
#include "plugin_lib.h"

namespace OHOS::AVSession {
class CollaborationManager {
public:
    static CollaborationManager& GetInstance();
    static void ReleaseInstance();
    CollaborationManager();
    virtual ~CollaborationManager();
    void SendCollaborationApplyResult(const std::function<void(const int32_t code)>& callback);
    void SendCollaborationOnStop(const std::function<void(void)>& callback);
    int32_t ReadCollaborationManagerSo();
    int32_t RegisterLifecycleCallback();
    int32_t UnRegisterLifecycleCallback();
    int32_t PublishServiceState(const char* peerNetworkId, ServiceCollaborationManagerBussinessStatus state);
    int32_t ApplyAdvancedResource(const char* peerNetworkId);

    std::function<void(const int32_t code)> sendCollaborationApplyResult_;
    std::function<void(void)> sendCollaborationOnStop_;

private:
    static std::shared_ptr<CollaborationManager> instance_;
    static std::recursive_mutex instanceLock_;
    const int32_t remoteHardwareListSize_ = 2;
    const int32_t localHardwareListSize_ = 0;
    const std::string serviceName_ = "URLCasting";
    const std::string dataType_ = "DATA_TYPE_BYTES";
    PluginLib pluginLib_ {"/system/lib64/libcfwk_allconnect_client.z.so"};
    ServiceCollaborationManager_ResourceRequestInfoSets *resourceRequest_ =
        new ServiceCollaborationManager_ResourceRequestInfoSets();
    ServiceCollaborationManager_API exportapi_;

    using CollaborationManagerExportFunType = int32_t (*)(ServiceCollaborationManager_API *exportapi);
    CollaborationManagerExportFunType collaborationManagerExportFun_;
    ServiceCollaborationManager_HardwareRequestInfo localHardwareList_;
    ServiceCollaborationManager_HardwareRequestInfo remoteHardwareList_[2];
    ServiceCollaborationManager_CommunicationRequestInfo communicationRequest_;
};
}   // namespace OHOS::AVSession
#endif //COLLABORATION_MANAGER_H