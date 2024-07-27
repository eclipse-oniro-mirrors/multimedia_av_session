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

#include <string>
#include "avsession_log.h"
#include "avsession_errors.h"
#include "collaboration_manager_utils.h"
#include "plugin_lib.h"

namespace OHOS::AVSession {
class CollaborationManager {
public:
    static CollaborationManager& GetInstance();
    virtual ~CollaborationManager();
    void SendRejectStateToStopCast(const std::function<void(const std::string callbackName,
        bool flag)>& callback);
    int64_t ReadCollaborationManagerSo();
    int64_t RegisterLifecycleCallback();
    int64_t UnRegisterLifecycleCallback();
    int64_t PublishServiceState(const char* peerNetworkId, ServiceCollaborationManagerBussinessStatus state);
    int32_t ApplyAdvancedResource(const char* peerNetworkId);

    std::function<void(const std::string callbackName, bool flag)> sendRejectStateToStopCast_;

private:
    ServiceCollaborationManager_HardwareRequestInfo localHardwareList_ = {
    .hardWareType = ServiceCollaborationManagerHardwareType::SCM_UNKNOWN_TYPE,
    .canShare = false
    };
    ServiceCollaborationManager_HardwareRequestInfo remoteHardwareList_[2] = {
    {
        .hardWareType = ServiceCollaborationManagerHardwareType::SCM_DISPLAY,
        .canShare = false
    },
    {
        .hardWareType = ServiceCollaborationManagerHardwareType::SCM_SPEAKER,
        .canShare = false
    }
    };
    ServiceCollaborationManager_CommunicationRequestInfo communicationRequest_ = {
        .minBandwidth = 80 * 1024 * 1024,
        .maxLatency = 5000,
        .minLatency = 500,
        .maxWaitTime = 60000,
        .dataType = dataType_.c_str()
    };
    const int32_t remoteHardwareListSize_ = 2;
    const int32_t localHardwareListSize_ = 0;
    const std::string serviceName_ = "URLCasting";
    constexpr std::string dataType_ = "DATA_TYPE_BYTES";
    PluginLib pluginLib_ {"/system/lib64/libcfwk_allconnect_client.z.so"};
    ServiceCollaborationManager_ResourceRequestInfoSets *resourceRequest_ =
        new ServiceCollaborationManager_ResourceRequestInfoSets();
    ServiceCollaborationManager_API exportapi_;

    using CollaborationManagerExportFunType = int32_t (*)(ServiceCollaborationManager_API *exportapi);
    CollaborationManagerExportFunType collaborationManagerExportFun_;
};
}   // namespace OHOS::AVSession
#endif //COLLABORATION_MANAGER_H