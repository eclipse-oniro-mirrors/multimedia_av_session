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
#ifndef COLLABORATION_MANAGER_UTILS_H
#define COLLABORATION_MANAGER_UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ServiceCollaborationManagerHardwareType {
    SCM_UNKNOWN_TYPE = 0,
    SCM_DISPLAY = 1,
    SCM_MIC = 2,
    SCM_SPEAKER = 3,
    SCM_CAMERA = 4,
} ServiceCollaborationManagerHardwareType;

typedef enum ServiceCollaborationManagerBussinessStatus {
    SCM_IDLE = 1,
    SCM_PREPARE = 2,
    SCM_CONNECTING = 3,
    SCM_CONNECTED = 4
} ServiceCollaborationManagerBussinessStatus;

typedef enum ServiceCollaborationManagerResultCode {
    PASS = 1004720001,
    REJECT = 1004720002,
    WAIT_SELECT = 1004720003,
    USER_AGREE = 1004720004
} ServiceCollaborationManagerResultCode;

typedef enum ServiceCollaborationManagerCheckConflictType {
    ALL = 0,
    BUSINESS_AND_HARDWARE_CONFLICT = 1,
    ONLY_LINK_CONFLICT = 2 // reservation param, not implementation
} ServiceCollaborationManagerCheckConflictType;

typedef enum ServiceCollaborationManagerRoleType {
    ROLE_UNKNOWN,
    ROLE_GO = 1,
    ROLE_GC = 2,
} ServiceCollaborationManagerRoleType;

typedef enum ServiceCollaborationManagerBusinessType {
    BUSINESS_UNKNOWN = 0,
    BUSINESS_FOREGROUND = 1,
    BUSINESS_BACKGROUND = 2,
} ServiceCollaborationManagerBusinessType;

typedef enum ServiceCollaborationManagerApplyResourceScenario {
    SCENARIO_COMMON = 0,
    SCENARIO_RESOLVE_AFTER_SOFTBUS_LINK_FAILED = 1,
} ServiceCollaborationManagerApplyResourceScenario;

typedef enum ServiceCollaborationManagerSoftbusTriggerType {
    TRIGGER_UNKNOWN = 0,
    TRIGGER_COAP = 1,
    TRIGGER_BLE = 2,
    TRIGGER_ACTION = 3
} ServiceCollaborationManagerSoftbusTriggerType;

typedef enum ServiceCollaborationManagerReuseValue {
    REUSE_DEFAULT = 0,
    REUSE_TRUE = 1,
    REUSE_FALSE = 2,
} ServiceCollaborationManagerReuseValue;

typedef enum ServiceCollaborationManagerLinkType {
    UNKNOWN = 0,
    SOFTBUS_HML_OR_P2P = 1, // create HML by softbus
    SOFTBUS_P2P = 2, // create P2P by softbus
    NATIVE_P2P = 3,
    REUSING_AP = 4, // business reuse ap link
    WLAN = 5,
} ServiceCollaborationManagerLinkType;

typedef struct ServiceCollaborationManager_HardwareRequestInfo {
    ServiceCollaborationManagerHardwareType hardWareType;
    bool canShare;
} ServiceCollaborationManager_HardwareRequestInfo;

typedef struct ServiceCollaborationManager_CommunicationRequestInfo {
    int32_t minBandwidth;
    int32_t maxLatency;
    int32_t minLatency;
    int32_t maxWaitTime;
    const char* dataType;
} ServiceCollaborationManager_CommunicationRequestInfo;

typedef struct ServiceCollaborationManager_ResourceRequestInfoSets {
    uint32_t remoteHardwareListSize;
    ServiceCollaborationManager_HardwareRequestInfo *remoteHardwareList;
    uint32_t localHardwareListSize;
    ServiceCollaborationManager_HardwareRequestInfo *localHardwareList;
    ServiceCollaborationManager_CommunicationRequestInfo *communicationRequest;
    ServiceCollaborationManagerCheckConflictType checkConflictType = ALL;
    ServiceCollaborationManagerLinkType linkType = UNKNOWN;
    ServiceCollaborationManagerRoleType roleTypeForP2P = ROLE_UNKNOWN;
    ServiceCollaborationManagerSoftbusTriggerType softbusTriggerType = TRIGGER_UNKNOWN;
    ServiceCollaborationManagerApplyResourceScenario applyResourceScenario = SCENARIO_COMMON;
    int32_t softbusLinkFailedCode = 0;
    ServiceCollaborationManagerReuseValue canReuseNativeP2pGo = REUSE_DEFAULT;
    ServiceCollaborationManagerReuseValue canReuseSoftbusP2pGo = REUSE_DEFAULT;
    ServiceCollaborationManagerBusinessType businessType = BUSINESS_UNKNOWN;
    int32_t maxActiveTime = -1;
} ServiceCollaborationManager_ResourceRequestInfoSets;

typedef struct ServiceCollaborationManager_ServiceStateInfo {
    const char *peerNetworkId = nullptr;
    const char *serviceName = nullptr;
    const char *extraInfo = nullptr;
    ServiceCollaborationManagerBussinessStatus state = SCM_IDLE;
} ServiceCollaborationManager_ServiceStateInfo;

typedef struct ServiceCollaborationManager_Callback {
    int32_t (*OnStop)(const char* peerNetworkId);
    int32_t (*ApplyResult)(int32_t errorcode, int32_t result, const char* reason);
} ServiceCollaborationManager_Callback;

typedef struct ServiceCollaborationManagerV2_API {
    int32_t (*ServiceCollaborationManager_PublishServiceState)(
        ServiceCollaborationManager_ServiceStateInfo *serviceStateInfo,
        ServiceCollaborationManager_ResourceRequestInfoSets *resourceRequest, int32_t userId);
    int32_t (*ServiceCollaborationManager_ApplyAdvancedResource)(const char* peerNetworkId, const char* serviceName,
        ServiceCollaborationManager_ResourceRequestInfoSets* resourceRequest, int32_t userId,
        ServiceCollaborationManager_Callback* callback);
    int32_t (*ServiceCollaborationManager_RegisterLifecycleCallback)(const char* serviceName,
        ServiceCollaborationManager_Callback* callback);
    int32_t (*ServiceCollaborationManager_UnRegisterLifecycleCallback)(const char* serviceName);
} ServiceCollaborationManagerV2_API;

int32_t ServiceCollaborationManagerV2_Export(ServiceCollaborationManagerV2_API *exportapi);

#ifdef __cplusplus
}
#endif

#endif //COLLABORATION_MANAGER_H