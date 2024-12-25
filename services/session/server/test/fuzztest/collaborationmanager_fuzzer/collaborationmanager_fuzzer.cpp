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

#include <cstddef>
#include <cstdint>
#include <string>

#include "ipc_skeleton.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_log.h"
#include "audio_info.h"
#include "collaborationmanager_fuzzer.h"
#include "collaboration_manager.h"
#include "securec.h"

using namespace std;
namespace OHOS::AVSession {
static const int32_t MAX_CODE_LEN  = 512;
static const int32_t MIN_SIZE_NUM = 4;

static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

void CollaborationManagerFuzzer::CollaborationManagerFuzzTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    CollaborationManager::GetInstance().RegisterLifecycleCallback();

    auto registerLifecycleCallback1 = [](const char* serviceName, ServiceCollaborationManager_Callback* callback) {
        return static_cast<int32_t>(0);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback
        = registerLifecycleCallback1;
    CollaborationManager::GetInstance().RegisterLifecycleCallback();

    auto registerLifecycleCallback2 = [](const char* serviceName, ServiceCollaborationManager_Callback* callback) {
        return static_cast<int32_t>(1);
    };
    CollaborationManager::GetInstance().exportapi_.ServiceCollaborationManager_RegisterLifecycleCallback
        = registerLifecycleCallback2;
    CollaborationManager::GetInstance().RegisterLifecycleCallback();
    CollaborationManager collaborationManager;
    collaborationManager.ReadCollaborationManagerSo();
    std::string peerNetworkId = std::to_string(GetData<uint8_t>());
    vector<ServiceCollaborationManagerBussinessStatus> states;
    states.push_back(ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
    states.push_back(ServiceCollaborationManagerBussinessStatus::SCM_PREPARE);
    states.push_back(ServiceCollaborationManagerBussinessStatus::SCM_CONNECTING);
    states.push_back(ServiceCollaborationManagerBussinessStatus::SCM_CONNECTED);
    collaborationManager.PublishServiceState(peerNetworkId.c_str(), states[GetData<uint8_t>() % states.size()]);
    collaborationManager.ApplyAdvancedResource(peerNetworkId.c_str());
}

void CollaborationManagerRemoteRequest(uint8_t* data, size_t size)
{
    auto collaborationManager = std::make_unique<CollaborationManagerFuzzer>();
    if (collaborationManager == nullptr) {
        SLOGI("collaborationManager is null");
        return;
    }
    collaborationManager->CollaborationManagerFuzzTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    CollaborationManagerRemoteRequest(data, size);
    return 0;
}
}