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

#include "ipc_skeleton.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_log.h"
#include "audio_info.h"
#include "collaborationmanager_fuzzer.h"
#include "collaboration_manager.h"

using namespace std;
namespace OHOS::AVSession {
static const int32_t MAX_CODE_LEN  = 512;
static const int32_t MIN_SIZE_NUM = 4;
static const int32_t MAX_CODE_TEST = 24;

void CollaborationManagerFuzzer::CollaborationManagerFuzzTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
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

    const char* peerNetworkId = reinterpret_cast<const char*>(data);
    CollaborationManager collaborationManager;
    collaborationManager.ReadCollaborationManagerSo();
    ServiceCollaborationManagerBussinessStatus state = ServiceCollaborationManagerBussinessStatus::SCM_IDLE;
    collaborationManager.PublishServiceState(peerNetworkId, state);
    collaborationManager.ApplyAdvancedResource(peerNetworkId);
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
    /* Run your code on data */
    CollaborationManagerRemoteRequest(data, size);
    return 0;
}
}