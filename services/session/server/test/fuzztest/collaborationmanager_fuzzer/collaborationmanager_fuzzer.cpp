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
#include <fuzzer/FuzzedDataProvider.h>

using namespace std;
namespace OHOS::AVSession {
static const int32_t MAX_CODE_LEN  = 20;
static const int32_t MIN_SIZE_NUM = 10;

static const uint8_t *RAW_DATA = nullptr;
static size_t g_totalSize = 0;
static size_t g_sizePos;
using TestFunc = function<void(FuzzedDataProvider&)>;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_totalSize - g_sizePos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_sizePos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_sizePos += objectSize;
    return object;
}

std::string GetString()
{
    size_t objectSize = (GetData<int8_t>() % MAX_CODE_LEN) + 1;
    if (RAW_DATA == nullptr || objectSize > g_totalSize - g_sizePos) {
        return "OVER_SIZE";
    }
    char object[objectSize + 1];
    errno_t ret = memcpy_s(object, sizeof(object), RAW_DATA + g_sizePos, objectSize);
    if (ret != EOK) {
        return "";
    }
    g_sizePos += objectSize;
    std::string output(object);
    return output;
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
    DeviceInfo deviceInfo;
    deviceInfo.supportedProtocols_ = GetData<int32_t>();
    deviceInfo.ipAddress_ = GetString();
    vector<ServiceCollaborationManagerBussinessStatus> states;
    states.push_back(ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
    states.push_back(ServiceCollaborationManagerBussinessStatus::SCM_PREPARE);
    states.push_back(ServiceCollaborationManagerBussinessStatus::SCM_CONNECTING);
    states.push_back(ServiceCollaborationManagerBussinessStatus::SCM_CONNECTED);
    collaborationManager.PublishServiceState(peerNetworkId.c_str(), states[GetData<uint8_t>() % states.size()]);
    collaborationManager.ApplyAdvancedResource(peerNetworkId.c_str(), deviceInfo);
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

void SendCollaborationOnStopFuzzTest(FuzzedDataProvider& provider)
{
    auto collaborationManager = std::make_unique<CollaborationManager>();
    CHECK_AND_RETURN(collaborationManager != nullptr);
    collaborationManager->SendCollaborationOnStop(nullptr);
}

void SendCollaborationApplyResultFuzzTest(FuzzedDataProvider& provider)
{
    auto collaborationManager = std::make_unique<CollaborationManager>();
    CHECK_AND_RETURN(collaborationManager != nullptr);
    collaborationManager->SendCollaborationApplyResult(nullptr);
}

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    // initialize data
    RAW_DATA = rawData;
    g_totalSize = size;
    g_sizePos = 0;
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);
    std::vector<TestFunc> allFuncs = {
        SendCollaborationOnStopFuzzTest,
        SendCollaborationApplyResultFuzzTest,
    };

    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t len = allFuncs.size();
    if (len > 0) {
        allFuncs[code % len](provider);
    } else {
        SLOGE("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }
    /* Run your code on data */
    CollaborationManagerRemoteRequest(data, size);
    FuzzTest(data, size);
    return 0;
}
}