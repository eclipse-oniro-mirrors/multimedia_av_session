/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "migrateavsession_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_service.h"
#include "migrate_avsession_server.h"
#include "migrate_avsession_manager.h"
#include "system_ability_definition.h"
#include "securec.h"

namespace OHOS::AVSession {
static const int32_t MAX_CODE_LEN = 512;
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

void MigrateAVSessionFuzzerTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    int32_t sessionId = GetData<uint8_t>();
    std::string scene = std::to_string(GetData<uint8_t>());
    std::string deviceId = std::to_string(GetData<uint8_t>());

    std::shared_ptr<MigrateAVSessionServer> migrateServer_ = std::make_shared<MigrateAVSessionServer>();
    sptr<AVSessionService> avservice_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    if (!avservice_) {
        SLOGI("service is null");
        return;
    }
    migrateServer_->Init(avservice_);
    MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(scene, migrateServer_);

    migrateServer_->ConnectProxy(sessionId);
    migrateServer_->OnConnectSession(sessionId);
    migrateServer_->OnDisconnectProxy(deviceId);
    MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(scene);
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    MigrateAVSessionFuzzerTest(const_cast<uint8_t*>(data), size);
    return 0;
}
} // namespace OHOS::AVSession
