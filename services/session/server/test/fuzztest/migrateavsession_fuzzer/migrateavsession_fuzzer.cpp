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

#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_service.h"
#include "migrate_avsession_server.h"
#include "migrate_avsession_manager.h"
#include "system_ability_definition.h"

namespace OHOS::AVSession {
void MigrateAVSessionFuzzerTest(uint8_t* data, size_t size)
{
    int32_t sessionId = *reinterpret_cast<const int32_t*>(data);
    std::string scene(reinterpret_cast<const char*>(data), size);
    std::string deviceId(reinterpret_cast<const char*>(data), size);

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
    /* Run your code on data */
    MigrateAVSessionFuzzerTest(const_cast<uint8_t*>(data), size);
    return 0;
}
} // namespace OHOS::AVSession
