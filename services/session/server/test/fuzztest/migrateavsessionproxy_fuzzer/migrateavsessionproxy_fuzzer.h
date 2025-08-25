/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MIGRATE_AVSESSION_PROXY_FUZZER_H
#define MIGRATE_AVSESSION_PROXY_FUZZER_H

#include "migrate_avsession_proxy.h"
#include "avsession_service.h"

namespace OHOS::AVSession {
class MigrateAVSessionProxyTest {
public:
    static MigrateAVSessionProxyTest &GetInstance()
    {
        static MigrateAVSessionProxyTest test {};
        return test;
    }

    MigrateAVSessionProxyTest()
    {
        avservice_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
        if (avservice_ == nullptr) {
            return;
        }
        migrateAVSessionProxy_ = std::make_shared<MigrateAVSessionProxy>(avservice_.GetRefPtr());
        if (migrateAVSessionProxy_ == nullptr) {
            avservice_->OnStop();
            return;
        }
        migrateAVSessionProxy_->OnConnectServer(deviceId_);
    }

    ~MigrateAVSessionProxyTest()
    {
        if (migrateAVSessionProxy_) {
            migrateAVSessionProxy_->OnDisconnectServer("");
            migrateAVSessionProxy_->OnDisconnectServer(deviceId_);
            migrateAVSessionProxy_->servicePtr_ = nullptr;
            migrateAVSessionProxy_.reset();
        }
        if (avservice_) {
            avservice_->OnStop();
        }
    }

    std::shared_ptr<MigrateAVSessionProxy> migrateAVSessionProxy_ = nullptr;
    sptr<AVSessionService> avservice_ = nullptr;
    std::string deviceId_ = "DEFAULT";
};
}
#endif