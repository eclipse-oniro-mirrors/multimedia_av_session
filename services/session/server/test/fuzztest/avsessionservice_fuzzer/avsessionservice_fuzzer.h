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

#ifndef OHOS_AVSESSIONSERVICE_FUZZER_H
#define OHOS_AVSESSIONSERVICE_FUZZER_H
#include "avsession_proxy.h"

namespace OHOS::AVSession {
    class AVSessionProxyTestOnServiceFuzzer : public AVSessionProxy {
    public:
        explicit AVSessionProxyTestOnServiceFuzzer(const sptr<IRemoteObject> &impl)
            : AVSessionProxy(impl)
        {}
        sptr<IRemoteObject> GetRemote()
        {
            return Remote();
        }
    };

    class AVSessionServiceStubFuzzer {
    public:
        AVSessionServiceStubFuzzer() = default;
        ~AVSessionServiceStubFuzzer() = default;
        int32_t OnRemoteRequest(const uint8_t* data, size_t size);
        int32_t OnRemoteRequestForSessionStub(const uint8_t* data, size_t size);
    };
}

#endif
