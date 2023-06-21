/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_CALLBACK_PROXY_FUZZER_H
#define OHOS_AVSESSION_CALLBACK_PROXY_FUZZER_H
#include <cstdint>
#include "avsession_callback_proxy.h"
namespace OHOS::AVSession {
class AvsessionCallbackProxyFuzzerTest : public AVSessionCallbackProxy {
public:
    explicit AvsessionCallbackProxyFuzzerTest(const sptr<IRemoteObject>& impl)
        : AVSessionCallbackProxy(impl)
    {}
    sptr<IRemoteObject> GetRemote()
    {
        return Remote();
    }
};

bool AvsessionCallbackProxySendRequestTest(uint8_t* data, size_t size);

class AvsessionCallbackProxyFuzzer {
public:
    AvsessionCallbackProxyFuzzer() = default;
    ~AvsessionCallbackProxyFuzzer() = default;
    bool FuzzSendRequest(uint8_t* data, size_t size);
};
}
#endif