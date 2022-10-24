/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_CONTRILLER_PROXY_FUZZER_H
#define OHOS_AVSESSION_CONTRILLER_PROXY_FUZZER_H
#include <cstdint>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include "avsession_controller_proxy.h"
namespace OHOS::AVSession {
class AvsessionControllerProxyFuzzerTest : public AVSessionControllerProxy {
public:
    explicit AvsessionControllerProxyFuzzerTest(const sptr<IRemoteObject> &impl)
        : AVSessionControllerProxy(impl)
    {}
    sptr<IRemoteObject> GetRemote()
    {
        return Remote();
    }
};
bool AvsessionControllerProxySendRequest(uint8_t* data, size_t size);
void AvsessionControllerProxyTest(uint8_t* data, size_t size);

class AvsessionControllerProxyFuzzer {
public:
    AvsessionControllerProxyFuzzer() = default;
    ~AvsessionControllerProxyFuzzer() = default;
    bool FuzzSendRequest(uint8_t* data, size_t size);
};
}
#endif

