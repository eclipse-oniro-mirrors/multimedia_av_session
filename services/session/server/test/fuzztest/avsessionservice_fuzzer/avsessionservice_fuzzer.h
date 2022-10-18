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

#ifndef OHOS_AVSESSIONSERVICE_FUZZER_H
#define OHOS_AVSESSIONSERVICE_FUZZER_H
#include <cstdint>
#include <cstddef>
namespace OHOS::AVSession {
int32_t AVSessionServiceRemoteRequestTest(uint8_t* data, size_t size);
int32_t AVSessionServiceGetAllSessionDescriptorsTest(uint8_t* data, size_t size);
int32_t AVSessionServiceCreSessionAndControllerTest(uint8_t* data, size_t size);
int32_t AVSessionServiceRegisterTest(uint8_t* data, size_t size);
void AVSessionOnAddSystemAbilityTest(uint8_t* data, size_t size);
int32_t AVSessionSendCommandTest(uint8_t* data, size_t size);

class AVSessionServiceFuzzer {
public:
    AVSessionServiceFuzzer() = default;
    ~AVSessionServiceFuzzer() = default;
    int32_t OnRemoteRequest(uint8_t* data, size_t size);
    int32_t GetAllSessionDescriptorsTest(uint8_t* data, size_t size);
    int32_t CreateSessionAndControllerTest(uint8_t* data, size_t size);
    int32_t RegisterTest(uint8_t* data, size_t size);
    void OnAddSystemAbilityTest(uint8_t* data, size_t size);
    int32_t SendCommandTest(uint8_t* data, size_t size);
};
}
#endif