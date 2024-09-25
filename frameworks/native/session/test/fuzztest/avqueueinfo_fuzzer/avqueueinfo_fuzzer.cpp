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

#include <iostream>
#include <memory>

#include "avqueue_info.h"
#include "avqueueinfo_fuzzer.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using namespace std;
namespace OHOS::AVSession {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t MAX_CODE_TEST = 24;

void AVQueueInfoFuzzer::AVQueueInfoFuzzTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }

    OHOS::Parcel parcel;
    AVQueueInfo avQueueInfo;
    avQueueInfo.Marshalling(parcel);

    OHOS::Parcel data_;
    data_.WriteBuffer(data, size);
    avQueueInfo.Unmarshalling(data_);

    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string avQueueName(reinterpret_cast<const char*>(data), size);
    std::string avQueueId(reinterpret_cast<const char*>(data), size);
    avQueueInfo.SetBundleName(bundleName);
    avQueueInfo.GetBundleName();
    avQueueInfo.SetAVQueueName(avQueueName);
    avQueueInfo.GetAVQueueName();
    avQueueInfo.SetAVQueueId(avQueueId);
    avQueueInfo.GetAVQueueId();

    std::shared_ptr<AVSessionPixelMap> avQueueImage = std::make_shared<AVSessionPixelMap>();
    avQueueInfo.SetAVQueueImage(avQueueImage);
    avQueueInfo.GetAVQueueImage();

    int32_t avQueueLength = *(reinterpret_cast<const int32_t*>(data));
    avQueueInfo.SetAVQueueLength(avQueueLength);
    avQueueInfo.GetAVQueueLength();

    std::string avQueueImageUri(reinterpret_cast<const char*>(data), size);
    avQueueInfo.SetAVQueueImageUri(avQueueImageUri);
    avQueueInfo.GetAVQueueImageUri();
}

void AVQueueInfoOnRemoteRequest(uint8_t* data, size_t size)
{
    auto avQueueInfo = std::make_unique<AVQueueInfoFuzzer>();
    if (avQueueInfo == nullptr) {
        SLOGE("avQueueInfo is null");
        return;
    }
    avQueueInfo->AVQueueInfoFuzzTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    AVQueueInfoOnRemoteRequest(data, size);
    return 0;
}
}