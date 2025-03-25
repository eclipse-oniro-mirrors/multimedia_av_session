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

#include "securec.h"
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
static const int32_t MAX_CODE_NUM  = 20;
static const int32_t MIN_SIZE_NUM = 10;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_sizePos;

/*
* describe: get data from FUZZ untrusted data(RAW_DATA) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_sizePos) {
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
    size_t objectSize = (GetData<int8_t>() % MAX_CODE_NUM) + 1;
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_sizePos) {
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

void AVQueueInfoFuzzer::AVQueueInfoFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }

    SLOGI("AVQueueInfoFuzzTest in");
    OHOS::Parcel parcel;
    AVQueueInfo avQueueInfo;
    avQueueInfo.Marshalling(parcel);

    OHOS::Parcel data_;
    data_.WriteBuffer(RAW_DATA + sizeof(uint32_t), g_dataSize - sizeof(uint32_t));
    avQueueInfo.Unmarshalling(data_);

    std::string bundleName = GetString();
    std::string avQueueName = GetString();
    std::string avQueueId = GetString();
    avQueueInfo.SetBundleName(bundleName);
    avQueueInfo.GetBundleName();
    avQueueInfo.SetAVQueueName(avQueueName);
    avQueueInfo.GetAVQueueName();
    avQueueInfo.SetAVQueueId(avQueueId);
    avQueueInfo.GetAVQueueId();

    std::shared_ptr<AVSessionPixelMap> avQueueImage = std::make_shared<AVSessionPixelMap>();
    avQueueInfo.SetAVQueueImage(avQueueImage);
    avQueueInfo.GetAVQueueImage();

    int32_t avQueueLength = GetData<int32_t>();
    avQueueInfo.SetAVQueueLength(avQueueLength);
    avQueueInfo.GetAVQueueLength();

    std::string avQueueImageUri = GetString();
    avQueueInfo.SetAVQueueImageUri(avQueueImageUri);
    avQueueInfo.GetAVQueueImageUri();
}

void AVQueueInfoOnRemoteRequest(uint8_t* data, size_t size)
{
    // initialize data
    RAW_DATA = data;
    g_dataSize = size;
    g_sizePos = 0;

    auto avQueueInfo = std::make_unique<AVQueueInfoFuzzer>();
    if (avQueueInfo == nullptr) {
        SLOGE("avQueueInfo is null");
        return;
    }
    avQueueInfo->AVQueueInfoFuzzTest();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    AVQueueInfoOnRemoteRequest(data, size);
    return 0;
}
}