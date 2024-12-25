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

#include "avcall_meta_data.h"
#include "avcallmetadata_fuzzer.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "securec.h"

using namespace std;
namespace OHOS::AVSession {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t *RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

/*
 * describe: get data from outside untrusted data(RAW_DATA) which size is according to sizeof(T)
 * tips: only support basic type
 */
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

void AVCallMetaDataFuzzer::AVCallMetaDataFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    OHOS::Parcel parcel;
    AVCallMetaData avCallMetaData;
    avCallMetaData.Marshalling(parcel);

    OHOS::Parcel data_;
    data_.WriteBuffer(RAW_DATA, g_dataSize);
    avCallMetaData.Unmarshalling(data_);

    uint8_t randomNum1 = GetData<uint8_t>();
    uint8_t randomNum2 = GetData<uint8_t>();
    std::vector<std::string> names = { "fake_name1", "fake_name2" };
    std::vector<std::string> phoneNumbers = { "11111111111", "22222222222", "33333333333" };
    std::string name(names[randomNum1 % names.size()]);
    std::string phoneNumber(phoneNumbers[randomNum2 % phoneNumbers.size()]);
    avCallMetaData.SetName(name);
    avCallMetaData.GetName();
    avCallMetaData.SetPhoneNumber(phoneNumber);
    avCallMetaData.GetPhoneNumber();

    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    avCallMetaData.SetMediaImage(mediaImage);
    avCallMetaData.GetMediaImage();

    uint8_t randomNum3 = GetData<uint8_t>();
    std::vector<std::string> mediaImageUris = { "fake_uri1", "fake_uri2" };
    std::string mediaImageUri(mediaImageUris[randomNum3 % mediaImageUris.size()]);
    avCallMetaData.SetMediaImageUri(mediaImageUri);
    avCallMetaData.GetMediaImageUri();

    avCallMetaData.GetAVCallMetaMask();
    avCallMetaData.Reset();

    AVCallMetaData metaOut;
    metaOut.SetName(name);
    metaOut.SetPhoneNumber(phoneNumber);
    AVCallMetaData::AVCallMetaMaskType mask = metaOut.GetAVCallMetaMask();
    avCallMetaData.CopyToByMask(mask, metaOut);
    avCallMetaData.CopyFrom(metaOut);

    AVCallMetaData from;
    from.SetMediaImage(mediaImage);
    from.SetMediaImageUri(mediaImageUri);
    AVCallMetaData to;
    avCallMetaData.CloneMediaImage(from, to);
    avCallMetaData.CloneMediaImageUri(from, to);
}

void AVCallMetaDataOnRemoteRequest()
{
    auto avCallMetaData = std::make_unique<AVCallMetaDataFuzzer>();
    if (avCallMetaData == nullptr) {
        SLOGE("avCallMetaData is null");
        return;
    }
    avCallMetaData->AVCallMetaDataFuzzTest();
}

bool FuzzTest(const uint8_t* data, size_t size)
{
    // initialize data
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;

    AVCallMetaDataOnRemoteRequest();

    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::AVSession::THRESHOLD) {
        return 0;
    }

    FuzzTest(data, size);
    return 0;
}
}