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

using namespace std;
namespace OHOS::AVSession {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t MAX_CODE_TEST = 24;

void AVCallMetaDataFuzzer::AVCallMetaDataFuzzTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }

    OHOS::Parcel parcel;
    AVCallMetaData avCallMetaData;
    avCallMetaData.Marshalling(parcel);

    OHOS::Parcel data_;
    data_.WriteBuffer(data, size);
    avCallMetaData.Unmarshalling(data_);

    std::string name(reinterpret_cast<const char*>(data), size);
    std::string phoneNumber(reinterpret_cast<const char*>(data), size);
    avCallMetaData.SetName(name);
    avCallMetaData.GetName();
    avCallMetaData.SetPhoneNumber(phoneNumber);
    avCallMetaData.GetPhoneNumber();

    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    avCallMetaData.SetMediaImage(mediaImage);
    avCallMetaData.GetMediaImage();

    std::string mediaImageUri(reinterpret_cast<const char*>(data), size);
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
    AVCallMetaData to;
    avCallMetaData.CloneMediaImage(from, to);
    avCallMetaData.CloneMediaImageUri(from, to);
}

void AVCallMetaDataOnRemoteRequest(uint8_t* data, size_t size)
{
    auto avCallMetaData = std::make_unique<AVCallMetaDataFuzzer>();
    if (avCallMetaData == nullptr) {
        SLOGE("avCallMetaData is null");
        return;
    }
    avCallMetaData->AVCallMetaDataFuzzTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    AVCallMetaDataOnRemoteRequest(data, size);
    return 0;
}
}