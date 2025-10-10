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

#include <fuzzer/FuzzedDataProvider.h>
#include <vector>
#include "av_data_src_descriptor.h"
#include "avsessiondescriptor_fuzzer.h"
#include "avsession_descriptor.h"
#include "parcel.h"

namespace OHOS {
namespace AVSession {
constexpr size_t MAX_PARCEL_BUFFER_LEN = 2048;

void AVSessionDescriptorTest(FuzzedDataProvider& fdp)
{
    Parcel dataParcel;
    size_t bufferLen = fdp.ConsumeIntegralInRange<size_t>(0, MAX_PARCEL_BUFFER_LEN);
    std::vector<uint8_t> buffer = fdp.ConsumeBytes<uint8_t>(bufferLen);
    if (!buffer.empty()) {
        dataParcel.WriteBuffer(buffer.data(), buffer.size());
    }
    dataParcel.RewindRead(0);

    AVSessionDescriptor avSessionDescriptor;

    avSessionDescriptor.Unmarshalling(dataParcel);
    avSessionDescriptor.Marshalling(dataParcel);

    AVDataSrcDescriptor avDataSrcDescriptorOut;
    avDataSrcDescriptorOut.fileSize = fdp.ConsumeIntegral<int64_t>();
    avDataSrcDescriptorOut.hasCallback = fdp.ConsumeBool();

    Parcel dataSrcParcel;
    avDataSrcDescriptorOut.WriteToParcel(dataSrcParcel);
    dataSrcParcel.RewindRead(0);

    AVDataSrcDescriptor avDataSrcDescriptorIn;
    avDataSrcDescriptorIn.ReadFromParcel(dataSrcParcel);
}

} // namespace AVSession
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::AVSession::AVSessionDescriptorTest(fdp);
    return 0;
}