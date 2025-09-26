/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fuzzer/FuzzedDataProvider.h>

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_service_stub.h"
#include "iavsession_controller.h"
#include "iremote_stub.h"
#include "avcontroller_item.h"
#include "avsession_item.h"
#include "avsession_service.h"
#include "want_params.h"
#include "avsession_servicestub_fuzzer.h"
#include "securec.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_TEST = 24;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM  = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
constexpr size_t ELEMENTS_MAX_LENGTH = 128;
const size_t MAX_BUFFER_SIZE = 64 * 1024;
const size_t MAX_AVQUEUEINFO_SIZE = 512;
FuzzedDataProvider provider(RAW_DATA, g_dataSize);

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
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

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        SLOGI("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void AvSessionServiceFuzzer::FuzzOnRemoteRequest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    int32_t code = GetData<int32_t>();
    if (code >= MAX_CODE_TEST) {
        return;
    }
    sptr<AVSessionService> avSessionService = new AVSessionService(GetData<int32_t>());
    if (avSessionService == nullptr) {
        return;
    }

    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    dataMessageParcel.WriteInterfaceToken(avSessionService->GetDescriptor());
    dataMessageParcel.WriteBuffer(RAW_DATA + sizeof(uint32_t), g_dataSize - sizeof(uint32_t));
    dataMessageParcel.RewindRead(0);
    int32_t ret = avSessionService->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
}

void AvSessionServiceFuzzer::FuzzTests()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);

    MessageParcel dataMessageParcel;
    OutputDeviceInfo outputDeviceInfo;
    avSessionService->CheckBeforeHandleStartCast(dataMessageParcel, outputDeviceInfo);

    OHOS::AVSession::DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = GetData<int32_t>();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> mediaImageUris = {"deviceid", "deviceid2"};
    deviceInfo.deviceId_ = std::string (mediaImageUris[randomNum % mediaImageUris.size()]);
    uint8_t randomNum2 = GetData<uint8_t>();
    std::vector<std::string> mediaImageUris2 = {"devicename", "devicename2"};
    deviceInfo.deviceName_ = std::string (mediaImageUris2[randomNum2 % mediaImageUris.size()]);
    uint8_t randomNum3 = GetData<uint8_t>();
    std::vector<std::string> mediaImageUris3 = {"ipaddress", "ipaddress2"};
    deviceInfo.ipAddress_ = std::string (mediaImageUris3[randomNum3 % mediaImageUris.size()]);
    deviceInfo.providerId_ = GetData<int32_t>();
    deviceInfo.supportedProtocols_ = GetData<int32_t>();
    deviceInfo.authenticationStatus_ = GetData<int32_t>();
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    avSessionService->CheckBeforeHandleStartCast(dataMessageParcel, outputDeviceInfo);
}

void AvSessionServiceStubFuzzer::MarshallingAVQueueInfosFuzzTest()
{
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN(avSessionService != nullptr);
    MessageParcel reply;
    std::vector<OHOS::AVSession::AVQueueInfo> avQueueInfos;
    size_t elements = provider.ConsumeIntegralInRange<size_t>(0, ELEMENTS_MAX_LENGTH);
    for (size_t i = 0; i < elements; ++i) {
        OHOS::AVSession::AVQueueInfo info;
        avQueueInfos.push_back(std::move(info));
    }
    avSessionService->MarshallingAVQueueInfos(reply, avQueueInfos);
}

void AvSessionServiceStubFuzzer::AVQueueInfoImgToBufferFuzzTest()
{
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN(avSessionService != nullptr);
    std::vector<OHOS::AVSession::AVQueueInfo> avQueueInfos;
    size_t elements = provider.ConsumeIntegralInRange<size_t>(0, ELEMENTS_MAX_LENGTH);
    if (elements > SIZE_MAX / MAX_AVQUEUEINFO_SIZE) {
        return;
    }
    for (size_t i = 0; i < elements; ++i) {
        OHOS::AVSession::AVQueueInfo info;
        avQueueInfos.push_back(std::move(info));
    }
    size_t requiredBufferSize = elements * MAX_AVQUEUEINFO_SIZE;
    size_t bufferSize = std::min(requiredBufferSize, MAX_BUFFER_SIZE);
    if (bufferSize == 0 || bufferSize > MAX_BUFFER_SIZE) {
        return;
    }
    unsigned char* buffer = new unsigned char[bufferSize];
    avSessionService->AVQueueInfoImgToBuffer(avQueueInfos, buffer);
    delete[] buffer;
}

void AvSessionServiceStubFuzzer::HandleGetHistoricalAVQueueInfosFuzzTest()
{
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN(avSessionService != nullptr);
    MessageParcel data;
    MessageParcel reply;
    avSessionService->HandleGetHistoricalAVQueueInfos(data, reply);
}

void AvSessionServiceStubFuzzer::HandleSendSystemAVKeyEventFuzzTest()
{
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN(avSessionService != nullptr);
    MessageParcel data;
    MessageParcel reply;
    avSessionService->HandleSendSystemAVKeyEvent(data, reply);
}

void AvSessionServiceStubFuzzer::HandleGetDistributedSessionControllersInnerFuzzTest()
{
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    CHECK_AND_RETURN(avSessionService != nullptr);
    MessageParcel data;
    MessageParcel reply;
    avSessionService->HandleGetDistributedSessionControllersInner(data, reply);
}

void OHOS::AVSession::AvSessionServiceOnRemoteRequest()
{
    auto aVSessionService = std::make_unique<AvSessionServiceFuzzer>();

    aVSessionService->FuzzOnRemoteRequest();
}

void OHOS::AVSession::AvSessionServiceTests()
{
    auto aVSessionService = std::make_unique<AvSessionServiceFuzzer>();

    aVSessionService->FuzzTests();
}

typedef void (*TestFuncs[7])();

TestFuncs g_testFuncs = {
    AvSessionServiceOnRemoteRequest,
    AvSessionServiceTests,
    AvSessionServiceStubFuzzer::MarshallingAVQueueInfosFuzzTest,
    AvSessionServiceStubFuzzer::AVQueueInfoImgToBufferFuzzTest,
    AvSessionServiceStubFuzzer::HandleGetHistoricalAVQueueInfosFuzzTest,
    AvSessionServiceStubFuzzer::HandleSendSystemAVKeyEventFuzzTest,
    AvSessionServiceStubFuzzer::HandleGetDistributedSessionControllersInnerFuzzTest,
};

static bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if ((rawData == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return false;
    }

    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        SLOGI("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < THRESHOLD) {
        return 0;
    }
    FuzzTest(data, size);
    return 0;
}
