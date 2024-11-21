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

#include <cstddef>
#include <cstdint>
#include <iostream>

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

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_TEST = 24;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM  = 4;

void AvSessionServiceFuzzer::FuzzOnRemoteRequest(int32_t code, const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    if (code >= MAX_CODE_TEST) {
        return;
    }
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);
    if (avSessionService == nullptr) {
        return;
    }

    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    dataMessageParcel.WriteInterfaceToken(avSessionService->GetDescriptor());
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    int32_t ret = avSessionService->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
}

void AvSessionServiceFuzzer::FuzzTests(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    sptr<AVSessionService> avSessionService = new AVSessionService(AVSESSION_SERVICE_ID);

    MessageParcel dataMessageParcel;
    OutputDeviceInfo outputDeviceInfo;
    avSessionService->CheckBeforeHandleStartCast(dataMessageParcel, outputDeviceInfo);

    OHOS::MessageParcel reply;
    AVQueueInfo aVQueueInfo;
    std::vector<AVQueueInfo> avQueueInfos = {aVQueueInfo};
    avSessionService->MarshallingAVQueueInfos(reply, avQueueInfos);

    unsigned char *buffer = new unsigned char[255];
    if (buffer != nullptr) {
        avSessionService->AVQueueInfoImgToBuffer(avQueueInfos, buffer);
        delete[] buffer;
    }
    avSessionService->AVQueueInfoImgToBuffer(avQueueInfos, buffer);
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 2, 3};
    mediaPixelMap->SetInnerImgBuffer(imgBuffer);
    aVQueueInfo.SetAVQueueImage(mediaPixelMap);
    avQueueInfos = {aVQueueInfo};
    buffer = new unsigned char[255];
    if (buffer != nullptr) {
        avSessionService->AVQueueInfoImgToBuffer(avQueueInfos, buffer);
        delete[] buffer;
    }

    OHOS::AVSession::DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "deviceid";
    deviceInfo.deviceName_ = "devicename";
    deviceInfo.ipAddress_ = "ipaddress";
    deviceInfo.providerId_ = 1;
    deviceInfo.supportedProtocols_ = 1;
    deviceInfo.authenticationStatus_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    avSessionService->CheckBeforeHandleStartCast(dataMessageParcel, outputDeviceInfo);
}

void OHOS::AVSession::AvSessionServiceOnRemoteRequest(int32_t code, const uint8_t* data, size_t size)
{
    auto aVSessionService = std::make_unique<AvSessionServiceFuzzer>();

    aVSessionService->FuzzOnRemoteRequest(code, data, size);
}

void OHOS::AVSession::AvSessionServiceTests(const uint8_t* data, size_t size)
{
    auto aVSessionService = std::make_unique<AvSessionServiceFuzzer>();

    aVSessionService->FuzzTests(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    SLOGI("the maximum length of size should not be verified");
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    for (uint32_t i = 0; i <= MAX_CODE_TEST; i++) {
        OHOS::AVSession::AvSessionServiceOnRemoteRequest(i, data, size);
    }
    OHOS::AVSession::AvSessionServiceTests(data, size);
    return 0;
}