/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "avsession_log.h"
#include "avsession_errors.h"
#include "session_listener_client.h"
#include "session_listenerstub_fuzzer.h"

namespace OHOS::AVSession {
static constexpr int32_t MAX_CODE_NUM = 6;
static constexpr int32_t MIN_SIZE_NUM = 4;
std::shared_ptr<SessionListenerClient> g_SessionListenerStubClient(nullptr);

void SessionListenerStubFuzzer::OnRemoteRequest(int32_t code, uint8_t* data, size_t size)
{
    size -= sizeof(uint32_t);
    
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInterfaceToken(ISessionListener::GetDescriptor());
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    g_SessionListenerStubClient->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void SessionListenerStubFuzzer::FuzzTests(const uint8_t* data, size_t size)
{
    int32_t uid = *(reinterpret_cast<const int32_t*>(data));
    g_SessionListenerStubClient->OnAudioSessionChecked(uid);

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "deviceId";
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    g_SessionListenerStubClient->OnDeviceAvailable(outputDeviceInfo);

    std::string deviceId(reinterpret_cast<const char *>(data), size);
    g_SessionListenerStubClient->OnDeviceOffline(deviceId);
}

void SessionListenerStubTest(uint8_t* data, size_t size)
{
    auto sessionListenerStubFuzzer = std::make_unique<SessionListenerStubFuzzer>();
    if (sessionListenerStubFuzzer == nullptr) {
        return;
    }
    sessionListenerStubFuzzer->FuzzTests(data, size);
    for (uint32_t i = 0; i <= MAX_CODE_NUM; i++) {
        sessionListenerStubFuzzer->OnRemoteRequest(i, data, size);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    SLOGI("the maximum length of size should not be verified");
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    
    std::shared_ptr<TestSessionListener> testSessionListener = std::make_shared<TestSessionListener>();
    g_SessionListenerStubClient = std::make_shared<SessionListenerClient>(testSessionListener);

    SessionListenerStubTest(data, size);
    return 0;
}
}