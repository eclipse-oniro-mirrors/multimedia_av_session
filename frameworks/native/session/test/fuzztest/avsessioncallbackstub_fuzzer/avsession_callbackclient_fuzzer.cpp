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

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include "avsession_callback_stub.h"
#include "iavsession_callback.h"
#include "avsession_callbackclient_fuzzer.h"
#include "avsession_callback_client.h"
#include "avsession_info.h"
#include "key_event.h"
#include "avsession_log.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_LEN = 512;
const int32_t MAX_CODE_TEST = 15;

void TestAVSessionCallback::OnPlay()
{
    SLOGI("Enter into TestAVSessionCallback::OnPlay.");
}

void TestAVSessionCallback::OnPause()
{
    SLOGI("Enter into TestAVSessionCallback::OnPause.");
}

void TestAVSessionCallback::OnStop()
{
    SLOGI("Enter into TestAVSessionCallback::OnStop.");
}

void TestAVSessionCallback::OnPlayNext()
{
    SLOGI("Enter into TestAVSessionCallback::OnPlayNext.");
}

void TestAVSessionCallback::OnPlayPrevious()
{
    SLOGI("Enter into TestAVSessionCallback::OnPlayPrevious.");
}

void TestAVSessionCallback::OnFastForward()
{
    SLOGI("Enter into TestAVSessionCallback::OnFastForward.");
}

void TestAVSessionCallback::OnRewind()
{
    SLOGI("Enter into TestAVSessionCallback::OnRewind.");
}

void TestAVSessionCallback::OnSeek(int64_t time)
{
    SLOGI("Enter into TestAVSessionCallback::OnSeek.");
}

void TestAVSessionCallback::OnSetSpeed(double speed)
{
    SLOGI("Enter into TestAVSessionCallback::OnSetSpeed.");
}

void TestAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
    SLOGI("Enter into TestAVSessionCallback::OnSetLoopMode.");
}

void TestAVSessionCallback::OnToggleFavorite(const std::string& mediald)
{
    SLOGI("Enter into TestAVSessionCallback::OnToggleFavorite.");
}

void TestAVSessionCallback::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    SLOGI("Enter into TestAVSessionCallback::OnMediaKeyEvent.");
}

void TestAVSessionCallback::OnOutputDeviceChange(const OutputDeviceInfo &outputDeviceInfo)
{
    SLOGI("Enter into TestAVSessionCallback::OnOutputDeviceChange.");
}

int32_t AvSessionCallbackClientFuzzer::FuzzOnRemoteRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return 0;
    }
	if (size > MAX_CODE_LEN) {
        return 0;
    }

    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
	if (code > MAX_CODE_TEST) {
		return 0;
	}

    size -= sizeof(uint32_t);

    std::shared_ptr<AVSessionCallback> avSessionCallbackStub(new TestAVSessionCallback);
    sptr<AVSessionCallbackClient> avSessionCallbackStubClient = new AVSessionCallbackClient(avSessionCallbackStub);
	if (!avSessionCallbackStubClient) {
	    SLOGI("avSessionCallbackStubClient is null");
	    return false;
    }
    MessageParcel reply;
    MessageOption option;
    MessageParcel dataMessageParcel;

    if (!dataMessageParcel.WriteInterfaceToken(avSessionCallbackStubClient->GetDescriptor())) {
        return 0;
    }
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    int32_t ret = avSessionCallbackStubClient->OnRemoteRequest(code, dataMessageParcel, reply, option);
    return ret;
}

int32_t OHOS::AVSession::AvSessionCallbackClientRemoteRequestTest(uint8_t* data, size_t size)
{
    auto avSessionCallbackStub = std::make_unique<AvSessionCallbackClientFuzzer>();
    if (avSessionCallbackStub == nullptr) {
        cout << "avSessionCallbackStub is null" << endl;
        return 0;
    }
    return avSessionCallbackStub->FuzzOnRemoteRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvSessionCallbackClientRemoteRequestTest(const_cast<uint8_t*>(data), size);
    return 0;
}