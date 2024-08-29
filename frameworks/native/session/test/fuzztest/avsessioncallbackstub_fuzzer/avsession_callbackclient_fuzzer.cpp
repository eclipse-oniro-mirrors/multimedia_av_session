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
#include "avsession_callback_stub.h"
#include "iavsession_callback.h"
#include "iremote_stub.h"
#include "avsession_callback_client.h"
#include "want_params.h"
#include "avsession_callbackclient_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_TEST = 5;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM  = 8;

class TestAVSessionCallback : public AVSessionCallback {
    void OnAVCallAnswer() override;
    void OnAVCallHangUp() override;
    void OnAVCallToggleCallMute() override;
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward(int64_t time) override;
    void OnRewind(int64_t time) override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediald) override;
    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override;
    void OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) override;
    void OnSkipToQueueItem(int32_t itemId) override;
    void OnPlayFromAssetId(int64_t assetId) override;
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override;
};

void TestAVSessionCallback::OnAVCallAnswer()
{
    SLOGI("Enter into TestAVSessionCallback::OnAVCallAnswer.");
}

void TestAVSessionCallback::OnAVCallHangUp()
{
    SLOGI("Enter into TestAVSessionCallback::OnAVCallHangUp.");
}

void TestAVSessionCallback::OnAVCallToggleCallMute()
{
    SLOGI("Enter into TestAVSessionCallback::OnAVCallToggleCallMute.");
}

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

void TestAVSessionCallback::OnFastForward(int64_t time)
{
    SLOGI("Enter into TestAVSessionCallback::OnFastForward.");
}

void TestAVSessionCallback::OnRewind(int64_t time)
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

void TestAVSessionCallback::OnOutputDeviceChange(const int32_t connectionState,
    const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("Enter into TestAVSessionCallback::OnOutputDeviceChange.");
}

void TestAVSessionCallback::OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    SLOGI("Enter into TestAVSessionCallback::OnCommonCommand.");
}

void TestAVSessionCallback::OnSkipToQueueItem(int32_t itemId)
{
    SLOGI("Enter into TestAVSessionCallback::OnSkipToQueueItem.");
}

void TestAVSessionCallback::OnPlayFromAssetId(int64_t assetId)
{
    SLOGI("Enter into TestAVSessionCallback::OnPlayFromAssetId.");
}

void TestAVSessionCallback::OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo)
{
    SLOGI("Enter into TestAVSessionCallback::OnCastDisplayChange.");
}

void AvSessionCallbackClientFuzzer::FuzzOnRemoteRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }
    std::shared_ptr<TestAVSessionCallback> testAVSessionCallback = std::make_shared<TestAVSessionCallback>();
    if (!testAVSessionCallback) {
        SLOGI("testAVSessionCallback is null");
        return;
    }
    sptr<AVSessionCallbackClient> aVSessionCallbackClient =
        new AVSessionCallbackClient(testAVSessionCallback);
    if (!aVSessionCallbackClient) {
        SLOGI("aVSessionCallbackClient is null");
        return;
    }
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    if (!dataMessageParcel.WriteInterfaceToken(aVSessionCallbackClient->GetDescriptor())) {
        return;
    }
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    int32_t ret = aVSessionCallbackClient->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
}

void AvSessionCallbackClientFuzzer::FuzzTests(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    FuzzTestInner1(data, size);
    FuzzTestInner2(data, size);
}

void AvSessionCallbackClientFuzzer::FuzzTestInner1(const uint8_t* data, size_t size)
{
    std::shared_ptr<TestAVSessionCallback> testAVSessionCallback = std::make_shared<TestAVSessionCallback>();
    if (!testAVSessionCallback) {
        SLOGI("testAVSessionCallback is null");
        return;
    }
    AVSessionCallbackClient aVSessionCallbackClient(testAVSessionCallback);
    aVSessionCallbackClient.OnAVCallAnswer();
    aVSessionCallbackClient.OnAVCallHangUp();
    aVSessionCallbackClient.OnAVCallToggleCallMute();
    aVSessionCallbackClient.OnPlay();
    aVSessionCallbackClient.OnPause();
    aVSessionCallbackClient.OnStop();
    aVSessionCallbackClient.OnPlayNext();
    aVSessionCallbackClient.OnPlayPrevious();

    auto speed = *(reinterpret_cast<const double*>(data));
    auto time = *(reinterpret_cast<const int64_t*>(data));
    auto loopMode = *(reinterpret_cast<const int32_t*>(data));
    aVSessionCallbackClient.OnFastForward(time);
    aVSessionCallbackClient.OnRewind(time);
    aVSessionCallbackClient.OnSeek(time);
    aVSessionCallbackClient.OnSetSpeed(speed);
    aVSessionCallbackClient.OnSetLoopMode(loopMode);

    std::string mediald(reinterpret_cast<const char*>(data), size);
    aVSessionCallbackClient.OnToggleFavorite(mediald);
}

void AvSessionCallbackClientFuzzer::FuzzTestInner2(const uint8_t* data, size_t size)
{
    std::shared_ptr<TestAVSessionCallback> testAVSessionCallback = std::make_shared<TestAVSessionCallback>();
    if (!testAVSessionCallback) {
        SLOGI("testAVSessionCallback is null");
        return;
    }
    AVSessionCallbackClient aVSessionCallbackClient(testAVSessionCallback);
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_CANCEL);
    aVSessionCallbackClient.OnMediaKeyEvent(*(keyEvent.get()));

    int32_t connectionState = 0;
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = *(reinterpret_cast<const int32_t*>(data));
    deviceInfo.deviceId_ = deviceId;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    aVSessionCallbackClient.OnOutputDeviceChange(connectionState, outputDeviceInfo);

    AAFwk::WantParams commandArgs;
    std::string commonCommand(reinterpret_cast<const char*>(data), size);
    aVSessionCallbackClient.OnCommonCommand(commonCommand, commandArgs);

    auto itemId = *(reinterpret_cast<const int32_t*>(data));
    auto assetId = *(reinterpret_cast<const int64_t*>(data));
    aVSessionCallbackClient.OnSkipToQueueItem(itemId);
    aVSessionCallbackClient.OnPlayFromAssetId(assetId);

    CastDisplayInfo castDisplayInfo;
    aVSessionCallbackClient.OnCastDisplayChange(castDisplayInfo);
}

void OHOS::AVSession::AvSessionCallbackOnRemoteRequest(const uint8_t* data, size_t size)
{
    auto avSessionCallbackClient = std::make_unique<AvSessionCallbackClientFuzzer>();
    if (avSessionCallbackClient == nullptr) {
        SLOGI("avSessionCallbackClient is null");
        return;
    }
    avSessionCallbackClient->FuzzOnRemoteRequest(data, size);
}

void OHOS::AVSession::AvSessionCallbackClientTests(const uint8_t* data, size_t size)
{
    auto avSessionCallbackClient = std::make_unique<AvSessionCallbackClientFuzzer>();
    if (avSessionCallbackClient == nullptr) {
        SLOGI("avSessionCallbackClient is null");
        return;
    }
    avSessionCallbackClient->FuzzTests(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvSessionCallbackOnRemoteRequest(data, size);
    OHOS::AVSession::AvSessionCallbackClientTests(data, size);
    return 0;
}