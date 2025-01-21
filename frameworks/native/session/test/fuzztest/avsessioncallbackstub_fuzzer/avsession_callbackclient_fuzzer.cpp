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
#include "securec.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static constexpr int32_t MAX_CODE_TEST = 5;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM  = 8;
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

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        SLOGI("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

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
    void OnToggleFavorite(const std::string& mediaId) override;
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

void TestAVSessionCallback::OnToggleFavorite(const std::string& mediaId)
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

void AvSessionCallbackClientFuzzer::FuzzOnRemoteRequest(int32_t code)
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
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
    dataMessageParcel.WriteBuffer(RAW_DATA + sizeof(uint32_t), g_dataSize - sizeof(uint32_t));
    dataMessageParcel.RewindRead(0);
    int32_t ret = aVSessionCallbackClient->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
}

void AvSessionCallbackClientFuzzer::FuzzTests()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    FuzzTestInner1();
    FuzzTestInner2();
}

void AvSessionCallbackClientFuzzer::FuzzTestInner1()
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

    auto speed = GetData<double>();
    auto time = GetData<int64_t>();
    auto loopMode = GetData<int32_t>();
    aVSessionCallbackClient.OnFastForward(time);
    aVSessionCallbackClient.OnRewind(time);
    aVSessionCallbackClient.OnSeek(time);
    aVSessionCallbackClient.OnSetSpeed(speed);
    aVSessionCallbackClient.OnSetLoopMode(loopMode);

    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> mediaIds = { "mediaId1", "mediaId2", "mediaId3" };
    std::string mediaId(mediaIds[randomNum % mediaIds.size()]);
    aVSessionCallbackClient.OnToggleFavorite(mediaId);
}

void AvSessionCallbackClientFuzzer::FuzzTestInner2()
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
    uint8_t randomNum1 = GetData<uint8_t>();
    std::vector<std::string> deviceIds = { "device1", "device2", "device3" };
    std::string deviceId(deviceIds[randomNum1 % deviceIds.size()]);
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = GetData<uint32_t>();
    deviceInfo.deviceId_ = deviceId;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    aVSessionCallbackClient.OnOutputDeviceChange(connectionState, outputDeviceInfo);

    AAFwk::WantParams commandArgs;
    uint8_t randomNum2 = GetData<uint8_t>();
    std::vector<std::string> commonCommands = { "command1", "command2", "command3" };
    std::string commonCommand(commonCommands[randomNum2 % commonCommands.size()]);
    aVSessionCallbackClient.OnCommonCommand(commonCommand, commandArgs);

    auto itemId = GetData<uint32_t>();
    auto assetId = GetData<uint64_t>();
    aVSessionCallbackClient.OnSkipToQueueItem(itemId);
    aVSessionCallbackClient.OnPlayFromAssetId(assetId);

    CastDisplayInfo castDisplayInfo;
    uint8_t randomNum3 = GetData<uint8_t>();
    std::vector<std::string> infoNames = { "info1", "info2", "info3" };
    castDisplayInfo.name = infoNames[randomNum3 % infoNames.size()];
    aVSessionCallbackClient.OnCastDisplayChange(castDisplayInfo);
}

void OHOS::AVSession::AvSessionCallbackOnRemoteRequest()
{
    for (uint32_t i = 0; i <= MAX_CODE_TEST; i++) {
        auto avSessionCallbackClient = std::make_unique<AvSessionCallbackClientFuzzer>();
        if (avSessionCallbackClient == nullptr) {
            SLOGI("avSessionCallbackClient is null");
            return;
        }
        avSessionCallbackClient->FuzzOnRemoteRequest(i);
    }
}

void OHOS::AVSession::AvSessionCallbackClientTests()
{
    auto avSessionCallbackClient = std::make_unique<AvSessionCallbackClientFuzzer>();
    if (avSessionCallbackClient == nullptr) {
        SLOGI("avSessionCallbackClient is null");
        return;
    }
    avSessionCallbackClient->FuzzTests();
}

typedef void (*TestFuncs[2])();

TestFuncs g_testFuncs = {
    OHOS::AVSession::AvSessionCallbackOnRemoteRequest,
    OHOS::AVSession::AvSessionCallbackClientTests,
};

static bool FuzzTest(const uint8_t* rawData, size_t size)
{
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