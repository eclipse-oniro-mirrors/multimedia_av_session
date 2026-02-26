/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "avcontrollercallbackclient_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>

#include "avcontroller_callback_client.h"
#include "avsession_log.h"

namespace OHOS {
namespace AVSession {
constexpr int32_t MIN_SIZE_NUM = 10;
constexpr int32_t MAX_SIZE_NUM = 100;

class AVControllerCallbackMock : public AVControllerCallback {
    void OnAVCallMetaDataChange(const AVCallMetaData& avCallMetaData) override {}
    void OnAVCallStateChange(const AVCallState& avCallState) override {}
    void OnSessionDestroy() override {}
    void OnPlaybackStateChange(const AVPlaybackState& state) override {}
    void OnMetaDataChange(const AVMetaData& data) override {}
    void OnActiveStateChange(bool isActive) override {}
    void OnValidCommandChange(const std::vector<int32_t>& cmds) override {}
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override {}
    void OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args) override {}
    void OnQueueItemsChange(const std::vector<AVQueueItem>& items) override {}
    void OnQueueTitleChange(const std::string& title) override {}
    void OnExtrasChange(const AAFwk::WantParams& extras) override {}
    void OnCustomData(const AAFwk::WantParams& data) override {}
    void OnDesktopLyricVisibilityChanged(bool isVisible) override {}
    void OnDesktopLyricStateChanged(const DesktopLyricState &state) override {}
    void OnDesktopLyricEnabled(bool isEnabled) override {}
    virtual ~AVControllerCallbackMock() = default;
};

void AvControllerCallbackClientFuzzer::OnSessionDestroyFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);
    callbackClient->OnSessionDestroy();
}

void AvControllerCallbackClientFuzzer::OnAVCallMetaDataChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    AVCallMetaData data;
    data.SetName(provider.ConsumeRandomLengthString());
    callbackClient->OnAVCallMetaDataChange(data);
}

void AvControllerCallbackClientFuzzer::OnAVCallStateChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    AVCallState state;
    state.SetAVCallState(provider.ConsumeIntegral<int32_t>());
    callbackClient->OnAVCallStateChange(state);
}

void AvControllerCallbackClientFuzzer::OnPlaybackStateChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    AVPlaybackState state;
    state.SetState(provider.ConsumeIntegral<int32_t>());
    auto cb = [](const AVPlaybackState &state) {};
    callbackClient->AddListenerForPlaybackState(cb);
    callbackClient->OnPlaybackStateChange(state);
    callbackClient->RemoveListenerForPlaybackState();
}

void AvControllerCallbackClientFuzzer::OnMetaDataChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    AVMetaData data;
    data.SetTitle(provider.ConsumeRandomLengthString());
    callbackClient->OnMetaDataChange(data);
}

void AvControllerCallbackClientFuzzer::OnActiveStateChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    callbackClient->OnActiveStateChange(provider.ConsumeBool());
}

void AvControllerCallbackClientFuzzer::OnValidCommandChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    std::vector<int32_t> cmds;
    int32_t cmdsLen = provider.ConsumeIntegralInRange<int32_t>(MIN_SIZE_NUM, MAX_SIZE_NUM);
    for (int32_t i = 0; i < cmdsLen; i++) {
        cmds.push_back(provider.ConsumeIntegral<int32_t>());
    }
    callbackClient->OnValidCommandChange(cmds);
}

void AvControllerCallbackClientFuzzer::OnOutputDeviceChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    OutputDeviceInfo outputDeviceInfo;
    int32_t connectionState = provider.ConsumeIntegral<int32_t>();
    callbackClient->OnOutputDeviceChange(connectionState, outputDeviceInfo);
}

void AvControllerCallbackClientFuzzer::OnSessionEventChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    std::string event = provider.ConsumeRandomLengthString();
    AAFwk::WantParams args;
    callbackClient->OnSessionEventChange(event, args);
}

void AvControllerCallbackClientFuzzer::OnQueueItemsChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    std::vector<AVQueueItem> items;
    callbackClient->OnQueueItemsChange(items);
}

void AvControllerCallbackClientFuzzer::OnQueueTitleChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    std::string title = provider.ConsumeRandomLengthString();
    callbackClient->OnQueueTitleChange(title);
}

void AvControllerCallbackClientFuzzer::OnExtrasChangeFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    AAFwk::WantParams extras;
    callbackClient->OnExtrasChange(extras);
}

void AvControllerCallbackClientFuzzer::OnCustomDataFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    AAFwk::WantParams data;
    callbackClient->OnCustomData(data);
}

void AvControllerCallbackClientFuzzer::OnDesktopLyricVisibilityChangedFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    callbackClient->OnDesktopLyricVisibilityChanged(provider.ConsumeBool());
}

void AvControllerCallbackClientFuzzer::OnDesktopLyricStateChangedFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    DesktopLyricState state;
    state.isLocked_ = provider.ConsumeBool();
    callbackClient->OnDesktopLyricStateChanged(state);
}

void AvControllerCallbackClientFuzzer::OnDesktopLyricEnabledFuzzTest(FuzzedDataProvider &provider)
{
    auto callback = std::make_shared<AVControllerCallbackMock>();
    sptr<AVControllerCallbackClient> callbackClient = new AVControllerCallbackClient(callback);
    CHECK_AND_RETURN(callbackClient != nullptr);

    callbackClient->OnDesktopLyricEnabled(provider.ConsumeBool());
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        SLOGE("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

using TestFuncs = void (*)(FuzzedDataProvider &provider);

TestFuncs g_allFuncs[] = {
    AvControllerCallbackClientFuzzer::OnSessionDestroyFuzzTest,
    AvControllerCallbackClientFuzzer::OnAVCallMetaDataChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnAVCallStateChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnPlaybackStateChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnMetaDataChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnActiveStateChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnValidCommandChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnOutputDeviceChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnSessionEventChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnQueueItemsChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnQueueTitleChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnExtrasChangeFuzzTest,
    AvControllerCallbackClientFuzzer::OnCustomDataFuzzTest,
    AvControllerCallbackClientFuzzer::OnDesktopLyricVisibilityChangedFuzzTest,
    AvControllerCallbackClientFuzzer::OnDesktopLyricStateChangedFuzzTest,
    AvControllerCallbackClientFuzzer::OnDesktopLyricEnabledFuzzTest,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    uint32_t len = GetArrLength(g_allFuncs);
    CHECK_AND_RETURN_RET(len > 0, false);
    FuzzedDataProvider provider(rawData, size);
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t index = code % len;
    if (len > 0 && g_allFuncs[index] != nullptr) {
        g_allFuncs[index](provider);
    } else {
        SLOGE("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }
    /* Run your code on data */
    FuzzTest(data, size);
    return 0;
}
} // namespace AVSession
} // namespace OHOS
