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

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avcontroller_callback_stub.h"
#include "iavcontroller_callback.h"
#include "iremote_stub.h"
#include "avcontroller_callback_client.h"
#include "want_params.h"
#include "avcontroller_callbackclient_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

constexpr int32_t MAX_CODE_TEST = 5;
constexpr int32_t MAX_CODE_LEN  = 512;
constexpr int32_t MIN_SIZE_NUM  = 4;

class TestAVControllerCallback : public AVControllerCallback {
    void OnSessionDestroy() override;

    void OnPlaybackStateChange(const AVPlaybackState& state) override;

    void OnMetaDataChange(const AVMetaData& data) override;

    void OnActiveStateChange(bool isActive) override;

    void OnValidCommandChange(const std::vector<int32_t>& cmds) override;

    void OnOutputDeviceChange(const int32_t deviceState, const OutputDeviceInfo& outputDeviceInfo) override {};

    void OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args) override;

    void OnQueueItemsChange(const std::vector<AVQueueItem>& items) override;

    void OnQueueTitleChange(const std::string& title) override;

    void OnExtrasChange(const AAFwk::WantParams& extras) override;
};

void TestAVControllerCallback::OnSessionDestroy()
{
    SLOGI("Enter into TestAVControllerCallback::OnSessionDestroy.");
}

void TestAVControllerCallback::OnPlaybackStateChange(const AVPlaybackState& state)
{
    SLOGI("Enter into TestAVControllerCallback::OnPlaybackStateChange.");
}

void TestAVControllerCallback::OnMetaDataChange(const AVMetaData& data)
{
    SLOGI("Enter into TestAVControllerCallback::OnMetaDataChange.");
}

void TestAVControllerCallback::OnActiveStateChange(bool isActive)
{
    SLOGI("Enter into TestAVControllerCallback::OnActiveStateChange.");
}

void TestAVControllerCallback::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    SLOGI("Enter into TestAVControllerCallback::OnValidCommandChange.");
}

void TestAVControllerCallback::OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args)
{
    SLOGI("Enter into TestAVControllerCallback::OnSessionEventChange.");
}

void TestAVControllerCallback::OnQueueItemsChange(const std::vector<AVQueueItem>& items)
{
    SLOGI("Enter into TestAVControllerCallback::OnQueueItemsChange.");
}

void TestAVControllerCallback::OnQueueTitleChange(const std::string& title)
{
    SLOGI("Enter into TestAVControllerCallback::OnQueueTitleChange.");
}

void TestAVControllerCallback::OnExtrasChange(const AAFwk::WantParams& extras)
{
    SLOGI("Enter into TestAVControllerCallback::OnExtrasChange.");
}

void AvControllerCallbackClientFuzzer::FuzzOnRemoteRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }
    std::shared_ptr<TestAVControllerCallback> testAVControllerCallback = std::make_shared<TestAVControllerCallback>();
    if (!testAVControllerCallback) {
        SLOGI("testAVControllerCallback is null");
        return;
    }
    sptr<AVControllerCallbackClient> aVControllerCallbackClient =
        new AVControllerCallbackClient(testAVControllerCallback);
    if (!aVControllerCallbackClient) {
        SLOGI("avControllerCallbackClient is null");
        return;
    }
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    if (!dataMessageParcel.WriteInterfaceToken(aVControllerCallbackClient->GetDescriptor())) {
        return;
    }
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    int32_t ret = aVControllerCallbackClient->OnRemoteRequest(code, dataMessageParcel, reply, option);
    if (ret == 0) {
        SLOGI("OnRemoteRequest ERR_NONE");
    }
}

void AvControllerCallbackClientFuzzer::FuzzTests(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    std::shared_ptr<TestAVControllerCallback> testAVControllerCallback = std::make_shared<TestAVControllerCallback>();
    if (!testAVControllerCallback) {
        SLOGI("testAVControllerCallback is null");
        return;
    }
    AVControllerCallbackClient aVControllerCallbackClient(testAVControllerCallback);
    aVControllerCallbackClient.OnSessionDestroy();
    int32_t state = *(reinterpret_cast<const int32_t*>(data));
    if ((state >= AVPlaybackState::PLAYBACK_STATE_INITIAL) && (state <= AVPlaybackState::PLAYBACK_STATE_MAX)) {
        AVPlaybackState playbackState;
        playbackState.SetState(state);
        aVControllerCallbackClient.OnPlaybackStateChange(playbackState);
    }

    AVMetaData metaData;
    std::string assetId(reinterpret_cast<const char*>(data), size);
    metaData.SetAssetId(assetId);
    aVControllerCallbackClient.OnMetaDataChange(metaData);
    aVControllerCallbackClient.OnActiveStateChange(*(reinterpret_cast<const bool*>(data)));

    std::vector<int32_t> cmds;
    cmds.push_back(*(reinterpret_cast<const int32_t*>(data)));
    aVControllerCallbackClient.OnValidCommandChange(cmds);

    AAFwk::WantParams wantParams;
    std::string eventName(reinterpret_cast<const char*>(data), size);
    aVControllerCallbackClient.OnSessionEventChange(eventName, wantParams);
}

void OHOS::AVSession::AvControllerCallbackOnRemoteRequest(const uint8_t* data, size_t size)
{
    auto avControllerCallbackClient = std::make_unique<AvControllerCallbackClientFuzzer>();
    if (avControllerCallbackClient == nullptr) {
        SLOGI("avControllerCallbackClient is null");
        return;
    }
    avControllerCallbackClient->FuzzOnRemoteRequest(data, size);
}

void OHOS::AVSession::AvControllerCallbackClientTests(const uint8_t* data, size_t size)
{
    auto avControllerCallbackClient = std::make_unique<AvControllerCallbackClientFuzzer>();
    if (avControllerCallbackClient == nullptr) {
        SLOGI("avControllerCallbackClient is null");
        return;
    }
    avControllerCallbackClient->FuzzTests(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvControllerCallbackOnRemoteRequest(data, size);
    OHOS::AVSession::AvControllerCallbackClientTests(data, size);
    return 0;
}