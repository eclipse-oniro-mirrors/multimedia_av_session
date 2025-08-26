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

#include "ipc_skeleton.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_log.h"
#include "audio_info.h"
#include "focussessionstrategy_fuzzer.h"
#include "focus_session_strategy.h"
#include "avsession_item.h"
#include "securec.h"
#include "avsession_event_handler.h"

using namespace std;
namespace OHOS::AVSession {
using OHOS::AudioStandard::AudioRendererChangeInfo;
using OHOS::AudioStandard::RendererState;
static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;

static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;
 
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

void FocusSessionStrategyFuzzer::FocusSessionStrategyFuzzTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    vector<RendererState> rendererStates;
    rendererStates.push_back(RendererState::RENDERER_INVALID);
    rendererStates.push_back(RendererState::RENDERER_NEW);
    rendererStates.push_back(RendererState::RENDERER_PREPARED);
    rendererStates.push_back(RendererState::RENDERER_RUNNING);
    rendererStates.push_back(RendererState::RENDERER_STOPPED);
    rendererStates.push_back(RendererState::RENDERER_RELEASED);
    rendererStates.push_back(RendererState::RENDERER_PAUSED);
    FocusSessionStrategy focusSessionStrategy;

    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = GetData<uint32_t>();
    info->sessionId = GetData<uint32_t>();
    info->rendererState = rendererStates[GetData<uint8_t>() % rendererStates.size()];

    AudioRendererChangeInfo info_ = {};
    info_.clientUID = GetData<uint32_t>();
    info_.sessionId = GetData<uint32_t>();
    info_.clientPid = GetData<uint32_t>();
    std::pair<int32_t, int32_t> key = std::make_pair(info_.clientUID, info_.clientPid);
    info_.rendererState = rendererStates[GetData<uint8_t>() % rendererStates.size()];
    focusSessionStrategy.IsFocusSession(key);

    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infosExpected);
}

void FocusSessionStrategyFuzzer::FocusSessionStrategyFuzzTestSecond(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    FocusSessionStrategy focusSessionStrategy;
    int32_t uid = static_cast<int32_t>(GetData<uint16_t>());
    int32_t pid = static_cast<int32_t>(GetData<uint16_t>());
    pid = pid == 0 ? pid + 1 : pid;

    AudioRendererChangeInfos infos;
    auto info1 = std::make_shared<AudioStandard::AudioRendererChangeInfo>();
    if (info1 == nullptr) {
        return;
    }
    info1->clientUID = uid;
    info1->clientPid = pid;
    info1->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    info1->rendererState = AudioStandard::RendererState::RENDERER_RUNNING;
    infos.push_back(info1);

    auto info2 = std::make_shared<AudioStandard::AudioRendererChangeInfo>();
    if (info2 == nullptr) {
        return;
    }
    info2->clientUID = uid;
    info2->clientPid = static_cast<int32_t>(getpid());
    info2->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    info2->rendererState = AudioStandard::RendererState::RENDERER_STOPPED;
    infos.push_back(info2);

    auto info3 = std::make_shared<AudioStandard::AudioRendererChangeInfo>();
    if (info3 == nullptr) {
        return;
    }
    info3->clientUID = static_cast<int32_t>(getpid());
    info3->clientPid = static_cast<int32_t>(getpid());
    info3->rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    info3->rendererState = AudioStandard::RendererState::RENDERER_RELEASED;
    infos.push_back(info3);

    std::pair<int32_t, int32_t> state = {info2->clientUID, info2->clientPid};
    focusSessionStrategy.lastStates_[state] = AudioStandard::RendererState::RENDERER_RUNNING;
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infos);
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("CheckFocusStop" + std::to_string(state.second));
}

void Func1(const FocusSessionStrategy::FocusSessionChangeInfo &info, bool isPlaying)
{
    (void)info;
    (void)isPlaying;
}

bool Func2(const FocusSessionStrategy::FocusSessionChangeInfo &info)
{
    (void)info;
    return true;
}

void FocusSessionStrategyFuzzer::FocusSessionStrategyFuzzTestThird(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    FocusSessionStrategy focusSessionStrategy;
    focusSessionStrategy.RegisterFocusSessionChangeCallback([] (const auto &info, bool isPlaying) {
        (void)info;
        (void)isPlaying;
    });
    focusSessionStrategy.RegisterFocusSessionSelector([] (const auto &info) -> bool {
        (void)info;
        return true;
    });

    std::vector<int> audioPlayingUids;
    focusSessionStrategy.SetAudioPlayingUids(audioPlayingUids);

    int32_t uid = static_cast<int32_t>(GetData<uint16_t>());
    int32_t pid = static_cast<int32_t>(GetData<uint16_t>());
    pid = pid == 0 ? pid + 1 : pid;
    std::pair<int32_t, int32_t> state = {uid, pid};
    focusSessionStrategy.lastStates_[state] = AudioStandard::RendererState::RENDERER_RUNNING;
    focusSessionStrategy.CheckFocusSessionStop(state);
    std::pair<int32_t, int32_t> fakeState = {0, 0};
    focusSessionStrategy.CheckFocusSessionStop(fakeState);
    focusSessionStrategy.DelayStopFocusSession(state);
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("CheckFocusStop" + std::to_string(state.second));
    focusSessionStrategy.UpdateFocusSession(state);

    focusSessionStrategy.lastStates_.erase(fakeState);
    focusSessionStrategy.lastStates_[state] = AudioStandard::RendererState::RENDERER_RUNNING;
    focusSessionStrategy.IsFocusSession(fakeState);
    focusSessionStrategy.IsFocusSession(state);
}

void FocusSessionStrategyRemoteRequest(uint8_t* data, size_t size)
{
    auto focusSessionStrategy = std::make_unique<FocusSessionStrategyFuzzer>();
    if (focusSessionStrategy == nullptr) {
        SLOGI("focusSessionStrategy is null");
        return;
    }
    focusSessionStrategy->FocusSessionStrategyFuzzTest(data, size);
    focusSessionStrategy->FocusSessionStrategyFuzzTestSecond(data, size);
    focusSessionStrategy->FocusSessionStrategyFuzzTestThird(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    FocusSessionStrategyRemoteRequest(data, size);
    return 0;
}
}