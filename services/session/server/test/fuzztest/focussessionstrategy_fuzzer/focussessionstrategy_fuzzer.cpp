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
    info->clientUID = GetData<uint8_t>();
    info->sessionId = GetData<uint8_t>();
    info->rendererState = rendererStates[GetData<uint8_t>() % rendererStates.size()];

    AudioRendererChangeInfo info_ = {};
    info_.clientUID = GetData<uint8_t>();
    info_.clientPid = GetData<uint8_t>();
    std::pair<int32_t, int32_t> key = std::make_pair(info_.clientUID, info_.clientPid);
    info_.sessionId = GetData<uint8_t>();
    info_.rendererState = rendererStates[GetData<uint8_t>() % rendererStates.size()];
    focusSessionStrategy.IsFocusSession(key);

    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    focusSessionStrategy.HandleAudioRenderStateChangeEvent(infosExpected);
}

void FocusSessionStrategyRemoteRequest(uint8_t* data, size_t size)
{
    auto focusSessionStrategy = std::make_unique<FocusSessionStrategyFuzzer>();
    if (focusSessionStrategy == nullptr) {
        SLOGI("focusSessionStrategy is null");
        return;
    }
    focusSessionStrategy->FocusSessionStrategyFuzzTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    FocusSessionStrategyRemoteRequest(data, size);
    return 0;
}
}