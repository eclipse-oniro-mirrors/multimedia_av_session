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

using namespace std;
namespace OHOS::AVSession {
using OHOS::AudioStandard::AudioRendererChangeInfo;
using OHOS::AudioStandard::RendererState;
static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;
static const int32_t MAX_CODE_TEST = 24;
static constexpr int32_t SESSION_ID = 2;
static constexpr int32_t CLIENT_UID = 1;

void FocusSessionStrategyFuzzer::FocusSessionStrategyFuzzTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }

    FocusSessionStrategy focusSessionStrategy;

    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = *(reinterpret_cast<const int32_t*>(data));
    info->sessionId = *(reinterpret_cast<const int32_t*>(data));
    info->rendererState = RendererState::RENDERER_RELEASED;

    AudioRendererChangeInfo info_ = {};
    info_.clientUID = CLIENT_UID;
    info_.sessionId = SESSION_ID;
    info_.rendererState = RendererState::RENDERER_RUNNING;
    focusSessionStrategy.IsFocusSession(info_);

    FocusSessionStrategy::FocusSessionChangeInfo sessionInfo;
    sessionInfo.uid = *(reinterpret_cast<const int32_t*>(data));

    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    focusSessionStrategy.SelectFocusSession(infosExpected, sessionInfo);
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
    /* Run your code on data */
    FocusSessionStrategyRemoteRequest(data, size);
    return 0;
}
}