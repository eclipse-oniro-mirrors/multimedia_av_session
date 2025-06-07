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

#ifndef OHOS_FOCUS_SESSION_STRATEGY_H
#define OHOS_FOCUS_SESSION_STRATEGY_H

#include <functional>
#include <map>
#include <memory>
#include "audio_stream_manager.h"
#include "audio_adapter.h"

namespace OHOS::AVSession {
class FocusSessionStrategy {
public:
    using StreamUsage = AudioStandard::StreamUsage;
    struct FocusSessionChangeInfo {
        int32_t uid {};
        int32_t pid {};
        StreamUsage streamUsage {};
    };
    using FocusSessionChangeCallback = std::function<void(const FocusSessionChangeInfo&, bool)>;
    using FocusSessionSelector = std::function<bool(const FocusSessionChangeInfo&)>;

    FocusSessionStrategy();
    ~FocusSessionStrategy();

    void Init();

    void RegisterFocusSessionChangeCallback(const FocusSessionChangeCallback& callback);
    void RegisterFocusSessionSelector(const FocusSessionSelector& selector);

private:
    void HandleAudioRenderStateChangeEvent(const AudioRendererChangeInfos& infos);

    bool IsFocusSession(const std::pair<int32_t, int32_t> key);
    bool CheckFocusSessionStop(const std::pair<int32_t, int32_t> key);
    void UpdateFocusSession(const std::pair<int32_t, int32_t> key);
    void DelayStopFocusSession(const std::pair<int32_t, int32_t> key);
    void ProcAudioRenderChange(const AudioRendererChangeInfos& infos);

    FocusSessionChangeCallback callback_;
    FocusSessionSelector selector_;
    std::shared_ptr<AudioStandard::AudioRendererStateChangeCallback> audioRendererStateChangeCallback_;
    std::recursive_mutex stateLock_;
    std::map<std::pair<int32_t, int32_t>, int32_t> lastStates_;   //<<uid,pid>, state>
    std::map<std::pair<int32_t, int32_t>, int32_t> currentStates_;
    const int32_t cancelTimeout = 5000;
    const int32_t runningState = 2;
    const int32_t stopState = 0;
    const int32_t ancoUid = 1041;
    const std::vector<AudioStandard::StreamUsage> ALLOWED_ANCO_STREAM_USAGE {
        AudioStandard::STREAM_USAGE_MUSIC,
        AudioStandard::STREAM_USAGE_MOVIE,
        AudioStandard::STREAM_USAGE_VOICE_COMMUNICATION
    };
    const std::vector<AudioStandard::StreamUsage> ALLOWED_MEDIA_STREAM_USAGE {
        AudioStandard::STREAM_USAGE_MUSIC,
        AudioStandard::STREAM_USAGE_MOVIE,
        AudioStandard::STREAM_USAGE_AUDIOBOOK
    };
};
}
#endif // OHOS_FOCUS_SESSION_STRATEGY_H