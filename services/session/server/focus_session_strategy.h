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
    struct FocusSessionChangeInfo {
        int32_t uid {};
    };
    using FocusSessionChangeCallback = std::function<void(const FocusSessionChangeInfo&)>;
    using FocusSessionSelector = std::function<bool(const FocusSessionChangeInfo&)>;

    FocusSessionStrategy();
    ~FocusSessionStrategy();

    void Init();

    void RegisterFocusSessionChangeCallback(const FocusSessionChangeCallback& callback);
    void RegisterFocusSessionSelector(const FocusSessionSelector& selector);

private:
    void HandleAudioRenderStateChangeEvent(const AudioRendererChangeInfos& infos);

    bool IsFocusSession(const AudioStandard::AudioRendererChangeInfo& info);
    bool SelectFocusSession(const AudioRendererChangeInfos& infos, FocusSessionChangeInfo& sessionInfo);

    FocusSessionChangeCallback callback_;
    FocusSessionSelector selector_;
    std::shared_ptr<AudioStandard::AudioRendererStateChangeCallback> audioRendererStateChangeCallback_;
    std::recursive_mutex stateLock_;
    std::map<int32_t, AudioStandard::RendererState> lastStates_;
};
}
#endif // OHOS_FOCUS_SESSION_STRATEGY_H