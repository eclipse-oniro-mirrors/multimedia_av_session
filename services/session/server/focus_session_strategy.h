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
#include "audio_stream_manager.h"

namespace OHOS::AVSession {
using AudioRendererChangeInfos = std::vector<std::unique_ptr<AudioStandard::AudioRendererChangeInfo>>;
class FocusSessionStrategy {
public:
    struct FocusSessionChangeInfo {
        int32_t uid_ {};
    };
    using FocusSessionChangeCallback = std::function<void(const FocusSessionChangeInfo&)>;

    FocusSessionStrategy();
    ~FocusSessionStrategy();

    void Init();

    void RegisterFocusSessionChangeCallback(const FocusSessionChangeCallback& callback);

private:
    void HandleAudioRenderStateChangeEvent(const AudioRendererChangeInfos &infos);

    static bool IsFocusSession(const AudioStandard::AudioRendererChangeInfo& info);
    static bool SelectFocusSession(const AudioRendererChangeInfos &infos, FocusSessionChangeInfo& sessionInfo);

    FocusSessionChangeCallback callback_;
    std::shared_ptr<AudioStandard::AudioRendererStateChangeCallback> audioRendererStateChangeCallback_;
};

class AVSessionAudioRendererStateChangeCallback : public AudioStandard::AudioRendererStateChangeCallback {
public:
    using StateChangeNotifier = std::function<void(const AudioRendererChangeInfos&)>;

    explicit AVSessionAudioRendererStateChangeCallback(const StateChangeNotifier& notifier);
    ~AVSessionAudioRendererStateChangeCallback() override;

    void OnRendererStateChange(const AudioRendererChangeInfos& infos) override;

private:
    StateChangeNotifier notifier_;
};
}
#endif // OHOS_FOCUS_SESSION_STRATEGY_H