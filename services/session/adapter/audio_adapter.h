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

#ifndef AV_SESSION_AUDIO_ADAPTER_H
#define AV_SESSION_AUDIO_ADAPTER_H

#include <functional>
#include <memory>
#include <mutex>
#include "audio_stream_manager.h"
#include "audio_info.h"

namespace OHOS::AVSession {
using AudioRendererChangeInfos = std::vector<std::unique_ptr<AudioStandard::AudioRendererChangeInfo>>;
using DeviceChangeAction = AudioStandard::DeviceChangeAction;
class AudioAdapter : public AudioStandard::AudioRendererStateChangeCallback,
                     public AudioStandard::AudioManagerDeviceChangeCallback,
                     public std::enable_shared_from_this<AudioAdapter> {
public:
    using StateListener = std::function<void(const AudioRendererChangeInfos& infos)>;
    using DeviceChangeListener = std::function<void(const DeviceChangeAction& deviceChangeAction)>;
    static AudioAdapter& GetInstance();

    AudioAdapter();
    ~AudioAdapter() override;

    void Init();

    void AddStreamRendererStateListener(const StateListener& listener);

    void AddDeviceChangeListener(const DeviceChangeListener& listener);

    int32_t PauseAudioStream(int32_t uid);

    int32_t PauseAudioStream(int32_t uid, AudioStandard::StreamUsage usage);

    void OnRendererStateChange(const AudioRendererChangeInfos& infos) override;

    void OnDeviceChange(const DeviceChangeAction& deviceChangeAction) override;

    bool GetRendererState(int32_t uid, AudioStandard::RendererState& rendererState);

private:
    static std::shared_ptr<AudioAdapter> instance_;
    static std::once_flag onceFlag_;
    std::vector<StateListener> listeners_;
    std::vector<DeviceChangeListener> deviceChangeListeners_;
};
}
#endif // AV_SESSION_AUDIO_ADAPTER_H
