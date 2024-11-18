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
#include "audio_routing_manager.h"
#include "audio_info.h"

namespace OHOS::AVSession {
using AudioRendererChangeInfos = std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>>;
using DeviceChangeAction = AudioStandard::DeviceChangeAction;
using AudioDeviceDescriptor = AudioStandard::AudioDeviceDescriptor;
class AudioAdapter : public AudioStandard::AudioRendererStateChangeCallback,
                     public AudioStandard::AudioManagerDeviceChangeCallback,
                     public AudioStandard::AudioPreferredOutputDeviceChangeCallback,
                     public std::enable_shared_from_this<AudioAdapter> {
public:
    using StateListener = std::function<void(const AudioRendererChangeInfos& infos)>;
    using DeviceChangeListener = std::function<void(const DeviceChangeAction& deviceChangeAction)>;
    using PreferOutputDeviceChangeListener = std::function<void(const std::vector<sptr<AudioDeviceDescriptor>> &desc)>;
    static AudioAdapter& GetInstance();

    AudioAdapter();
    ~AudioAdapter() override;

    void Init();

    void AddStreamRendererStateListener(const StateListener& listener);

    void AddDeviceChangeListener(const PreferOutputDeviceChangeListener& listener);

    int32_t MuteAudioStream(int32_t uid, int32_t pid);

    int32_t UnMuteAudioStream(int32_t uid);

    int32_t MuteAudioStream(int32_t uid, AudioStandard::StreamUsage usage);

    int32_t UnMuteAudioStream(int32_t uid, AudioStandard::StreamUsage usage);

    int32_t PauseAudioStream(int32_t uid, AudioStandard::StreamUsage usage);

    void OnRendererStateChange(const AudioRendererChangeInfos& infos) override;

    void OnDeviceChange(const DeviceChangeAction& deviceChangeAction) override;

    void OnPreferredOutputDeviceUpdated(const std::vector<sptr<AudioDeviceDescriptor>> &desc) override;

    bool GetRendererRunning(int32_t uid);

private:
    static std::shared_ptr<AudioAdapter> instance_;
    static std::once_flag onceFlag_;
    std::vector<StateListener> listeners_;
    std::vector<PreferOutputDeviceChangeListener> deviceChangeListeners_;
    const std::vector<AudioStandard::StreamUsage> BACKGROUND_MUTE_STREAM_USAGE {
        AudioStandard::STREAM_USAGE_MUSIC,
        AudioStandard::STREAM_USAGE_MOVIE,
        AudioStandard::STREAM_USAGE_GAME,
        AudioStandard::STREAM_USAGE_AUDIOBOOK
    };
};
}
#endif // AV_SESSION_AUDIO_ADAPTER_H
