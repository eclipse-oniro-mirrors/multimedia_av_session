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
using AudioDeviceDescriptors = std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>>;
using AudioDeviceDescriptorWithSptr = std::shared_ptr<AudioStandard::AudioDeviceDescriptor>;
using DeviceChangeAction = AudioStandard::DeviceChangeAction;
using AudioDeviceDescriptor = AudioStandard::AudioDeviceDescriptor;

using AudioDeviceDescriptorsCallbackFunc = std::function<void(const AudioDeviceDescriptors&)>;

class AudioVolumeKeyEventCallback;
class AudioPreferredDeviceChangeCallback;
class AudioAllowedPlaybackCallback;

class AudioAdapter : public AudioStandard::AudioRendererStateChangeCallback,
                     public AudioStandard::AudioManagerDeviceChangeCallback,
                     public AudioStandard::AudioManagerAvailableDeviceChangeCallback,
                     public AudioStandard::AudioPreferredOutputDeviceChangeCallback,
                     public std::enable_shared_from_this<AudioAdapter> {
public:
    using StateListener = std::function<void(const AudioRendererChangeInfos& infos)>;
    using DeviceChangeListener = std::function<void(const DeviceChangeAction& deviceChangeAction)>;
    using PreferOutputDeviceChangeListener =
        std::function<void(const std::vector<std::shared_ptr<AudioDeviceDescriptor>> &desc)>;
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

    void OnAvailableDeviceChange(const AudioStandard::AudioDeviceUsage usage,
        const AudioStandard::DeviceChangeAction& deviceChangeAction) override;

    void OnPreferredOutputDeviceUpdated(const AudioDeviceDescriptors& desc) override;

    bool GetRendererRunning(int32_t uid, int32_t pid);

    int32_t SetVolume(int32_t volume);
    int32_t GetVolume();
    int32_t RegisterVolumeKeyEventCallback(const std::function<void(int32_t)>& callback);
    int32_t UnregisterVolumeKeyEventCallback();

    AudioDeviceDescriptors GetAvailableDevices();
    int32_t SetAvailableDeviceChangeCallback(const std::function<void(
        const AudioDeviceDescriptors&)>& callback);
    int32_t UnsetAvailableDeviceChangeCallback();

    AudioDeviceDescriptors GetDevices();
    int32_t SetDeviceChangeCallback();
    int32_t UnsetDeviceChangeCallback();

    AudioDeviceDescriptors GetPreferredOutputDeviceForRendererInfo();
    int32_t SetPreferredOutputDeviceChangeCallback(const std::function<void(
        const AudioDeviceDescriptors&)>& callback);
    int32_t UnsetPreferredOutputDeviceChangeCallback();

    int32_t SelectOutputDevice(const AudioDeviceDescriptorWithSptr& desc);
    AudioDeviceDescriptorWithSptr FindRenderDeviceForUsage(const AudioDeviceDescriptors& devices,
        const AudioDeviceDescriptorWithSptr& desc);

    int32_t RegisterAllowedPlaybackCallback(const std::function<bool(int32_t, int32_t)>& callback);
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
    std::recursive_mutex listenersLock_;
    bool is2in1_ {false};

    int32_t volumeMax_ = 0;
    int32_t volumeMin_ = 0;
    std::shared_ptr<AudioVolumeKeyEventCallback> volumeCallback_;
    std::shared_ptr<AudioPreferredDeviceChangeCallback> preferredDeviceChangeCallback_;

    AudioDeviceDescriptorsCallbackFunc availableDeviceChangeCallbackFunc_;
    std::shared_ptr<AudioAllowedPlaybackCallback> playbackCallback_;
};

class AudioVolumeKeyEventCallback : public AudioStandard::VolumeKeyEventCallback {
public:
    explicit AudioVolumeKeyEventCallback(const std::function<void(int32_t)>& callback)
        : callback_(callback) { }
    ~AudioVolumeKeyEventCallback() = default;

    void OnVolumeKeyEvent(AudioStandard::VolumeEvent volumeEvent) override
    {
        callback_(volumeEvent.volume);
    }

private:
    const std::function<void(int32_t)> callback_;
};

class AudioPreferredDeviceChangeCallback : public AudioStandard::AudioPreferredOutputDeviceChangeCallback {
public:
    explicit AudioPreferredDeviceChangeCallback(const std::function<void(
        const AudioDeviceDescriptors&)>& callback) : callback_(callback) { }
    ~AudioPreferredDeviceChangeCallback() = default;

    void OnPreferredOutputDeviceUpdated(const AudioDeviceDescriptors& desc) override
    {
        auto device = AudioAdapter::GetInstance().GetPreferredOutputDeviceForRendererInfo();
        callback_(device);
    }

private:
    const AudioDeviceDescriptorsCallbackFunc callback_;
};

class AudioAllowedPlaybackCallback : public AudioStandard::AudioQueryAllowedPlaybackCallback {
    public:
        explicit AudioAllowedPlaybackCallback(const std::function<bool(
            int32_t, int32_t)>& callback) : callback_(callback) { }
        ~AudioAllowedPlaybackCallback() = default;

        bool OnQueryAllowedPlayback(int32_t uid, int32_t pid) override
        {
            return callback_(uid, pid);
        }

    private:
        const std::function<bool(int32_t, int32_t)> callback_;
    };
}
#endif // AV_SESSION_AUDIO_ADAPTER_H
