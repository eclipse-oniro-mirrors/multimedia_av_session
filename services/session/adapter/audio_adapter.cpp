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
#include "audio_adapter.h"
#include "audio_system_manager.h"
#include "avsession_log.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
std::shared_ptr<AudioAdapter> AudioAdapter::instance_;
std::once_flag AudioAdapter::onceFlag_;

AudioAdapter& AudioAdapter::GetInstance()
{
    std::call_once(onceFlag_, [] {
        instance_ = std::make_shared<AudioAdapter>();
    });
    return *instance_;
}

AudioAdapter::AudioAdapter()
{
    SLOGD("construct");
}

AudioAdapter::~AudioAdapter()
{
    SLOGD("destroy");
}

void AudioAdapter::Init()
{
    SLOGI("register audio renderer event listener");
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->RegisterAudioRendererEventListener(getpid(),
                                                                                                    shared_from_this());
    if (ret != 0) {
        SLOGE("register audio renderer event listener failed");
    }
    AudioStandard::AudioRendererInfo rendererInfo = {};
    rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    ret = AudioStandard::AudioRoutingManager::GetInstance()->SetPreferredOutputDeviceChangeCallback(
        rendererInfo, shared_from_this());
    if (ret != 0) {
        SLOGE("register audio device changed event listener failed");
    }
}

void AudioAdapter::AddStreamRendererStateListener(const StateListener& listener)
{
    listeners_.push_back(listener);
}

void AudioAdapter::AddDeviceChangeListener(const PreferOutputDeviceChangeListener& listener)
{
    deviceChangeListeners_.push_back(listener);
}

int32_t AudioAdapter::MuteAudioStream(int32_t uid, int32_t pid)
{
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfo;
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(audioRendererChangeInfo);
    if (ret != 0) {
        SLOGE("get renderer state failed");
        return AVSESSION_ERROR;
    }
    auto muteRet = AVSESSION_ERROR;
    for (const auto& info : audioRendererChangeInfo) {
        if ((info->clientUID == uid && info->clientPid == pid) &&
            info->rendererState == AudioStandard::RENDERER_RUNNING &&
            (std::count(BACKGROUND_MUTE_STREAM_USAGE.begin(), BACKGROUND_MUTE_STREAM_USAGE.end(),
                info->rendererInfo.streamUsage) != 0)) {
            SLOGI("mute uid=%{public}d pid=%{public}d stream usage %{public}d renderer state is %{public}d",
                uid, pid, info->rendererInfo.streamUsage, info->rendererState);
            auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
                uid, AudioStandard::StreamSetState::STREAM_MUTE, info->rendererInfo.streamUsage);
            if (ret != 0) {
                SLOGE("mute uid=%{public}d failed", uid);
                return AVSESSION_ERROR;
            }
            muteRet = AVSESSION_SUCCESS;
        }
    }
    return muteRet;
}

int32_t AudioAdapter::UnMuteAudioStream(int32_t uid)
{
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfo;
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(audioRendererChangeInfo);
    if (ret != 0) {
        SLOGE("get renderer state failed");
        return AVSESSION_ERROR;
    }
    for (const auto& info : audioRendererChangeInfo) {
        if (info->clientUID == uid) {
            SLOGI("unmute uid=%{public}d stream usage %{public}d renderer state is %{public}d",
                uid, info->rendererInfo.streamUsage, info->rendererState);
            auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
                uid, AudioStandard::StreamSetState::STREAM_UNMUTE, info->rendererInfo.streamUsage);
            if (ret != 0) {
                SLOGE("mute uid=%{public}d failed", uid);
                return AVSESSION_ERROR;
            }
        }
    }
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::UnMuteAudioStream(int32_t uid, AudioStandard::StreamUsage usage)
{
    SLOGI("unmute uid=%{public}d stream usage %{public}d", uid, usage);
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
        uid, AudioStandard::StreamSetState::STREAM_UNMUTE, usage);
    if (ret != 0) {
        SLOGE("unmute uid=%{public}d failed", uid);
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::MuteAudioStream(int32_t uid, AudioStandard::StreamUsage usage)
{
    if (std::count(BACKGROUND_MUTE_STREAM_USAGE.begin(), BACKGROUND_MUTE_STREAM_USAGE.end(), usage) == 0) {
        SLOGI("mute uid=%{public}d stream usage=%{public}d uncontrolled, return", uid, usage);
        return AVSESSION_ERROR;
    }
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
        uid, AudioStandard::StreamSetState::STREAM_MUTE, usage);
    if (ret != 0) {
        SLOGE("mute uid=%{public}d failed", uid);
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::PauseAudioStream(int32_t uid, AudioStandard::StreamUsage usage)
{
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
        uid, AudioStandard::StreamSetState::STREAM_PAUSE, usage);
    if (ret != 0) {
        SLOGE("pause uid=%{public}d failed", uid);
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

void AudioAdapter::OnRendererStateChange(const AudioRendererChangeInfos& infos)
{
    for (const auto& listener : listeners_) {
        if (listener) {
            listener(infos);
        }
    }
}

void AudioAdapter::OnDeviceChange(const DeviceChangeAction& deviceChangeAction)
{
}

void AudioAdapter::OnPreferredOutputDeviceUpdated(const std::vector<sptr<AudioDeviceDescriptor>> &desc)
{
    for (const auto& listener : deviceChangeListeners_) {
        if (listener) {
            listener(desc);
        }
    }
}

bool AudioAdapter::GetRendererRunning(int32_t uid)
{
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfo;
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(audioRendererChangeInfo);
    if (ret != 0) {
        SLOGE("get renderer state failed");
        return false;
    }
    for (const auto& info : audioRendererChangeInfo) {
        if (info->clientUID == uid && info->rendererState == AudioStandard::RENDERER_RUNNING) {
            SLOGI("find uid=%{public}d renderer state is %{public}d", uid, info->rendererState);
            return true;
        }
    }
    return false;
}
}
