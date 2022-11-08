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
    AudioStandard::AudioStreamManager::GetInstance()->RegisterAudioRendererEventListener(getpid(), shared_from_this());
    if (ret != 0) {
        SLOGE("register audio renderer event listener failed");
    }
}

void AudioAdapter::AddStreamRendererStateListener(const StateListener &listener)
{
    listeners_.push_back(listener);
}

int32_t AudioAdapter::PauseAudioStream(int32_t uid)
{
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
        uid, AudioStandard::StreamSetState::STREAM_PAUSE, AudioStandard::AudioStreamType::STREAM_MUSIC);
    if (ret != 0) {
        SLOGE("pause uid=%{public}d failed", uid);
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

void AudioAdapter::OnRendererStateChange(const AudioRendererChangeInfos &infos)
{
    for (const auto& listener : listeners_) {
        if (listener) {
            listener(infos);
        }
    }
}

bool AudioAdapter::GetRendererState(int32_t uid, AudioStandard::RendererState &rendererState)
{
    std::vector<std::unique_ptr<AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfo;
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(audioRendererChangeInfo);
    if (ret != 0) {
        SLOGE("get renderer state failed");
        return false;
    }
    for (const auto& info : audioRendererChangeInfo) {
        if (info->clientUID == uid) {
            rendererState = info->rendererState;
            SLOGI("find uid=%{public}d renderer state is %{public}d", uid, rendererState);
            return true;
        }
    }
    SLOGE("find uid=%{public}d renderer state fail", uid);
    return false;
}
}