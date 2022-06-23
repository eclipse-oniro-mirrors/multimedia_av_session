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

#include "focus_session_strategy.h"

#include <sys/types.h>
#include <unistd.h>
#include "avsession_log.h"

namespace OHOS::AVSession {
AVSessionAudioRendererStateChangeCallback::AVSessionAudioRendererStateChangeCallback(
    const StateChangeNotifier &notifier) : notifier_(notifier)
{
    SLOGI("construct");
}

AVSessionAudioRendererStateChangeCallback::~AVSessionAudioRendererStateChangeCallback()
{
    SLOGI("destroy");
}

void AVSessionAudioRendererStateChangeCallback::OnRendererStateChange(const AudioRendererChangeInfos& infos)
{
    if (notifier_) {
        notifier_(infos);
    }
}

FocusSessionStrategy::FocusSessionStrategy()
{
    SLOGI("construct");
}

FocusSessionStrategy::~FocusSessionStrategy()
{
    SLOGI("destroy");
    AudioStandard::AudioStreamManager::GetInstance()->UnregisterAudioRendererEventListener(getpid());
}

void FocusSessionStrategy::Init()
{
    SLOGI("register audio renderer event listener");
    audioRendererStateChangeCallback_ = std::make_shared<AVSessionAudioRendererStateChangeCallback>(
        [this](const auto &infos) { HandleAudioRenderStateChangeEvent(infos); }
    );

    AudioStandard::AudioStreamManager::GetInstance()->RegisterAudioRendererEventListener(
        getpid(), audioRendererStateChangeCallback_);
}

void FocusSessionStrategy::RegisterFocusSessionChangeCallback(const FocusSessionChangeCallback &callback)
{
    callback_ = callback;
}

void FocusSessionStrategy::HandleAudioRenderStateChangeEvent(const AudioRendererChangeInfos &infos)
{
    SLOGI("enter");
    FocusSessionChangeInfo focusSessionChangeInfo;
    if (SelectFocusSession(infos, focusSessionChangeInfo)) {
        if (callback_) {
            callback_(focusSessionChangeInfo);
        }
    }
}

bool FocusSessionStrategy::IsFocusSession(const AudioStandard::AudioRendererChangeInfo& info)
{
    if ((info.rendererState == AudioStandard::RendererState::RENDERER_RUNNING) &&
        (info.rendererInfo.streamUsage == AudioStandard::StreamUsage::STREAM_USAGE_MEDIA) &&
        ((info.rendererInfo.contentType == AudioStandard::ContentType::CONTENT_TYPE_MUSIC) ||
        (info.rendererInfo.contentType == AudioStandard::ContentType::CONTENT_TYPE_MOVIE))) {
        return true;
    }
    return false;
}

bool FocusSessionStrategy::SelectFocusSession(const AudioRendererChangeInfos &infos,
                                              FocusSessionChangeInfo& sessionInfo)
{
    for (const auto& info : infos) {
        if (IsFocusSession(*info)) {
            sessionInfo.uid_ = info->clientUID;
            SLOGI("uid=%{public}d is focus session", sessionInfo.uid_);
            return true;
        }
    }
    return false;
}
}