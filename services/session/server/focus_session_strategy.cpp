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
#include "avsession_log.h"
#include "audio_adapter.h"
#include "avsession_sysevent.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {
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
    AudioAdapter::GetInstance().AddStreamRendererStateListener([this](const auto& infos) {
        HandleAudioRenderStateChangeEvent(infos);
    });
}

void FocusSessionStrategy::RegisterFocusSessionChangeCallback(const FocusSessionChangeCallback& callback)
{
    callback_ = callback;
}

void FocusSessionStrategy::RegisterFocusSessionSelector(const FocusSessionSelector& selector)
{
    selector_ = selector;
}

void FocusSessionStrategy::ProcAudioRenderChange(const AudioRendererChangeInfos& infos)
{
    SLOGD("AudioRenderStateChange start");
    std::pair<int32_t, int32_t> playingKey = std::make_pair(-1, -1);
    for (const auto& info : infos) {
        SLOGD("AudioRenderStateChange uid=%{public}d pid=%{public}d audioSessionId=%{public}d state=%{public}d",
            info->clientUID, info->clientPid, info->sessionId, info->rendererState);
        if (info->clientUID == ancoUid && (std::count(ALLOWED_ANCO_STREAM_USAGE.begin(),
            ALLOWED_ANCO_STREAM_USAGE.end(), info->rendererInfo.streamUsage) == 0)) {
            SLOGI("Anco invalid uid=%{public}d usage=%{public}d", info->clientUID, info->rendererInfo.streamUsage);
            continue;
        }
        if ((std::count(ALLOWED_MEDIA_STREAM_USAGE.begin(),
            ALLOWED_MEDIA_STREAM_USAGE.end(), info->rendererInfo.streamUsage) == 0)) {
            SLOGI("Media invalid uid=%{public}d usage=%{public}d", info->clientUID, info->rendererInfo.streamUsage);
            continue;
        }
        CHECK_AND_CONTINUE(info->clientPid != 0);
        {
            std::lock_guard lockGuard(stateLock_);
            std::pair<int32_t, int32_t> key = std::make_pair(info->clientUID, info->clientPid);
            auto it = currentStates_.find(key);
            if (it == currentStates_.end()) {
                currentStates_[key] = stopState;
            } else if (info->rendererState == AudioStandard::RendererState::RENDERER_RELEASED) {
                currentStates_.erase(it);
                continue;
            }

            if (info->rendererState == AudioStandard::RendererState::RENDERER_RUNNING) {
                currentStates_[key] = runningState;
                playingKey = key;
            }
            if (playingKey != key) {
                currentStates_[key] = stopState;
            }
        }
    }
    SLOGD("AudioRenderStateChange end");
}

void FocusSessionStrategy::HandleAudioRenderStateChangeEvent(const AudioRendererChangeInfos& infos)
{
    ProcAudioRenderChange(infos);
    std::pair<int32_t, int32_t> focusSessionKey = std::make_pair(-1, -1);
    std::pair<int32_t, int32_t> stopSessionKey = std::make_pair(-1, -1);
    {
        std::lock_guard lockGuard(stateLock_);
        for (auto it = currentStates_.begin(); it != currentStates_.end(); it++) {
            if (it->second == runningState) {
                if (IsFocusSession(it->first)) {
                    focusSessionKey = it->first;
                    continue;
                }
            } else {
                if (CheckFocusSessionStop(it->first)) {
                    stopSessionKey = it->first;
                }
            }
        }
    }
    if (focusSessionKey.first != -1 && focusSessionKey.second != -1) {
        UpdateFocusSession(focusSessionKey);
    }
    if (stopSessionKey.first != -1 && stopSessionKey.second != -1) {
        DelayStopFocusSession(stopSessionKey);
    }
}

bool FocusSessionStrategy::IsFocusSession(const std::pair<int32_t, int32_t> key)
{
    bool isFocus = false;
    auto it = lastStates_.find(key);
    if (it == lastStates_.end()) {
        isFocus = true;
    } else {
        isFocus = it->second != runningState;
    }

    lastStates_[key] = currentStates_[key];
    if (isFocus) {
        AVSessionEventHandler::GetInstance().AVSessionRemoveTask("CheckFocusStop" + std::to_string(key.second));
        HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "FOCUS_SESSION_UID", key.second,
            "AUDIO_INFO_RENDERER_STATE", AudioStandard::RendererState::RENDERER_RUNNING,
            "DETAILED_MSG", "focussessionstrategy selectfocussession, current focus session info");
        SLOGI("IsFocusSession uid=%{public}d isFocusTRUE", key.second);
    }
    return isFocus;
}

void FocusSessionStrategy::UpdateFocusSession(const std::pair<int32_t, int32_t> key)
{
    FocusSessionChangeInfo sessionInfo;
    sessionInfo.uid = key.first;
    sessionInfo.pid = key.second;
    if (selector_) {
        selector_(sessionInfo);
    }
    if (callback_) {
        callback_(sessionInfo, true);
    }
}

bool FocusSessionStrategy::CheckFocusSessionStop(const std::pair<int32_t, int32_t> key)
{
    bool isFocusStop = false;
    auto it = lastStates_.find(key);
    if (it == lastStates_.end()) {
        isFocusStop = false;
    } else {
        isFocusStop = it->second == runningState;
    }

    lastStates_[key] = currentStates_[key];
    if (isFocusStop) {
        SLOGI("CheckFocusSessionStop uid=%{public}d pid=%{public}d isFocusStopTRUE", key.first, key.second);
    }
    return isFocusStop;
}

void FocusSessionStrategy::DelayStopFocusSession(const std::pair<int32_t, int32_t> key)
{
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, key]() {
            {
                std::lock_guard lockGuard(stateLock_);
                SLOGE("DelayStopFocus uid=%{public}d lastState=%{public}d", key.first, lastStates_[key]);
                if (lastStates_[key] == AudioStandard::RendererState::RENDERER_RUNNING) {
                    return;
                }
            }
            FocusSessionChangeInfo changeInfo;
            changeInfo.uid = key.first;
            changeInfo.pid = key.second;
            if (callback_) {
                callback_(changeInfo, false);
            }
        }, "CheckFocusStop" + std::to_string(key.second), cancelTimeout);
}
}
