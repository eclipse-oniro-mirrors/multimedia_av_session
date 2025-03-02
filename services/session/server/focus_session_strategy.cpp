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

void FocusSessionStrategy::HandleAudioRenderStateChangeEvent(const AudioRendererChangeInfos& infos)
{
    SLOGD("AudioRenderStateChange start");
    int32_t playingUid = -1;
    for (const auto& info : infos) {
        SLOGD("AudioRenderStateChange uid=%{public}d sessionId=%{public}d state=%{public}d",
            info->clientUID, info->sessionId, info->rendererState);
        {
            std::lock_guard lockGuard(stateLock_);
            auto it = currentStates_.find(info->clientUID);
            if (it == currentStates_.end()) {
                currentStates_[info->clientUID] = stopState;
            } else if (info->rendererState == AudioStandard::RendererState::RENDERER_RELEASED) {
                currentStates_.erase(it);
                continue;
            }

            if (info->rendererState == AudioStandard::RendererState::RENDERER_RUNNING) {
                currentStates_[info->clientUID] = runningState;
                playingUid = info->clientUID;
            }
            if (playingUid != info->clientUID) {
                currentStates_[info->clientUID] = stopState;
            }
        }
    }
    SLOGD("AudioRenderStateChange end");

    int32_t focusSessionUid = -1;
    int32_t stopSessionUid = -1;
    {
        std::lock_guard lockGuard(stateLock_);
        for (auto it = currentStates_.begin(); it != currentStates_.end(); it++) {
            if (it->second == runningState) {
                if (IsFocusSession(it->first)) {
                    focusSessionUid = it->first;
                    continue;
                }
            } else {
                if (CheckFocusSessionStop(it->first)) {
                    stopSessionUid = it->first;
                }
            }
        }
    }

    if (focusSessionUid != -1) {
        UpdateFocusSession(focusSessionUid);
    }

    if (stopSessionUid != -1) {
        DelayStopFocusSession(stopSessionUid);
    }
}

bool FocusSessionStrategy::IsFocusSession(const int32_t uid)
{
    bool isFocus = false;
    auto it = lastStates_.find(uid);
    if (it == lastStates_.end()) {
        isFocus = true;
    } else {
        isFocus = it->second != runningState;
    }

    lastStates_[uid] = currentStates_[uid];
    if (isFocus) {
        AVSessionEventHandler::GetInstance().AVSessionRemoveTask("CheckFocusStop" + std::to_string(uid));
        HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "FOCUS_SESSION_UID", uid,
            "AUDIO_INFO_RENDERER_STATE", AudioStandard::RendererState::RENDERER_RUNNING,
            "DETAILED_MSG", "focussessionstrategy selectfocussession, current focus session info");
    }
    SLOGI("IsFocusSession uid=%{public}d isFocus=%{public}d", uid, isFocus);
    return isFocus;
}

void FocusSessionStrategy::UpdateFocusSession(const int32_t uid)
{
    FocusSessionChangeInfo sessionInfo;
    sessionInfo.uid = uid;
    if (selector_) {
        selector_(sessionInfo);
    }
    if (callback_) {
        callback_(sessionInfo, true);
    }
}

bool FocusSessionStrategy::CheckFocusSessionStop(const int32_t uid)
{
    bool isFocusStop = false;
    auto it = lastStates_.find(uid);
    if (it == lastStates_.end()) {
        isFocusStop = true;
    } else {
        isFocusStop = it->second == runningState;
    }

    lastStates_[uid] = currentStates_[uid];
    SLOGI("CheckFocusSessionStop uid=%{public}d isFocusStop=%{public}d", uid, isFocusStop);
    return isFocusStop;
}

void FocusSessionStrategy::DelayStopFocusSession(const int32_t uid)
{
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this, uid]() {
            {
                std::lock_guard lockGuard(stateLock_);
                SLOGI("CheckFocusStop uid=%{public}d lastState=%{public}d", uid, lastStates_[uid]);
                if (lastStates_[uid] == AudioStandard::RendererState::RENDERER_RUNNING) {
                    return;
                }
            }
            FocusSessionChangeInfo changeInfo;
            changeInfo.uid = uid;
            if (callback_) {
                callback_(changeInfo, false);
            }
        }, "CheckFocusStop" + std::to_string(uid), cancelTimeout);
}
}
