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
    FocusSessionChangeInfo focusSessionChangeInfo;
    if (SelectFocusSession(infos, focusSessionChangeInfo)) {
        if (callback_) {
            callback_(focusSessionChangeInfo, true);
        }
    }
}

bool FocusSessionStrategy::IsFocusSession(const AudioStandard::AudioRendererChangeInfo& info)
{
    if (info.rendererState == AudioStandard::RendererState::RENDERER_RUNNING) {
        std::lock_guard lockGuard(stateLock_);
        auto it = lastStates_.find(info.clientUID);
        if (it == lastStates_.end()) {
            return true;
        }
        if (it->second != AudioStandard::RendererState::RENDERER_RUNNING) {
            HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "FOCUS_SESSION_UID", info.clientUID,
                "AUDIO_INFO_CONTENT_TYPE", info.rendererInfo.contentType,
                "AUDIO_INFO_RENDERER_STATE", info.rendererState,
                "DETAILED_MSG", "focussessionstrategy selectfocussession, last focus session info");
            return true;
        }
    }
    return false;
}

void FocusSessionStrategy::CheckFocusSessionStop(const AudioStandard::AudioRendererChangeInfo& info)
{
    std::lock_guard lockGuard(stateLock_);
    if (info.rendererState != AudioStandard::RendererState::RENDERER_RUNNING &&
        lastStates_[info.clientUID] == AudioStandard::RendererState::RENDERER_RUNNING) {
        int32_t uid = info.clientUID;
        AVSessionEventHandler::GetInstance().AVSessionPostTask(
            [this, uid]() {
                SLOGI("check uid=%{public}d lastState=%{public}d", uid, lastStates_[uid]);
                if (lastStates_[uid] == AudioStandard::RendererState::RENDERER_RUNNING) {
                    return;
                }
                FocusSessionChangeInfo changeInfo;
                changeInfo.uid = uid;
                if (callback_) {
                    callback_(changeInfo, false);
                }
            }, "CheckFocusStop", cancelTimeout);
    }
}

bool FocusSessionStrategy::SelectFocusSession(const AudioRendererChangeInfos& infos,
                                              FocusSessionChangeInfo& sessionInfo)
{
    for (const auto& info : infos) {
        CheckFocusSessionStop(*info);
        if (!IsFocusSession(*info)) {
            std::lock_guard lockGuard(stateLock_);
            lastStates_[info->clientUID] = info->rendererState;
            HISYSEVENT_SET_AUDIO_STATUS(info->clientUID, info->rendererState);
            continue;
        }
        {
            std::lock_guard lockGuard(stateLock_);
            HISYSEVENT_SET_AUDIO_STATUS(info->clientUID, info->rendererState);
            lastStates_[info->clientUID] = info->rendererState;
        }
        SLOGD("SelectFocusSession check uid=%{public}d state=%{public}d", info->clientUID, info->rendererState);
        sessionInfo.uid = info->clientUID;
        sessionInfo.streamUsage = info->rendererInfo.streamUsage;
        if (selector_ != nullptr && !selector_(sessionInfo)) {
            continue;
        }
        SLOGI("uid=%{public}d is focus session", sessionInfo.uid);
        HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "FOCUS_SESSION_UID", sessionInfo.uid, "AUDIO_INFO_CONTENT_TYPE",
            info->rendererInfo.contentType, "AUDIO_INFO_RENDERER_STATE", info->rendererState,
            "DETAILED_MSG", "focussessionstrategy selectfocussession, current focus session info");
        return true;
    }
    return false;
}
}
