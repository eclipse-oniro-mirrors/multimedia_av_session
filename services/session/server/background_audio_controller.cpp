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

#include "background_audio_controller.h"
#include "avsession_log.h"
#include "avsession_service.h"
#include "avsession_item.h"
#include "permission_checker.h"

namespace OHOS::AVSession {
using AudioStandard::RendererState;

BackgroundAudioController::BackgroundAudioController() : ptr_(nullptr)
{
    SLOGI("construct");
}

BackgroundAudioController::~BackgroundAudioController()
{
    SLOGI("destroy");
}

void BackgroundAudioController::Init(AVSessionService *ptr)
{
    ptr_ = ptr;
    AudioAdapter::GetInstance().AddStreamRendererStateListener([this](const auto& infos) {
        HandleAudioStreamRendererStateChange(infos);
    });
    AppManagerAdapter::GetInstance().SetAppStateChangeObserver([this](int32_t uid, int32_t pid, bool isBackground) {
        SLOGI("set background observe for uid=%{public}d, pid=%{public}d, isBackground=%{public}d",
            uid, pid, isBackground);
        HandleAppMuteState(uid, pid, isBackground);
    });
}

void BackgroundAudioController::OnSessionCreate(const AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(lock_);
    sessionUIDs_.insert(descriptor.uid_);
    SLOGI("OnSessionCreate remove observe for uid %{public}d", descriptor.uid_);
    AppManagerAdapter::GetInstance().RemoveObservedApp(descriptor.uid_);
}

void BackgroundAudioController::OnSessionRelease(const AVSessionDescriptor& descriptor)
{
    {
        std::lock_guard lockGuard(lock_);
        sessionUIDs_.erase(descriptor.uid_);
    }

    if (descriptor.isThirdPartyApp_) {
        SLOGI("OnSessionRelease add observe for uid %{public}d", descriptor.uid_);
        AppManagerAdapter::GetInstance().AddObservedApp(descriptor.uid_);
        int32_t uid = descriptor.uid_;
        bool isRunning = AudioAdapter::GetInstance().GetRendererRunning(uid);
        if (!isRunning) {
            SLOGI("renderer state is not running when session release");
            return;
        }
        if (AppManagerAdapter::GetInstance().IsAppBackground(descriptor.uid_, descriptor.pid_)) {
            AudioAdapter::GetInstance().MuteAudioStream(descriptor.uid_);
            if (ptr_ != nullptr) {
                ptr_->NotifyAudioSessionCheckTrigger(descriptor.uid_);
            }
        }
    }
}

// LCOV_EXCL_START
void BackgroundAudioController::HandleAudioStreamRendererStateChange(const AudioRendererChangeInfos& infos)
{
    for (const auto& info : infos) {
        if (info->rendererState != AudioStandard::RENDERER_RUNNING) {
            continue;
        }
        if (PermissionChecker::GetInstance().CheckSystemPermissionByUid(info->clientUID)) {
            SLOGD("uid=%{public}d is system app", info->clientUID);
            continue;
        }
        SLOGI("AudioStreamRendererStateChange add observe for uid %{public}d", info->clientUID);
        AppManagerAdapter::GetInstance().AddObservedApp(info->clientUID);
        
        if (HasAVSession(info->clientUID)) {
            continue;
        }

        if (AppManagerAdapter::GetInstance().IsAppBackground(info->clientUID, info->clientPid)) {
            AudioAdapter::GetInstance().MuteAudioStream(info->clientUID);
            if (ptr_ != nullptr) {
                ptr_->NotifyAudioSessionCheckTrigger(info->clientUID);
            }
        } else {
            AudioAdapter::GetInstance().UnMuteAudioStream(info->clientUID);
        }
    }
}

void BackgroundAudioController::HandleAppMuteState(int32_t uid, int32_t pid, bool isBackground)
{
    if (PermissionChecker::GetInstance().CheckSystemPermissionByUid(uid)) {
        SLOGD("uid=%{public}d is system app", uid);
        return;
    }
    if (HasAVSession(uid)) {
        return;
    }

    if (isBackground) {
        std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> infos;
        auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(infos);
        if (ret != 0) {
            SLOGE("get renderer state failed");
            return;
        }
        bool isRunning = false;
        for (const auto& info : infos) {
            if (info->rendererState == AudioStandard::RENDERER_RUNNING &&
                (info->clientUID == uid and info->clientPid == pid)) {
                isRunning = true;
                break;
            }
        }
        if (!isRunning) {
            SLOGI("find uid=%{public}d pid=%{public}d isn't running, return", uid, pid);
            return;
        }
        SLOGI("mute uid=%{public}d", uid);
        AudioAdapter::GetInstance().MuteAudioStream(uid);
        if (ptr_ != nullptr) {
            ptr_->NotifyAudioSessionCheckTrigger(uid);
        }
    } else {
        SLOGI("unmute uid=%{public}d", uid);
        AudioAdapter::GetInstance().UnMuteAudioStream(uid);
    }
}
// LCOV_EXCL_STOP

bool BackgroundAudioController::IsBackgroundMode(int32_t creatorUid, BackgroundMode backgroundMode) const
{
    // LCOV_EXCL_START
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> continuousTaskList;
    ErrCode code = BackgroundTaskMgr::BackgroundTaskMgrHelper::GetContinuousTaskApps(continuousTaskList);
    if (code != OHOS::ERR_OK) {
        SLOGE("uid=%{public}d no continuous task list, code=%{public}d", creatorUid, code);
        return false;
    }
    // LCOV_EXCL_STOP

    for (const auto &task : continuousTaskList) {
        SLOGD("uid=%{public}d taskCreatorUid=%{public}d", creatorUid, task->GetCreatorUid());
        if (task->GetCreatorUid() != creatorUid) {
            continue;
        }

        std::vector<uint32_t> bgModeIds = task->GetTypeIds();
        auto it = std::find_if(bgModeIds.begin(), bgModeIds.end(), [ = ](auto mode) {
            uint32_t uMode = static_cast<uint32_t>(backgroundMode);
            return (mode == uMode);
        });
        if (it != bgModeIds.end()) {
            SLOGD("uid=%{public}d is audio playback", creatorUid);
            return true;
        }
    }
    SLOGD("uid=%{public}d isn't audio playback", creatorUid);
    return false;
}

bool BackgroundAudioController::HasAVSession(int32_t uid)
{
    std::lock_guard lockGuard(lock_);
    bool hasSession = false;
    auto it = sessionUIDs_.find(uid);
    if (it != sessionUIDs_.end()) {
        SLOGD("uid=%{public}d has av_session, no need to handle mute or unmute strategy.", uid);
        hasSession = true;
    }
    return hasSession;
}
}
