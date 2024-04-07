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
    AppManagerAdapter::GetInstance().SetAppBackgroundStateObserver([this](int32_t uid) {
        SLOGI("set background observe for uid %{public}d", uid);
        HandleAppBackgroundState(uid);
    });
}

void BackgroundAudioController::OnSessionCreate(const AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(lock_);
    sessionUIDs_.insert(descriptor.uid_);
    AppManagerAdapter::GetInstance().RemoveObservedApp(descriptor.uid_);
    SLOGI("OnSessionCreate remove observe for uid %{public}d", descriptor.uid_);
}

void BackgroundAudioController::OnSessionRelease(const AVSessionDescriptor& descriptor)
{
    {
        std::lock_guard lockGuard(lock_);
        sessionUIDs_.erase(descriptor.uid_);
    }

    if (descriptor.isThirdPartyApp_) {
        if (!AppManagerAdapter::GetInstance().IsAppBackground(descriptor.uid_)) {
            AppManagerAdapter::GetInstance().AddObservedApp(descriptor.uid_);
            SLOGI("OnSessionRelease add observe for uid %{public}d", descriptor.uid_);
            return;
        }
        int32_t uid = descriptor.uid_;
        AudioStandard::RendererState rendererState = AudioStandard::RENDERER_PAUSED;
        bool isSuccess = AudioAdapter::GetInstance().GetRendererState(uid, rendererState);
        if (isSuccess && rendererState != AudioStandard::RENDERER_RUNNING) {
            SLOGI("renderer state is not AudioStandard::RENDERER_RUNNING");
            return;
        }
        SLOGI("pause uid=%{public}d", descriptor.uid_);
        ptr_->NotifyAudioSessionCheckTrigger(descriptor.uid_);
        AudioAdapter::GetInstance().PauseAudioStream(descriptor.uid_);
    }
}

void BackgroundAudioController::HandleAudioStreamRendererStateChange(const AudioRendererChangeInfos& infos)
{
    for (const auto& info : infos) {
        if (info->rendererState != AudioStandard::RENDERER_RUNNING) {
            continue;
        }
        if (!AppManagerAdapter::GetInstance().IsAppBackground(info->clientUID)) {
            AppManagerAdapter::GetInstance().AddObservedApp(info->clientUID);
            SLOGD("AudioStreamRendererStateChange add observe for uid %{public}d", info->clientUID);
            continue;
        }
        if (info->rendererInfo.streamUsage == StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION) {
            SLOGD("uid=%{public}d is voip app", info->clientUID);
            HandleVoIPAppBackgroundState(info->clientUID);
            continue;
        }

        if (HasAVSession(info->clientUID)) {
            continue;
        }

        if (PermissionChecker::GetInstance().CheckSystemPermissionByUid(info->clientUID)) {
            SLOGD("uid=%{public}d is system app", info->clientUID);
            continue;
        }

        SLOGI("pause uid=%{public}d", info->clientUID);
        ptr_->NotifyAudioSessionCheckTrigger(info->clientUID);
        AudioAdapter::GetInstance().PauseAudioStream(info->clientUID);
    }
}

void BackgroundAudioController::HandleAppBackgroundState(int32_t uid)
{
    std::vector<std::unique_ptr<AudioStandard::AudioRendererChangeInfo>> infos;
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(infos);
    if (ret != 0) {
        SLOGE("get renderer state failed");
        return;
    }

    bool isRunning = false;
    bool isVoIP = false;
    for (const auto& info : infos) {
        if (info->clientUID == uid) {
            SLOGD("find uid=%{public}d", info->clientUID);
            if (info->rendererState == AudioStandard::RENDERER_RUNNING) {
                isRunning = true;
            }
            if (info->rendererInfo.streamUsage == StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION) {
                isVoIP = true;
            }
            break;
        }
    }

    if (!isRunning) {
        SLOGD("uid=%{public}d isn't renderer running", uid);
        return;
    }

    if (isVoIP) {
        SLOGD("uid=%{public}d is voip app", uid);
        HandleVoIPAppBackgroundState(uid);
        return;
    }

    if (HasAVSession(uid)) {
        return;
    }

    SLOGI("pause uid=%{public}d", uid);
    ptr_->NotifyAudioSessionCheckTrigger(uid);
    AudioAdapter::GetInstance().PauseAudioStream(uid);
}

void BackgroundAudioController::HandleVoIPAppBackgroundState(int32_t uid)
{
    if (HasAVSession(uid) && IsBackgroundMode(uid, BackgroundMode::AUDIO_PLAYBACK)) {
        return;
    }

    SLOGI("pause uid=%{public}d", uid);
    ptr_->NotifyAudioSessionCheckTrigger(uid);
    AudioAdapter::GetInstance().PauseAudioStream(uid, AudioStandard::AudioStreamType::STREAM_VOICE_COMMUNICATION);
}

bool BackgroundAudioController::IsBackgroundMode(int32_t creatorUid, BackgroundMode backgroundMode) const
{
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> continuousTaskList;
    ErrCode code = BackgroundTaskMgr::BackgroundTaskMgrHelper::GetContinuousTaskApps(continuousTaskList);
    if (code != OHOS::ERR_OK) {
        SLOGE("uid=%{public}d no continuous task list, code=%{public}d", creatorUid, code);
        return false;
    }

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
    bool hasSession = false;
    {
        std::lock_guard lockGuard(lock_);
        auto it = sessionUIDs_.find(uid);
        if (it != sessionUIDs_.end()) {
            SLOGD("uid=%{public}d has session", uid);
            hasSession = true;
        }
    }
    return hasSession;
}
}
