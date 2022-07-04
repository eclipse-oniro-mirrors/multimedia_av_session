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

#include "avsession_item.h"
#include "avsession_service.h"
#include "avcontroller_item.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_descriptor.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
AVSessionItem::AVSessionItem(const AVSessionDescriptor& descriptor)
    : descriptor_(descriptor)
{
    SLOGI("constructor id=%{public}d", descriptor_.sessionId_);
}

AVSessionItem::~AVSessionItem()
{
    SLOGI("destroy id=%{public}d", descriptor_.sessionId_);
}

int32_t AVSessionItem::GetSessionId()
{
    return descriptor_.sessionId_;
}

int32_t AVSessionItem::Destroy()
{
    AVSessionTrace avSessionTrace("AVSessionItem::Destroy");
    if (callback_) {
        callback_.clear();
    }

    SLOGI("size=%{public}d", static_cast<int>(controllers_.size()));
    {
        std::lock_guard lockGuard(lock_);
        for (auto it = controllers_.begin(); it != controllers_.end();) {
            SLOGI("pid=%{public}d", it->first);
            it->second->HandleSessionDestory();
            controllers_.erase(it++);
        }
    }

    if (serviceCallback_) {
        serviceCallback_(*this);
    }
    SLOGI("Destroy success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVMetaData(AVMetaData& meta)
{
    meta = metaData_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVMetaData(const AVMetaData& meta)
{
    AVSessionTrace avSessionTrace("AVSessionItem::SetAVMetaData");
    if (!metaData_.CopyFrom(meta)) {
        SLOGI("AVMetaData set error");
        return AVSESSION_ERROR;
    }
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        controller->HandleMetaDataChange(meta);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVPlaybackState(const AVPlaybackState& state)
{
    AVSessionTrace avSessionTrace("AVSessionItem::SetAVPlaybackState");
    if (!playbackState_.CopyFrom(state)) {
        SLOGI("AVMetaData set error");
        return AVSESSION_ERROR;
    }
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{public}d", pid);
        controller->HandlePlaybackStateChange(state);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVPlaybackState(AVPlaybackState& state)
{
    AVSessionTrace avSessionTrace("AVSessionItem::GetAVPlaybackState");
    state = playbackState_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    launchAbility_ = ability;
    return AVSESSION_SUCCESS;
}

sptr<IRemoteObject> AVSessionItem::GetControllerInner()
{
    AVSessionTrace avSessionTrace("AVSessionItem::GetControllerInner");
    std::lock_guard lockGuard(lock_);
    auto iter = controllers_.find(GetPid());
    if (iter == controllers_.end()) {
        return nullptr;
    }
    return iter->second;
}

int32_t AVSessionItem::RegisterCallbackInner(const sptr<IAVSessionCallback> &callback)
{
    callback_ = callback;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::Activate()
{
    AVSessionTrace avSessionTrace("AVSessionItem::Activate");
    descriptor_.isActive_ = true;
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleActiveStateChange(true);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::Deactivate()
{
    AVSessionTrace avSessionTrace("AVSessionItem::Deactivate");
    descriptor_.isActive_ = false;
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleActiveStateChange(false);
    }
    return AVSESSION_SUCCESS;
}

bool AVSessionItem::IsActive()
{
    return descriptor_.isActive_;
}

int32_t AVSessionItem::AddSupportCommand(int32_t cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::AddSupportCommand");
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    auto iter = std::find(supportedCmd_.begin(), supportedCmd_.end(), cmd);
    CHECK_AND_RETURN_RET_LOG(iter == supportedCmd_.end(), AVSESSION_SUCCESS, "cmd already been added");
    supportedCmd_.push_back(cmd);
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleValidCommandChange(supportedCmd_);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::DeleteSupportCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    std::remove(supportedCmd_.begin(), supportedCmd_.end(), cmd);
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleValidCommandChange(supportedCmd_);
    }
    return AVSESSION_SUCCESS;
}

AVSessionDescriptor AVSessionItem::GetDescriptor()
{
    return descriptor_;
}

AVPlaybackState AVSessionItem::GetPlaybackState()
{
    return playbackState_;
}

AVMetaData AVSessionItem::GetMetaData()
{
    return metaData_;
}

std::vector<int32_t> AVSessionItem::GetSupportCommand()
{
    return supportedCmd_;
}

AbilityRuntime::WantAgent::WantAgent AVSessionItem::GetLaunchAbility()
{
    return launchAbility_;
}

void AVSessionItem::HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSessionTrace avSessionTrace("AVSessionItem::MediaKeyEvent");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnMediaKeyEvent(keyEvent);
}

void AVSessionItem::ExecuteControllerCommand(const AVControlCommand& cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::ExecuteControllerCommand");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int32_t code = cmd.GetCommand();
    if (code >= 0 && code < SESSION_CMD_MAX) {
        return (this->*cmdHandlers[code])(cmd);
    }
}

void AVSessionItem::HandleOnPlay(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnPlay");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlay();
}

void AVSessionItem::HandleOnPause(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnPause");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPause();
}

void AVSessionItem::HandleOnStop(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnStop");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnStop();
}

void AVSessionItem::HandleOnPlayNext(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnPlayNext");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayNext();
}

void AVSessionItem::HandleOnPlayPrevious(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnPlayPrevious");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayPrevious();
}

void AVSessionItem::HandleOnFastForward(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnFastForward");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnFastForward();
}

void AVSessionItem::HandleOnRewind(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnRewind");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnRewind();
}

void AVSessionItem::HandleOnSeek(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnSeek");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int64_t time = 0;
    CHECK_AND_RETURN_LOG(cmd.GetSeekTime(time) == AVSESSION_SUCCESS, "GetSeekTime failed");
    callback_->OnSeek(time);
}

void AVSessionItem::HandleOnSetSpeed(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnSetSpeed");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    double speed = 0.0;
    CHECK_AND_RETURN_LOG(cmd.GetSpeed(speed) == AVSESSION_SUCCESS, "GetSpeed failed");
    callback_->OnSetSpeed(speed);
}

void AVSessionItem::HandleOnSetLoopMode(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnSetLoopMode");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int32_t loopMode = AVSESSION_ERROR;
    CHECK_AND_RETURN_LOG(cmd.GetLoopMode(loopMode) == AVSESSION_SUCCESS, "GetLoopMode failed");
    callback_->OnSetLoopMode(loopMode);
}

void AVSessionItem::HandleOnToggleFavorite(const AVControlCommand &cmd)
{
    AVSessionTrace avSessionTrace("AVSessionItem::OnToggleFavorite");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::string assetId;
    CHECK_AND_RETURN_LOG(cmd.GetAssetId(assetId) == AVSESSION_SUCCESS, "GetMediaId failed");
    callback_->OnToggleFavorite(assetId);
}

int32_t AVSessionItem::AddController(pid_t pid, sptr<AVControllerItem>& contoller)
{
    AVSessionTrace avSessionTrace("AVSessionItem::AddController");
    std::lock_guard lockGuard(lock_);
    controllers_.insert({ pid, contoller });
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::RegisterCallbackForRemote(std::shared_ptr<AVSessionCallback>& callback)
{
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::UnRegisterCallbackForRemote()
{
    return AVSESSION_SUCCESS;
}

void AVSessionItem::SetPid(pid_t pid)
{
    pid_ = pid;
}

void AVSessionItem::SetUid(uid_t uid)
{
    uid_ = uid;
}

pid_t AVSessionItem::GetPid() const
{
    return pid_;
}

uid_t  AVSessionItem::GetUid()
{
    return uid_;
}

void AVSessionItem::SetTop(bool top)
{
    descriptor_.isTopSession_ = top;
}

void AVSessionItem::HandleControllerRelease(pid_t pid)
{
    AVSessionTrace avSessionTrace("AVSessionItem::HandleControllerRelease");
    std::lock_guard lockGuard(lock_);
    controllers_.erase(pid);
}

void AVSessionItem::SetServiceCallbackForRelease(const std::function<void(AVSessionItem &)> &callback)
{
    serviceCallback_ = callback;
}
} // namespace OHOS::AVSession