/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

namespace OHOS::AVSession {
AVSessionItem::AVSessionItem(const AVSessionDescriptor& descriptor)
    : descriptor_(descriptor)
{
    SLOGD("constructor id=%{public}d", descriptor_.sessionId_);
}

AVSessionItem::~AVSessionItem()
{
    SLOGD("destroy id=%{public}d", descriptor_.sessionId_);
}

int32_t AVSessionItem::GetSessionId()
{
    return descriptor_.sessionId_;
}

int32_t AVSessionItem::Release()
{
    SLOGD("enter");
    for (const auto& [pid, controller] : controllers_) {
        controller->HandleSessionRelease(descriptor_);
    }
    if (serviceCallback_) {
        serviceCallback_(*this);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVMetaData(AVMetaData& meta)
{
    meta = metaData_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVMetaData(const AVMetaData& meta)
{
    for (const auto& [pid, controller] : controllers_) {
        controller->HandleMetaDataChange(meta);
    }
    metaData_.CopyFrom(meta);
    return AVSESSION_SUCCESS;
}

int32_t  AVSessionItem::SetAVPlaybackState(const AVPlaybackState& state)
{
    for (const auto& [pid, controller] : controllers_) {
        controller->HandlePlaybackStateChange(state);
    }
    playbackState_ = state;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVPlaybackState(AVPlaybackState& state)
{
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
    auto iter = controllers_.find(GetPid());
    if(iter == controllers_.end()) {
        return nullptr;
    }
    return iter->second;
}

int32_t AVSessionItem::RegisterCallbackInner(const sptr<IAVSessionCallback> &callback)
{
    callback_ = callback;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::Active()
{
    for (const auto& [pid, controller] : controllers_) {
        controller->HandleActiveStateChange(true);
    }
    descriptor_.isActive_ = true;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::Disactive()
{
    for (const auto& [pid, controller] : controllers_) {
        controller->HandleActiveStateChange(false);
    }
    descriptor_.isActive_ = false;
    return AVSESSION_SUCCESS;
}

bool AVSessionItem::IsActive()
{
    return descriptor_.isActive_;
}

int32_t AVSessionItem::AddSupportCommand(const int32_t cmd)
{
    supportedCmd_.push_back(cmd);
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

void AVSessionItem::HandleMediaButtonEvent(const MMI::KeyEvent& keyEvent)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnMediaKeyEvent(keyEvent);
}

void AVSessionItem::ExecuteControllerCommand(const AVControlCommand& cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int32_t code = cmd.GetCommand();
    if (code >= 0 && code < SESSION_CMD_MAX) {
        return (this->*cmdHandlers[code])(cmd);
    }
}

void AVSessionItem::HandleOnPlay(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlay();
}

void AVSessionItem::HandleOnPause(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPause();
}

void AVSessionItem::HandleOnStop(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnStop();
}

void AVSessionItem::HandleOnPlayNext(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayNext();
}

void AVSessionItem::HandleOnPlayPrevious(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayPrevious();
}

void AVSessionItem::HandleOnFastForward(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnFastForward();
}

void AVSessionItem::HandleOnRewind(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnRewind();
}

void AVSessionItem::HandleOnSeek(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int64_t time = AVSESSION_ERROR;
    CHECK_AND_RETURN_LOG(cmd.GetSeekTime(time) == AVSESSION_SUCCESS, "GetSeekTime failed");
    callback_->OnSeek(time);
}

void AVSessionItem::HandleOnSetSpeed(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    float speed = AVSESSION_ERROR;
    CHECK_AND_RETURN_LOG(cmd.GetSpeed(speed) == AVSESSION_SUCCESS, "GetSpeed failed");
    callback_->OnSetSpeed(speed);
}

void AVSessionItem::HandleOnSetLoopMode(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int32_t loopMode = AVSESSION_ERROR;
    CHECK_AND_RETURN_LOG(cmd.GetLoopMode(loopMode) == AVSESSION_SUCCESS, "GetLoopMode failed");
    callback_->OnSetLoopMode(loopMode);
}

void AVSessionItem::HandleOnToggleFavorite(const AVControlCommand &cmd)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::string mediaId;
    CHECK_AND_RETURN_LOG(cmd.GetMediaId(mediaId) == AVSESSION_SUCCESS, "GetMediaId failed");
    callback_->OnToggleFavorite(mediaId);
}

int32_t AVSessionItem::AddController(pid_t pid, sptr<AVControllerItem>& contoller)
{
    controllers_.insert({ pid, contoller });
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::RemoveController(pid_t pid)
{
    controllers_.erase(pid);
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

void AVSessionItem::SetServiceCallbackForRelease(const std::function<void(AVSessionItem &)> &callback)
{
    serviceCallback_ = callback;
}
} // namespace OHOS::AVSession