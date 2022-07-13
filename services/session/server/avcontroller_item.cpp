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

#include "avcontroller_item.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
AVControllerItem::AVControllerItem(pid_t pid, sptr<AVSessionItem> &session)
    : pid_(pid), session_(session)
{
    sessionId_ = session_->GetSessionId();
    SLOGI("construct sessionId=%{public}s", sessionId_.c_str());
}

AVControllerItem::~AVControllerItem()
{
    SLOGI("destroy sessionId=%{public}s", sessionId_.c_str());
}

int32_t AVControllerItem::RegisterCallbackInner(const sptr<IRemoteObject> &callback)
{
    callback_ = iface_cast<AVControllerCallbackProxy>(callback);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetAVPlaybackState(AVPlaybackState &state)
{
    if (session_ == nullptr) {
        SLOGI("session not exist");
        return ERR_SESSION_NOT_EXIST;
    }
    state = session_->GetPlaybackState();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetAVMetaData(AVMetaData &data)
{
    if (session_ == nullptr) {
        SLOGI("session not exist");
        return ERR_SESSION_NOT_EXIST;
    }
    data = session_->GetMetaData();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SendAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    if (session_ == nullptr) {
        SLOGI("session not exist");
        return ERR_SESSION_NOT_EXIST;
    }
    AVSessionTrace trace("AVControllerItem::SendAVKeyEvent");
    session_->HandleMediaKeyEvent(keyEvent);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent &ability)
{
    if (session_ == nullptr) {
        SLOGI("session not exist");
        return ERR_SESSION_NOT_EXIST;
    }
    ability = session_->GetLaunchAbility();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetValidCommands(std::vector<int32_t> &cmds)
{
    if (session_ == nullptr) {
        SLOGI("session not exist");
        return ERR_SESSION_NOT_EXIST;
    }
    cmds = session_->GetSupportCommand();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::IsSessionActive(bool &isActive)
{
    if (session_ == nullptr) {
        SLOGI("session not exist");
        return ERR_SESSION_NOT_EXIST;
    }
    isActive = session_->IsActive();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SendControlCommand(const AVControlCommand &cmd)
{
    if (session_ == nullptr) {
        SLOGI("session not exist");
        return ERR_SESSION_NOT_EXIST;
    }
    AVSessionTrace trace("AVControllerItem::SendControlCommand");
    std::vector<int32_t> cmds = session_->GetSupportCommand();
    if (std::find(cmds.begin(), cmds.end(), cmd.GetCommand()) == cmds.end()) {
        SLOGI("command not support");
        return ERR_COMMAND_NOT_SUPPORT;
    }
    session_->ExecuteControllerCommand(cmd);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SetMetaFilter(const AVMetaData::MetaMaskType &filter)
{
    metaMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType &filter)
{
    playbackMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::Destroy()
{
    if (callback_ != nullptr) {
        callback_ = nullptr;
    }
    if (session_ != nullptr) {
        session_->HandleControllerRelease(pid_);
        session_ = nullptr;
        sessionId_.clear();
    }
    if (serviceCallback_) {
        serviceCallback_(*this);
    }
    return AVSESSION_SUCCESS;
}

std::string AVControllerItem::GetSessionId()
{
    return sessionId_;
}

void AVControllerItem::HandleSessionDestroy()
{
    if (callback_ != nullptr) {
        AVSessionTrace trace("AVControllerItem::OnSessionDestroy");
        callback_->OnSessionDestroy();
    }
    if (session_ != nullptr) {
        session_ = nullptr;
    }
    sessionId_.clear();
}

void AVControllerItem::HandlePlaybackStateChange(const AVPlaybackState &state)
{
    if (callback_ == nullptr) {
        return;
    }
    AVPlaybackState stateOut;
    if (state.CopyToByMask(playbackMask_, stateOut)) {
        SLOGI("update playback state");
        AVSessionTrace trace("AVControllerItem::OnPlaybackStateChange");
        callback_->OnPlaybackStateChange(stateOut);
    }
}

void AVControllerItem::HandleMetaDataChange(const AVMetaData &data)
{
    if (callback_ == nullptr) {
        return;
    }
    AVMetaData metaOut;
    if (data.CopyToByMask(metaMask_, metaOut)) {
        SLOGI("update meta data");
        AVSessionTrace trace("AVControllerItem::OnMetaDataChange");
        callback_->OnMetaDataChange(metaOut);
    }
}

void AVControllerItem::HandleActiveStateChange(bool isActive)
{
    if (callback_ != nullptr) {
        AVSessionTrace trace("AVControllerItem::OnActiveStateChange");
        callback_->OnActiveStateChange(isActive);
    }
}

void AVControllerItem::HandleValidCommandChange(const std::vector<int32_t> &cmds)
{
    if (callback_ != nullptr) {
        AVSessionTrace trace("AVControllerItem::OnValidCommandChange");
        callback_->OnValidCommandChange(cmds);
    }
}

pid_t AVControllerItem::GetPid() const
{
    return pid_;
}

bool AVControllerItem::HasSession(const std::string& sessionId)
{
    return sessionId_ == sessionId;
}

void AVControllerItem::SetServiceCallbackForRelease(const std::function<void(AVControllerItem &)> &callback)
{
    serviceCallback_ = callback;
}
} // OHOS::AVSession