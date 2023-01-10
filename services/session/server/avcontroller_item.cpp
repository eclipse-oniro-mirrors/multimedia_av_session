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
#include "ipc_skeleton.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "command_send_limit.h"
#include "avsession_utils.h"
#include "permission_checker.h"
#include "avsession_sysevent.h"
#include "want_params.h"

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

namespace OHOS::AVSession {
AVControllerItem::AVControllerItem(pid_t pid, const sptr<AVSessionItem>& session)
    : pid_(pid), session_(session)
{
    sessionId_ = session_->GetSessionId();
    SLOGD("construct sessionId=%{public}s", sessionId_.c_str());
}

AVControllerItem::~AVControllerItem()
{
#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#if defined(__BIONIC__)
    mallopt(M_PURGE, 0);
#endif
#endif
}

int32_t AVControllerItem::RegisterCallbackInner(const sptr<IRemoteObject>& callback)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("RegisterCallbackInner: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller registercallbackinner checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    callback_ = iface_cast<AVControllerCallbackProxy>(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, AVSESSION_ERROR, "callback_ is nullptr");
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetAVPlaybackState(AVPlaybackState& state)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("GetAVPlaybackState: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller getavplaybackstate checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    state = session_->GetPlaybackState();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetAVMetaData(AVMetaData& data)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("GetAVMetaData: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller getavmetadata checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    data = session_->GetMetaData();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SendAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("SendAVKeyEvent: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller sendavkeyevent checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    session_->HandleMediaKeyEvent(keyEvent);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent& ability)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("GetLaunchAbility: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller getlaunchability checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    ability = session_->GetLaunchAbility();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetValidCommands(std::vector<int32_t>& cmds)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("GetValidCommands: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller getvalidcommands checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    cmds = session_->GetSupportCommand();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::IsSessionActive(bool& isActive)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("IsSessionActive: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller issessionactive checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    isActive = session_->IsActive();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SendControlCommand(const AVControlCommand& cmd)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("SendControlCommand: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller sendcontrolcommand checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    std::vector<int32_t> cmds = session_->GetSupportCommand();
    CHECK_AND_RETURN_RET_LOG(std::find(cmds.begin(), cmds.end(), cmd.GetCommand()) != cmds.end(),
                             ERR_COMMAND_NOT_SUPPORT, "command not support");
    CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(OHOS::IPCSkeleton::GetCallingPid()),
        ERR_COMMAND_SEND_EXCEED_MAX, "command send number exceed max");
    session_->ExecuteControllerCommand(cmd);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SetMetaFilter(const AVMetaData::MetaMaskType& filter)
{
    metaMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter)
{
    playbackMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::Destroy()
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("Destroy: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "SESSION_ID", sessionId_,
                            "ERROR_MSG", "controller destroy checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    callback_ = nullptr;
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
        callback_->OnSessionDestroy();
    }
    session_ = nullptr;
    sessionId_.clear();
}

void AVControllerItem::HandlePlaybackStateChange(const AVPlaybackState& state)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVPlaybackState stateOut;
    if (state.CopyToByMask(playbackMask_, stateOut)) {
        SLOGI("update playback state");
        AVSESSION_TRACE_SYNC_START("AVControllerItem::OnPlaybackStateChange");
        callback_->OnPlaybackStateChange(stateOut);
    }
}

void AVControllerItem::HandleMetaDataChange(const AVMetaData& data)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVMetaData metaOut;
    if (data.CopyToByMask(metaMask_, metaOut)) {
        if ((metaMask_.test(AVMetaData::META_KEY_MEDIA_IMAGE)) && (metaOut.GetMediaImage() != nullptr)) {
            std::string fileName = AVSessionUtils::GetCachePathName() + sessionId_ + AVSessionUtils::GetFileSuffix();
            std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaOut.GetMediaImage();
            AVSessionUtils::ReadImageFromFile(innerPixelMap, fileName);
            metaOut.SetMediaImage(innerPixelMap);
        }
        SLOGI("update meta data");
        AVSESSION_TRACE_SYNC_START("AVControllerItem::OnMetaDataChange");
        callback_->OnMetaDataChange(metaOut);
    }
}

void AVControllerItem::HandleOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnOutputDeviceChange(outputDeviceInfo);
}

void AVControllerItem::HandleActiveStateChange(bool isActive)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnActiveStateChange(isActive);
}

void AVControllerItem::HandleValidCommandChange(const std::vector<int32_t>& cmds)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnValidCommandChange(cmds);
}

void AVControllerItem::HandleSetSessionEvent(const std::string& event, const AAFwk::WantParams& args)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnSessionEventChange");
    callback_->OnSessionEventChange(event, args);
}

pid_t AVControllerItem::GetPid() const
{
    return pid_;
}

bool AVControllerItem::HasSession(const std::string& sessionId)
{
    return sessionId_ == sessionId;
}

void AVControllerItem::SetServiceCallbackForRelease(const std::function<void(AVControllerItem&)>& callback)
{
    serviceCallback_ = callback;
}
} // OHOS::AVSession