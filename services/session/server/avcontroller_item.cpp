/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
AVControllerItem::AVControllerItem(pid_t pid, const sptr<AVSessionItem>& session, int32_t userId)
    : pid_(pid), session_(session), userId_(userId)
{
    sessionId_ = session_->GetSessionId();
    SLOGI("construct sessionId=%{public}s, pid=%{public}d, userId=%{public}d",
        AVSessionUtils::GetAnonySessionId(sessionId_).c_str(), static_cast<int>(pid_), userId_);
}

AVControllerItem::~AVControllerItem()
{
    SLOGI("destroy sessionId=%{public}s, pid=%{public}d, userId=%{public}d",
        AVSessionUtils::GetAnonySessionId(sessionId_).c_str(), static_cast<int>(pid_), userId_);
}

int32_t AVControllerItem::GetUserId() const
{
    return userId_;
}

int32_t AVControllerItem::RegisterCallbackInner(const sptr<IRemoteObject>& callback)
{
    std::lock_guard lockGuard(callbackMutex_);
    SLOGD("do register callback for controller %{public}d", static_cast<int>(pid_));
    callback_ = iface_cast<AVControllerCallbackProxy>(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, AVSESSION_ERROR, "RegisterCallbackInner callback_ is nullptr");
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::RegisterAVControllerCallback(const std::shared_ptr<AVControllerCallback> &callback)
{
    std::lock_guard lockGuard(callbackMutex_);
    innerCallback_ = callback;
    CHECK_AND_RETURN_RET_LOG(innerCallback_ != nullptr, AVSESSION_ERROR, "RegisterCallbackInner callback_ is nullptr");
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetAVCallMetaData(AVCallMetaData& avCallMetaData)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    avCallMetaData = session_->GetAVCallMetaData();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetAVCallState(AVCallState& avCallState)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    avCallState = session_->GetAVCallState();
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControllerItem::GetAVPlaybackState(AVPlaybackState& state)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    state = session_->GetPlaybackState();
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControllerItem::GetAVMetaData(AVMetaData& data)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    data = session_->GetMetaData();
    if (data.GetMediaImage() != nullptr && !data.GetMediaImageUri().empty()) {
        SLOGI("check isFromSession %{public}d when have two image resources", isFromSession_);
        if (isFromSession_) {
            data.GetMediaImage()->Clear();
        } else {
            return ERR_INVALID_PARAM;
        }
    }
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControllerItem::GetAVQueueItems(std::vector<AVQueueItem>& items)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    items = session_->GetQueueItems();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetAVQueueTitle(std::string& title)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    title = session_->GetQueueTitle();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SkipToQueueItem(int32_t& itemId)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    session_->HandleSkipToQueueItem(itemId);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetExtras(AAFwk::WantParams& extras)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(OHOS::IPCSkeleton::GetCallingPid()),
        ERR_COMMAND_SEND_EXCEED_MAX, "command send number exceed max");
    extras = session_->GetExtras();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SendAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    session_->HandleMediaKeyEvent(keyEvent);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent& ability)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    ability = session_->GetLaunchAbility();
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetValidCommands(std::vector<int32_t>& cmds)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    cmds = session_->GetSupportCommand();
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControllerItem::IsSessionActive(bool& isActive)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    isActive = session_->IsActive();
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControllerItem::SendControlCommand(const AVControlCommand& cmd)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    std::vector<int32_t> cmds = session_->GetSupportCommand();
    CHECK_AND_RETURN_RET_LOG(std::find(cmds.begin(), cmds.end(), cmd.GetCommand()) != cmds.end(),
                             ERR_COMMAND_NOT_SUPPORT, "command not support");
    CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(OHOS::IPCSkeleton::GetCallingPid()),
        ERR_COMMAND_SEND_EXCEED_MAX, "command send number exceed max");
    session_->ExecuteControllerCommand(cmd);
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControllerItem::SendCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "Session not exist");
    CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(OHOS::IPCSkeleton::GetCallingPid()),
        ERR_COMMAND_SEND_EXCEED_MAX, "common command send number exceed max");
    session_->ExecueCommonCommand(commonCommand, commandArgs);
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVControllerItem::SetAVCallMetaFilter(const AVCallMetaData::AVCallMetaMaskType& filter)
{
    std::lock_guard lockGuard(avCallMetaMaskMutex_);
    avCallMetaMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SetAVCallStateFilter(const AVCallState::AVCallStateMaskType& filter)
{
    std::lock_guard lockGuard(avCallStateMaskMutex_);
    avCallStateMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SetMetaFilter(const AVMetaData::MetaMaskType& filter)
{
    std::lock_guard lockGuard(metaMaskMutex_);
    metaMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter)
{
    std::lock_guard lockGuard(playbackMaskMutex_);
    playbackMask_ = filter;
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControllerItem::Destroy()
{
    SLOGI("do controller destroyfor pid %{public}d", static_cast<int>(pid_));
    {
        std::lock_guard callbackLockGuard(callbackMutex_);
        callback_ = nullptr;
        innerCallback_ = nullptr;
    }
    {
        std::lock_guard sessionLockGuard(sessionMutex_);
        if (session_ != nullptr) {
            session_->HandleControllerRelease(pid_);
            session_ = nullptr;
            sessionId_.clear();
        }
    }
    {
        std::lock_guard serviceCallbacklockGuard(serviceCallbackMutex_);
        if (serviceCallback_) {
            serviceCallback_(*this);
        }
    }
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::DestroyWithoutReply()
{
    SLOGI("do controller DestroyWithoutReply for pid %{public}d", static_cast<int>(pid_));
    {
        std::lock_guard callbackLockGuard(callbackMutex_);
        innerCallback_ = nullptr;
        callback_ = nullptr;
    }
    {
        std::lock_guard sessionLockGuard(sessionMutex_);
        if (session_ != nullptr) {
            session_->HandleControllerRelease(pid_);
            sessionId_.clear();
            session_ = nullptr;
        }
    }
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
std::string AVControllerItem::GetSessionId()
{
    return sessionId_;
}
// LCOV_EXCL_STOP

void AVControllerItem::HandleSessionDestroy()
{
    {
        std::lock_guard callbackLockGuard(callbackMutex_);
        if (callback_ != nullptr) {
            callback_->OnSessionDestroy();
        }
        if (innerCallback_ != nullptr) {
            innerCallback_->OnSessionDestroy();
        }
    }
    std::lock_guard sessionLockGuard(sessionMutex_);
    session_ = nullptr;
    sessionId_.clear();
}

// LCOV_EXCL_START
void AVControllerItem::HandleAVCallStateChange(const AVCallState& avCallState)
{
    std::lock_guard callbackLockGuard(callbackMutex_);
    AVCallState stateOut;
    std::lock_guard avCallStateLockGuard(avCallStateMaskMutex_);
    if (avCallState.CopyToByMask(avCallStateMask_, stateOut)) {
        SLOGI("update avcall state");
        AVSESSION_TRACE_SYNC_START("AVControllerItem::OnAVCallStateChange");
        if (callback_ != nullptr) {
            callback_->OnAVCallStateChange(stateOut);
        }
        if (innerCallback_ != nullptr) {
            innerCallback_->OnAVCallStateChange(stateOut);
        }
    }
}

void AVControllerItem::HandleAVCallMetaDataChange(const AVCallMetaData& avCallMetaData)
{
    std::lock_guard callbackLockGuard(callbackMutex_);
    AVCallMetaData metaOut;
    std::lock_guard avCallMetaDataMaskLockGuard(avCallMetaMaskMutex_);
    if (avCallMetaData.CopyToByMask(avCallMetaMask_, metaOut)) {
        if (avCallMetaMask_.test(AVCallMetaData::AVCALL_META_KEY_MEDIA_IMAGE)) {
            std::shared_ptr<AVSessionPixelMap> innerPixelMap = nullptr;
            if (metaOut.GetMediaImage() != nullptr) {
                std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
                std::string fileName = sessionId_ + AVSessionUtils::GetFileSuffix();
                innerPixelMap = metaOut.GetMediaImage();
                AVSessionUtils::ReadImageFromFile(innerPixelMap, fileDir, fileName);
            }
            metaOut.SetMediaImage(innerPixelMap);
        }

        if (avCallMetaMask_.test(AVCallMetaData::AVCALL_META_KEY_NAME)) {
            metaOut.SetName(avCallMetaData.GetName());
        }

        if (avCallMetaMask_.test(AVCallMetaData::AVCALL_META_KEY_PHONE_NUMBER)) {
            metaOut.SetPhoneNumber(avCallMetaData.GetPhoneNumber());
        }
        SLOGI("update avcall meta data");
    }

    if (callback_ != nullptr) {
        callback_->OnAVCallMetaDataChange(metaOut);
    }
    if (innerCallback_ != nullptr) {
        innerCallback_->OnAVCallMetaDataChange(metaOut);
    }
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnAVCallMetaDataChange");
}

void AVControllerItem::HandlePlaybackStateChange(const AVPlaybackState& state)
{
    std::lock_guard callbackLockGuard(callbackMutex_);
    AVPlaybackState stateOut;
    std::lock_guard playbackLockGuard(playbackMaskMutex_);
    if (state.CopyToByMask(playbackMask_, stateOut)) {
        SLOGI("update playback pid %{public}d, state %{public}d",
            static_cast<int>(pid_), static_cast<int>(stateOut.GetState()));
        AVSESSION_TRACE_SYNC_START("AVControllerItem::OnPlaybackStateChange");
        if (callback_ != nullptr) {
            callback_->OnPlaybackStateChange(stateOut);
        }
        if (innerCallback_ != nullptr) {
            innerCallback_->OnPlaybackStateChange(stateOut);
        }
    }
}

void AVControllerItem::HandleMetaDataChange(const AVMetaData& data)
{
    std::lock_guard callbackLockGuard(callbackMutex_);
    AVMetaData metaOut;
    std::lock_guard metaMaskLockGuard(metaMaskMutex_);
    if (data.CopyToByMask(metaMask_, metaOut)) {
        if ((metaMask_.test(AVMetaData::META_KEY_MEDIA_IMAGE)) && (metaOut.GetMediaImage() != nullptr)) {
            std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
            std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaOut.GetMediaImage();
            AVSessionUtils::ReadImageFromFile(innerPixelMap, fileDir, sessionId_ + AVSessionUtils::GetFileSuffix());
            metaOut.SetMediaImage(innerPixelMap);
        }
        if ((metaMask_.test(AVMetaData::META_KEY_AVQUEUE_IMAGE)) && (metaOut.GetAVQueueImage() != nullptr)) {
            std::string avQueueFileDir = AVSessionUtils::GetFixedPathName(userId_);
            std::string avQueueFileName =
                session_->GetBundleName() + "_" + metaOut.GetAVQueueId() + AVSessionUtils::GetFileSuffix();
            std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = metaOut.GetAVQueueImage();
            AVSessionUtils::ReadImageFromFile(avQueuePixelMap, avQueueFileDir, avQueueFileName);
            metaOut.SetAVQueueImage(avQueuePixelMap);
        }
        if (!metaMask_.test(AVMetaData::META_KEY_ASSET_ID)) {
            metaOut.SetAssetId(data.GetAssetId());
        }
        SLOGI("update metaData pid %{public}d, title %{public}s", static_cast<int>(pid_), metaOut.GetTitle().c_str());
        AVSESSION_TRACE_SYNC_START("AVControllerItem::OnMetaDataChange");
        if (metaOut.GetMediaImage() != nullptr && !metaOut.GetMediaImageUri().empty()) {
            SLOGI("check isFromSession %{public}d when have two image resources", isFromSession_);
            if (isFromSession_) {
                metaOut.GetMediaImage()->Clear();
            } else {
                metaOut.SetMediaImageUri("");
            }
        }
        if (callback_ != nullptr) {
            callback_->OnMetaDataChange(metaOut);
        }
        if (innerCallback_ != nullptr) {
            innerCallback_->OnMetaDataChange(metaOut);
        }
    }
    std::shared_ptr<AVSessionPixelMap> innerQueuePixelMap = metaOut.GetAVQueueImage();
    if (innerQueuePixelMap != nullptr) {
        innerQueuePixelMap->Clear();
    }
    std::shared_ptr<AVSessionPixelMap> innerMediaPixelMap = metaOut.GetMediaImage();
    if (innerMediaPixelMap != nullptr) {
        innerMediaPixelMap->Clear();
    }
}

void AVControllerItem::HandleOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGD("Connection state %{public}d", connectionState);
    std::lock_guard lockGuard(callbackMutex_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnOutputDeviceChange(connectionState, outputDeviceInfo);
}
// LCOV_EXCL_STOP

void AVControllerItem::HandleActiveStateChange(bool isActive)
{
    std::lock_guard lockGuard(callbackMutex_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnActiveStateChange(isActive);
}

// LCOV_EXCL_START
void AVControllerItem::HandleValidCommandChange(const std::vector<int32_t>& cmds)
{
    std::lock_guard lockGuard(callbackMutex_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    SLOGD("do OnValidCommandChange with pid %{public}d cmd list size %{public}d",
        static_cast<int>(pid_), static_cast<int>(cmds.size()));
    callback_->OnValidCommandChange(cmds);
}
// LCOV_EXCL_STOP

void AVControllerItem::HandleSetSessionEvent(const std::string& event, const AAFwk::WantParams& args)
{
    std::lock_guard lockGuard(callbackMutex_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnSessionEventChange");
    callback_->OnSessionEventChange(event, args);
}

// LCOV_EXCL_START
void AVControllerItem::HandleQueueItemsChange(const std::vector<AVQueueItem>& items)
{
    std::lock_guard lockGuard(callbackMutex_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnQueueItemsChange");
    callback_->OnQueueItemsChange(items);
}

void AVControllerItem::HandleQueueTitleChange(const std::string& title)
{
    std::lock_guard lockGuard(callbackMutex_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnQueueTitleChange");
    callback_->OnQueueTitleChange(title);
}

void AVControllerItem::HandleExtrasChange(const AAFwk::WantParams& extras)
{
    std::lock_guard lockGuard(callbackMutex_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnSetExtras");
    callback_->OnExtrasChange(extras);
}
// LCOV_EXCL_STOP

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
    std::lock_guard lockGuard(serviceCallbackMutex_);
    serviceCallback_ = callback;
}
} // namespace OHOS::AVSession
