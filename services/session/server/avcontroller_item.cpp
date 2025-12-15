/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "avsession_utils.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_trace.h"
#include "command_send_limit.h"
#include "avsession_utils.h"
#include "permission_checker.h"
#include "avsession_sysevent.h"
#include "want_params.h"
#include "string_wrapper.h"
#include "bundle_status_adapter.h"

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

namespace OHOS::AVSession {
AVControllerItem::AVControllerItem(pid_t pid, const sptr<AVSessionItem>& session, int32_t userId)
    : pid_(pid), session_(session), userId_(userId)
{
    std::lock_guard sessionLockGuard(sessionMutex_);
    if (session_ != nullptr) {
        sessionId_ = session_->GetSessionId();
    }
}

AVControllerItem::~AVControllerItem()
{
}

int32_t AVControllerItem::GetUserId() const
{
    return userId_;
}

int32_t AVControllerItem::RegisterCallbackInner(const sptr<IRemoteObject>& callback)
{
    std::lock_guard lockGuard(callbackMutex_);
    SLOGD("do register callback for controller %{public}d", static_cast<int>(pid_));
    callback_ = iface_cast<IAVControllerCallback>(callback);
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

int32_t AVControllerItem::UnregisterAVControllerCallback()
{
    std::lock_guard lockGuard(callbackMutex_);
    SLOGI("UnregisterAVControllerCallback pid %{public}d", static_cast<int>(pid_));
    innerCallback_ = nullptr;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::RegisterMigrateAVSessionProxyCallback(
    const std::function<int32_t(const std::string&, AAFwk::WantParams&)>& callback)
{
    migrateProxyCallback_ = callback;
    CHECK_AND_RETURN_RET_LOG(migrateProxyCallback_ != nullptr, AVSESSION_ERROR,
        "RegisterMigrateAVSessionProxyCallback migrateProxyCallback_ is nullptr");
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

int32_t AVControllerItem::ReadImgForMetaData(AVMetaData& data)
{
    if (!data.GetMetaMask().test(AVMetaData::META_KEY_MEDIA_IMAGE)) {
        SLOGI("curNoImgFor:%{public}s", data.GetTitle().c_str());
        return AVSESSION_SUCCESS;
    }
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "SetImgForMetaData session not exist");
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = data.GetMediaImage();
    session_->ReadMetaDataImg(innerPixelMap);

    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = data.GetAVQueueImage();
    session_->ReadMetaDataAVQueueImg(avQueuePixelMap);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetAVMetaData(AVMetaData& data)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    data = session_->GetMetaDataWithoutImg();
    int32_t ret = ReadImgForMetaData(data);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "ReadImgForMetaData with ret:%{public}d", ret);
    if (data.GetMediaImage() != nullptr && !data.GetMediaImageUri().empty()) {
        SLOGI("isFromSession %{public}d|%{public}d", isFromSession_, data.GetMediaImageTopic());
        if (isFromSession_) {
            data.GetMediaImage()->Clear();
        } else {
            return ERR_INVALID_PARAM;
        }
    }
    return AVSESSION_SUCCESS;
}

void AVControllerItem::DoMetadataImgClean(AVMetaData& data)
{
    std::lock_guard metaMaskLockGuard(metaMaskMutex_);
    SLOGD("still clear media img in DoMetadataImgClean");
    std::shared_ptr<AVSessionPixelMap> innerQueuePixelMap = data.GetAVQueueImage();
    AVSessionPixelMapAdapter::CleanAVSessionPixelMap(innerQueuePixelMap);
    SLOGI("ImgClean:%{public}d", data.GetMediaImageTopic());
    std::shared_ptr<AVSessionPixelMap> innerMediaPixelMap = data.GetMediaImage();
    AVSessionPixelMapAdapter::CleanAVSessionPixelMap(innerMediaPixelMap);
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

int32_t AVControllerItem::GetExtrasWithEvent(const std::string& extraEvent, AAFwk::WantParams& extras)
{
    if (migrateProxyCallback_ != nullptr) {
        int32_t ret = migrateProxyCallback_(extraEvent, extras);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "extraEvent not support");
    } else {
        SLOGI("migrateProxyCallback_ function is nullptr");
    }

    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");

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
    if (std::find(cmds.begin(), cmds.end(), cmd.GetCommand()) == cmds.end()) {
        SLOGE("The command that needs to be sent is not supported.");
        return ERR_COMMAND_NOT_SUPPORT;
    }
    CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(OHOS::IPCSkeleton::GetCallingPid()),
        ERR_COMMAND_SEND_EXCEED_MAX, "command send number exceed max");
    session_->ExecuteControllerCommand(cmd);
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControllerItem::SendCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    if (migrateProxyCallback_ != nullptr) {
        int32_t ret = migrateProxyCallback_(commonCommand, const_cast<AAFwk::WantParams&>(commandArgs));
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "extraEvent not support");
    } else {
        SLOGI("migrateProxyCallback_ function is nullptr");
    }

    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "Session not exist");
    CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(OHOS::IPCSkeleton::GetCallingPid()),
        ERR_COMMAND_SEND_EXCEED_MAX, "common command send number exceed max");
    session_->ExecueCommonCommand(commonCommand, commandArgs);
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SendCustomData(const AAFwk::WantParams& data)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(data.HasParam("customData"), AVSESSION_ERROR, "Params don't have customData");
    auto value = data.GetParam("customData");
    AAFwk::IString* stringValue = AAFwk::IString::Query(value);
    CHECK_AND_RETURN_RET_LOG(stringValue != nullptr, AVSESSION_ERROR, "customData is an invalid string");
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "Session not exist");
    session_->ExecuteCustomData(data);
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

int32_t AVControllerItem::GetMetaFilter(AVMetaData::MetaMaskType& filter)
{
    std::lock_guard lockGuard(metaMaskMutex_);
    filter = metaMask_;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter)
{
    std::lock_guard lockGuard(playbackMaskMutex_);
    playbackMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::GetPlaybackFilter(AVPlaybackState::PlaybackStateMaskType& filter)
{
    std::lock_guard lockGuard(playbackMaskMutex_);
    filter = playbackMask_;
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVControllerItem::Destroy()
{
    if (sessionId_ == "DEFAULT") {
        SLOGE("controller create inside can not be destroy from outside");
        return AVSESSION_SUCCESS;
    }
    SLOGI("controller destroyed for pid %{public}d", static_cast<int>(pid_));
    {
        std::lock_guard callbackLockGuard(callbackMutex_);
        callback_ = nullptr;
        innerCallback_ = nullptr;
    }

    {
        std::lock_guard serviceCallbacklockGuard(serviceCallbackMutex_);
        if (serviceCallback_) {
            serviceCallback_(*this);
        }
    }

    {
        std::lock_guard sessionLockGuard(sessionMutex_);
        if (session_ != nullptr) {
            session_->HandleControllerRelease(pid_);
            session_ = nullptr;
            sessionId_.clear();
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
    std::lock_guard sessionLockGuard(sessionMutex_);
    return sessionId_;
}
// LCOV_EXCL_STOP

AppExecFwk::ElementName AVControllerItem::GetElementOfSession()
{
    std::lock_guard sessionLockGuard(sessionMutex_);
    AppExecFwk::ElementName elementOfSession;
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, elementOfSession, "session not exist");
    elementOfSession.SetBundleName(session_->GetBundleName());
    elementOfSession.SetAbilityName(session_->GetAbilityName());
    return elementOfSession;
}

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
            if (metaOut.GetMediaImage() != nullptr && session_ != nullptr) {
                innerPixelMap = metaOut.GetMediaImage();
                session_->ReadMetaDataImg(innerPixelMap);
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

void AVControllerItem::HandlePlaybackStateChange(const AVPlaybackState& state,
    const AVPlaybackState::PlaybackStateMaskType& changedStateMask)
{
    std::lock_guard callbackLockGuard(callbackMutex_);
    AVPlaybackState stateOut;
    std::lock_guard playbackLockGuard(playbackMaskMutex_);
    AVPlaybackState::PlaybackStateMaskType validMask = playbackMask_.all() ? playbackMask_ :
        changedStateMask & playbackMask_;
    if (state.CopyToByMask(validMask, stateOut)) {
        AVSESSION_TRACE_SYNC_START("AVControllerItem::OnPlaybackStateChange");
        if (callback_ != nullptr) {
            callback_->OnPlaybackStateChange(stateOut);
        }
        if (innerCallback_ != nullptr) {
            innerCallback_->OnPlaybackStateChange(stateOut);
        }
    }
}

void AVControllerItem::HandleMetaDataChange(const AVMetaData& data, const AVMetaData::MetaMaskType& changedDataMask)
{
    std::lock_guard callbackLockGuard(callbackMutex_);
    AVMetaData metaOut;
    std::lock_guard metaMaskLockGuard(metaMaskMutex_);
    AVMetaData::MetaMaskType validMask = metaMask_.all() ? metaMask_ : changedDataMask & metaMask_;
    bool copyResult = data.CopyToByMask(validMask, metaOut);
    CHECK_AND_PRINT_LOG(copyResult, "controller:%{public}d no mask", static_cast<int>(pid_));
    if (copyResult) {
        if ((metaMask_.test(AVMetaData::META_KEY_MEDIA_IMAGE)) && (metaOut.GetMediaImage() != nullptr)) {
            CHECK_AND_RETURN_LOG(session_ != nullptr, "Session not exist");
            std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaOut.GetMediaImage();
            session_->ReadMetaDataImg(innerPixelMap);
            metaOut.SetMediaImage(innerPixelMap);
        }
        if ((metaMask_.test(AVMetaData::META_KEY_AVQUEUE_IMAGE)) && (metaOut.GetAVQueueImage() != nullptr)) {
            CHECK_AND_RETURN_LOG(session_ != nullptr, "Session not exist");
            std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = metaOut.GetAVQueueImage();
            session_->ReadMetaDataAVQueueImg(avQueuePixelMap);
            metaOut.SetAVQueueImage(avQueuePixelMap);
        }
        metaOut.SetAssetId(data.GetAssetId());
        SLOGI("update metaData pid %{public}d, title %{public}s", static_cast<int>(pid_),
            AVSessionUtils::GetAnonyTitle(metaOut.GetTitle().c_str()).c_str());
        AVSESSION_TRACE_SYNC_START("AVControllerItem::OnMetaDataChange");
        if (metaOut.GetMediaImage() != nullptr && !metaOut.GetMediaImageUri().empty()) {
            SLOGI("isFromSession %{public}d in metaChange", isFromSession_);
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
    std::lock_guard lockGuard(callbackMutex_);
    if (callback_ != nullptr) {
        callback_->OnOutputDeviceChange(connectionState, outputDeviceInfo);
    }
}
// LCOV_EXCL_STOP

void AVControllerItem::HandleActiveStateChange(bool isActive)
{
    std::lock_guard lockGuard(callbackMutex_);
    if (callback_ != nullptr) {
        callback_->OnActiveStateChange(isActive);
    }
}

// LCOV_EXCL_START
void AVControllerItem::HandleValidCommandChange(const std::vector<int32_t>& cmds)
{
    std::lock_guard lockGuard(callbackMutex_);
    SLOGD("do OnValidCommandChange with pid %{public}d cmd list size %{public}d",
        static_cast<int>(pid_), static_cast<int>(cmds.size()));
    if (callback_ != nullptr) {
        callback_->OnValidCommandChange(cmds);
    }
    if (innerCallback_ != nullptr) {
        innerCallback_->OnValidCommandChange(cmds);
    }
}
// LCOV_EXCL_STOP

void AVControllerItem::HandleSetSessionEvent(const std::string& event, const AAFwk::WantParams& args)
{
    std::lock_guard lockGuard(callbackMutex_);
    if (callback_ != nullptr) {
        callback_->OnSessionEventChange(event, args);
    }
}

// LCOV_EXCL_START
void AVControllerItem::HandleQueueItemsChange(const std::vector<AVQueueItem>& items)
{
    std::lock_guard lockGuard(callbackMutex_);
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnQueueItemsChange");
    if (callback_ != nullptr) {
        callback_->OnQueueItemsChange(items);
    }
}

void AVControllerItem::HandleQueueTitleChange(const std::string& title)
{
    std::lock_guard lockGuard(callbackMutex_);
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnQueueTitleChange");
    if (callback_ != nullptr) {
        callback_->OnQueueTitleChange(title);
    }
}

void AVControllerItem::HandleExtrasChange(const AAFwk::WantParams& extras)
{
    std::lock_guard lockGuard(callbackMutex_);
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnSetExtras");
    if (callback_ != nullptr) {
        callback_->OnExtrasChange(extras);
    }
}
// LCOV_EXCL_STOP

void AVControllerItem::HandleCustomData(const AAFwk::WantParams& data)
{
    std::lock_guard lockGuard(callbackMutex_);
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnCustomData");
    if (callback_ != nullptr) {
        callback_->OnCustomData(data);
    }
}

void AVControllerItem::HandleDesktopLyricVisibilityChanged(bool isVisible)
{
    std::lock_guard lockGuard(callbackMutex_);
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnDesktopLyricVisibilityChanged");
    if (callback_ != nullptr) {
        callback_->OnDesktopLyricVisibilityChanged(isVisible);
    }
}

void AVControllerItem::HandleDesktopLyricStateChanged(const DesktopLyricState &state)
{
    std::lock_guard lockGuard(callbackMutex_);
    AVSESSION_TRACE_SYNC_START("AVControllerItem::OnDesktopLyricStateChanged");
    if (callback_ != nullptr) {
        callback_->OnDesktopLyricStateChanged(state);
    }
}

void AVControllerItem::HandleDesktopLyricEnabled(bool isEnabled)
{
    std::lock_guard lockGuard(callbackMutex_);
    AVSESSION_TRACE_SYNC_START("AVControllerItem::HandleDesktopLyricEnabled");
    if (callback_ != nullptr) {
        callback_->OnDesktopLyricEnabled(isEnabled);
    }
}

pid_t AVControllerItem::GetPid() const
{
    return pid_;
}

bool AVControllerItem::HasSession(const std::string& sessionId)
{
    std::lock_guard sessionLockGuard(sessionMutex_);
    return sessionId_ == sessionId;
}

void AVControllerItem::SetServiceCallbackForRelease(const std::function<void(AVControllerItem&)>& callback)
{
    std::lock_guard lockGuard(serviceCallbackMutex_);
    serviceCallback_ = callback;
}

std::string AVControllerItem::GetSessionType()
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, "SESSION_NULL", "session not exist");
    std::string sessionTypeStr = session_->GetSessionType();
    return sessionTypeStr;
}

int32_t AVControllerItem::IsDesktopLyricEnabled(bool &isEnabled)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    return session_->IsDesktopLyricEnabled(isEnabled);
}

int32_t AVControllerItem::SetDesktopLyricVisible(bool isVisible)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    std::string callingBundleName = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid());
    SLOGI("controller call");
    return session_->SetDesktopLyricVisibleInner(isVisible, callingBundleName);
}

int32_t AVControllerItem::IsDesktopLyricVisible(bool &isVisible)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    return session_->IsDesktopLyricVisible(isVisible);
}

int32_t AVControllerItem::SetDesktopLyricState(DesktopLyricState state)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    std::string callingBundleName = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid());
    SLOGI("controller call");
    return session_->SetDesktopLyricStateInner(state, callingBundleName);
}

int32_t AVControllerItem::GetDesktopLyricState(DesktopLyricState &state)
{
    std::lock_guard lockGuard(sessionMutex_);
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, ERR_SESSION_NOT_EXIST, "session not exist");
    return session_->GetDesktopLyricState(state);
}
} // namespace OHOS::AVSession
