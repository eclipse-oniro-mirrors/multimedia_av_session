/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "avcast_controller_item.h"
#include "avsession_radar.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "av_router.h"
#include "avsession_sysevent.h"
#include "avmedia_description.h"
#include "bundle_status_adapter.h"

#include <string>

namespace OHOS::AVSession {
AVCastControllerItem::AVCastControllerItem()
{
    SLOGD("AVCastControllerItem construct");
}

AVCastControllerItem::~AVCastControllerItem()
{
    SLOGD("AVCastControllerItem destruct");
}

void AVCastControllerItem::Init(std::shared_ptr<IAVCastControllerProxy> castControllerProxy,
    const std::function<void(int32_t, std::vector<int32_t>&)>& validCommandsChangecallback)
{
    castControllerProxy_ = castControllerProxy;
    castControllerProxy_->RegisterControllerListener(shared_from_this());
    validCommandsChangecallback_ = validCommandsChangecallback;
    {
        std::lock_guard<std::mutex> lock(callbackToSessionLock_);
        isSessionCallbackAvailable_ = true;
    }
}

void AVCastControllerItem::OnCastPlaybackStateChange(const AVPlaybackState& state)
{
    SLOGI("OnCastPlaybackStateChange state:%{public}d", state.GetState());
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    if (state.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAY) {
        AVSessionRadarInfo info("AVCastControllerItem::OnCastPlaybackStateChange");
        AVSessionRadar::GetInstance().PlayerStarted(info);
    } else if (state.GetState() != currentState_) {
        currentState_ = state.GetState();
        AVSessionRadarInfo info("AVCastControllerItem::OnCastPlaybackStateChange");
        AVSessionRadar::GetInstance().ControlCommandRespond(info);
    }
    AVPlaybackState stateOut;
    std::lock_guard lockGuard(itemCallbackLock_);
    if (state.CopyToByMask(castPlaybackMask_, stateOut)) {
        SLOGD("update cast playback state");
        AVSESSION_TRACE_SYNC_START("AVCastControllerItem::OnCastPlaybackStateChange");
        callback_->OnCastPlaybackStateChange(stateOut);
    }
    SLOGI("OnCastPlaybackStateChange done with state: %{public}d", state.GetState());
}

void AVCastControllerItem::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    SLOGI("OnMediaItemChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnMediaItemChange(avQueueItem);
    SLOGI("OnMediaItemChange done");
}

void AVCastControllerItem::OnPlayNext()
{
    SLOGI("OnPlayNext");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback is nullptr");
    AVSessionRadarInfo info("AVCastControllerItem::OnPlayNext");
    AVSessionRadar::GetInstance().ControlCommandRespond(info);
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnPlayNext();
}

void AVCastControllerItem::OnPlayPrevious()
{
    SLOGI("OnPlayPrevious");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSessionRadarInfo info("AVCastControllerItem::OnPlayPrevious");
    AVSessionRadar::GetInstance().ControlCommandRespond(info);
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnPlayPrevious();
}

void AVCastControllerItem::OnSeekDone(const int32_t seekNumber)
{
    SLOGI("OnSeekDone");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSessionRadarInfo info("AVCastControllerItem::OnSeekDone");
    AVSessionRadar::GetInstance().ControlCommandRespond(info);
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnSeekDone(seekNumber);
}

void AVCastControllerItem::OnVideoSizeChange(const int32_t width, const int32_t height)
{
    SLOGI("OnVideoSizeChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnVideoSizeChange(width, height);
}

void AVCastControllerItem::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{
    SLOGI("OnPlayerError error:%{public}d", errorCode);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSessionRadarInfo info("AVCastControllerItem::OnPlayerError");
    info.errorCode_ = errorCode;
    AVSessionRadar::GetInstance().ControlCommandError(info);
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnPlayerError(errorCode, errorMsg);
}

void AVCastControllerItem::OnEndOfStream(const int32_t isLooping)
{
    SLOGI("OnEndOfStream");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnEndOfStream(isLooping);
}

void AVCastControllerItem::OnPlayRequest(const AVQueueItem& avQueueItem)
{
    SLOGI("OnPlayRequest");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVSessionRadarInfo info("AVCastControllerItem::OnPlayRequest");
    AVSessionRadar::GetInstance().ControlCommandRespond(info);
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnPlayRequest(avQueueItem);
}

void AVCastControllerItem::OnKeyRequest(const std::string &assetId, const std::vector<uint8_t> &keyRequestData)
{
    SLOGI("OnKeyRequest");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnKeyRequest(assetId, keyRequestData);
}

void AVCastControllerItem::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    SLOGI("OnValidCommandChange");
    HandleCastValidCommandChange(cmds);
}

int32_t AVCastControllerItem::SendControlCommand(const AVCastControlCommand& cmd)
{
    SLOGI("Call SendControlCommand of cast controller proxy");
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    AVSessionRadarInfo info("AVCastControllerItem::SendControlCommand");
    AVSessionRadar::GetInstance().SendControlCommandBegin(info);
    castControllerProxy_->SendControlCommand(cmd);
    AVSessionRadar::GetInstance().SendControlCommandEnd(info);
    std::string API_PARAM_STRING = "cmd: " + std::to_string(cmd.GetCommand());
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "SendControlCommand",
        "BUNDLE_NAME", BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid()),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::Start(const AVQueueItem& avQueueItem)
{
    SLOGI("Call Start of cast controller proxy");
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    AVSessionRadarInfo info("AVCastControllerItem::Start");
    int32_t ret = castControllerProxy_->Start(avQueueItem);
    std::string errMsg = (ret == AVSESSION_SUCCESS) ? "SUCCESS" : "start failed";
    std::string mediaIcon = "false";
    std::string API_PARAM_STRING = "";
    std::string startPosition = "";
    std::string duration = "";
    std::string mediauri = "";
    if (avQueueItem.GetDescription() != nullptr) {
        startPosition = std::to_string(avQueueItem.GetDescription()->GetStartPosition());
        duration =  std::to_string(avQueueItem.GetDescription()->GetDuration());
        if (avQueueItem.GetDescription()->GetIcon() != nullptr ||
            !(avQueueItem.GetDescription()->GetIconUri().empty())) {
            mediaIcon = "true";
        }
        mediauri = avQueueItem.GetDescription()->GetMediaUri().empty() ? "false" : "true";
        API_PARAM_STRING = "mediauri: " + mediauri + "," + "iconImage: " + mediaIcon + ","
                                        + "mediaId: " + avQueueItem.GetDescription()->GetMediaId() + ","
                                        + "title: " + avQueueItem.GetDescription()->GetTitle() + ","
                                        + "subtitle: " + avQueueItem.GetDescription()->GetSubtitle() + ","
                                        + "mediaType: " + avQueueItem.GetDescription()->GetMediaType() + ","
                                        + "startPosition: " + startPosition + ","
                                        + "duration: " + duration;
    }
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "Start",
        "BUNDLE_NAME", BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid()),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", ret,
        "ERROR_MSG", errMsg);
    if (ret != AVSESSION_SUCCESS) {
        info.errorCode_ = AVSessionRadar::GetRadarErrorCode(ret);
        AVSessionRadar::GetInstance().StartPlayFailed(info);
    } else {
        AVSessionRadar::GetInstance().StartPlayBegin(info);
    }
    currentAVQueueItem_ = avQueueItem;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::Prepare(const AVQueueItem& avQueueItem)
{
    SLOGI("Call prepare of cast controller proxy");
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    auto ret = castControllerProxy_->Prepare(avQueueItem);
    std::string errMsg = (ret == AVSESSION_SUCCESS) ? "SUCCESS" : "prepare failed";
    std::string mediaIcon = "false";
    std::string API_PARAM_STRING = "";
    std::string startPosition = "";
    std::string duration = "";
    std::string mediauri = "";
    if (avQueueItem.GetDescription() != nullptr) {
        startPosition = std::to_string(avQueueItem.GetDescription()->GetStartPosition());
        duration =  std::to_string(avQueueItem.GetDescription()->GetDuration());
        if (avQueueItem.GetDescription()->GetIcon() != nullptr ||
            !(avQueueItem.GetDescription()->GetIconUri().empty())) {
            mediaIcon = "true";
        }
        mediauri = avQueueItem.GetDescription()->GetMediaUri().empty() ? "false" : "true";
        API_PARAM_STRING = "mediauri: " + mediauri + "," + "iconImage: " + mediaIcon + ","
                                        + "mediaId: " + avQueueItem.GetDescription()->GetMediaId() + ","
                                        + "title: " + avQueueItem.GetDescription()->GetTitle() + ","
                                        + "subtitle: " + avQueueItem.GetDescription()->GetSubtitle() + ","
                                        + "mediaType: " + avQueueItem.GetDescription()->GetMediaType() + ","
                                        + "startPosition: " + startPosition + ","
                                        + "duration: " + duration;
    }
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "Prepare",
        "BUNDLE_NAME", BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid()),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", ret,
        "ERROR_MSG", errMsg);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::GetDuration(int32_t& duration)
{
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    return castControllerProxy_->GetDuration(duration);
}

int32_t AVCastControllerItem::GetCastAVPlaybackState(AVPlaybackState& avPlaybackState)
{
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    auto ret = castControllerProxy_->GetCastAVPlaybackState(avPlaybackState);
    std::string errMsg = (ret == AVSESSION_SUCCESS) ? "SUCCESS" : "GetCastAVPlaybackState failed";
    int64_t avElapsedTime = avPlaybackState.GetPosition().elapsedTime_;
    int64_t avUpdateTime = avPlaybackState.GetPosition().updateTime_;
    std::string isFavor = avPlaybackState.GetFavorite() ? "true" : "false";
    std::string API_PARAM_STRING = "state: " + std::to_string(avPlaybackState.GetState()) + ", "
                                    + "elapsedTime: " + std::to_string(avElapsedTime) + ", "
                                    + "updateTime: " + std::to_string(avUpdateTime) + ", "
                                    + "loopMode: " + std::to_string(avPlaybackState.GetLoopMode()) + ", "
                                    + "isFavorite: " + isFavor;
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "GetCastAVPlaybackState",
        "BUNDLE_NAME", BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid()),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", ret,
        "ERROR_MSG", errMsg);
    return ret;
}

int32_t AVCastControllerItem::GetCurrentItem(AVQueueItem& currentItem)
{
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR,
        "cast controller proxy is nullptr");
    currentItem =  castControllerProxy_->GetCurrentItem();
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::GetValidCommands(std::vector<int32_t>& cmds)
{
    if (sessionTag_ == "RemoteCast") {
        CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR,
            "cast controller proxy is nullptr");
        castControllerProxy_->GetValidAbility(cmds);
        SLOGI("get available commands from cast with size %{public}zd", cmds.size());
        return AVSESSION_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(callbackToSessionLock_);
        CHECK_AND_RETURN_RET_LOG(isSessionCallbackAvailable_, AVSESSION_ERROR, "sessionCallback not available");
    }
    validCommandsChangecallback_(AVCastControlCommand::CAST_CONTROL_CMD_MAX, cmds);
    SLOGI("get available command with size %{public}zd", cmds.size());
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::SetDisplaySurface(std::string& surfaceId)
{
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    return castControllerProxy_->SetDisplaySurface(surfaceId);
}

int32_t AVCastControllerItem::SetCastPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter)
{
    castPlaybackMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::ProcessMediaKeyResponse(const std::string &assetId, const std::vector<uint8_t> &response)
{
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    auto ret =  castControllerProxy_->ProcessMediaKeyResponse(assetId, response);
    std::string API_PARAM_STRING = "assetId: " + assetId;
    std::string errMsg = (ret == AVSESSION_SUCCESS) ? "SUCCESS" : "ProcessMediaKeyResponse failed";
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "ProcessMediaKeyResponse",
        "BUNDLE_NAME",  BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid()),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", ret,
        "ERROR_MSG", errMsg);
    return ret;
}

int32_t AVCastControllerItem::AddAvailableCommand(const int32_t cmd)
{
    SLOGI("add available command %{public}d with isSessionCallbackAvailable check %{public}d",
        cmd, static_cast<int>(isSessionCallbackAvailable_));
    std::vector<int32_t> cmds(AVCastControlCommand::CAST_CONTROL_CMD_MAX);
    {
        std::lock_guard<std::mutex> lock(callbackToSessionLock_);
        CHECK_AND_RETURN_RET_LOG(isSessionCallbackAvailable_, AVSESSION_ERROR, "sessionCallback not available");
    }
    validCommandsChangecallback_(cmd, cmds);
    SLOGI("add available command with size %{public}d", static_cast<int32_t>(cmds.size()));
    if (cmds.empty()) {
        SLOGI("check is sink session with empty, not set");
    } else {
        CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR,
            "cast controller proxy is nullptr");
        auto ret = castControllerProxy_->SetValidAbility(cmds);
        std::string errMsg = (ret == AVSESSION_SUCCESS) ? "SUCCESS" : "onCastEvent failed";
        std::string API_PARAM_STRING = "cmd: " + std::to_string(cmd);
        HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
            "API_NAME", "onCastEvent",
            "BUNDLE_NAME", BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid()),
            "API_PARAM", API_PARAM_STRING,
            "ERROR_CODE", ret,
            "ERROR_MSG", errMsg);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::RemoveAvailableCommand(const int32_t cmd)
{
    SLOGI("remove available command %{public}d", cmd);
    std::vector<int32_t> cmds(AVCastControlCommand::CAST_CONTROL_CMD_MAX);
    {
        std::lock_guard<std::mutex> lock(callbackToSessionLock_);
        CHECK_AND_RETURN_RET_LOG(isSessionCallbackAvailable_, AVSESSION_ERROR, "sessionCallback not available");
    }
    validCommandsChangecallback_(cmd + removeCmdStep_, cmds);
    SLOGI("remove available command with size %{public}d", static_cast<int32_t>(cmds.size()));
    if (cmds.empty()) {
        SLOGI("check is sink session with empty, not set");
    } else {
        CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR,
            "cast controller proxy is nullptr");
        auto ret = castControllerProxy_->SetValidAbility(cmds);
        std::string errMsg = (ret == AVSESSION_SUCCESS) ? "SUCCESS" : "offCastEvent failed";
        std::string API_PARAM_STRING = "cmd: " + std::to_string(cmd);
        HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
            "API_NAME", "offCastEvent",
            "BUNDLE_NAME", BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid()),
            "API_PARAM", API_PARAM_STRING,
            "ERROR_CODE", ret,
            "ERROR_MSG", errMsg);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::HandleCastValidCommandChange(const std::vector<int32_t>& cmds)
{
    SLOGI("HandleCastValidCommandChange cmd size:%{public}zd", cmds.size());
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, AVSESSION_ERROR, "callback_ is nullptr");
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnCastValidCommandChanged(cmds);
    return AVSESSION_SUCCESS;
}

void AVCastControllerItem::SetSessionTag(const std::string& tag)
{
    sessionTag_ = tag;
}

bool AVCastControllerItem::RegisterControllerListener(std::shared_ptr<IAVCastControllerProxy> castControllerProxy)
{
    SLOGI("Call RegisterControllerListener of cast controller proxy");
    CHECK_AND_RETURN_RET_LOG(castControllerProxy != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    return castControllerProxy->RegisterControllerListener(shared_from_this());
}

int32_t AVCastControllerItem::RegisterCallbackInner(const sptr<IRemoteObject>& callback)
{
    SLOGI("call RegisterCallbackInner of cast controller proxy");
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_ = iface_cast<AVCastControllerCallbackProxy>(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, AVSESSION_ERROR, "callback_ is nullptr");
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::Destroy()
{
    SLOGI("Start cast controller destroy process with sessionCallback available set");
    if (castControllerProxy_) {
        castControllerProxy_ = nullptr;
    }
    {
        std::lock_guard lockGuard(itemCallbackLock_);
        if (callback_) {
            callback_ = nullptr;
        }
    }
    {
        std::lock_guard<std::mutex> lock(callbackToSessionLock_);
        isSessionCallbackAvailable_ = false;
    }
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
