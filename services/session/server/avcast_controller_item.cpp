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
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "av_router.h"

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
}

void AVCastControllerItem::OnCastPlaybackStateChange(const AVPlaybackState& state)
{
    SLOGI("OnCastPlaybackStateChange with state: %{public}d", state.GetState());
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    AVPlaybackState stateOut;
    std::lock_guard lockGuard(itemCallbackLock_);
    if (state.CopyToByMask(castPlaybackMask_, stateOut)) {
        SLOGI("update cast playback state");
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
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnPlayNext();
}

void AVCastControllerItem::OnPlayPrevious()
{
    SLOGI("OnPlayPrevious");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::lock_guard lockGuard(itemCallbackLock_);
    callback_->OnPlayPrevious();
}

void AVCastControllerItem::OnSeekDone(const int32_t seekNumber)
{
    SLOGI("OnSeekDone");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
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
    SLOGI("OnPlayerError");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
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

int32_t AVCastControllerItem::SendControlCommand(const AVCastControlCommand& cmd)
{
    SLOGI("Call SendControlCommand of cast controller proxy");
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    castControllerProxy_->SendControlCommand(cmd);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::Start(const AVQueueItem& avQueueItem)
{
    SLOGI("Call Start of cast controller proxy");
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    castControllerProxy_->Start(avQueueItem);
    currentAVQueueItem_ = avQueueItem;
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::Prepare(const AVQueueItem& avQueueItem)
{
    SLOGI("Call prepare of cast controller proxy");
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    castControllerProxy_->Prepare(avQueueItem);
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
    return castControllerProxy_->GetCastAVPlaybackState(avPlaybackState);
}

int32_t AVCastControllerItem::GetCurrentItem(AVQueueItem& currentItem)
{
    currentItem =  castControllerProxy_->GetCurrentItem();
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::GetValidCommands(std::vector<int32_t>& cmds)
{
    validCommandsChangecallback_(AVCastControlCommand::CAST_CONTROL_CMD_MAX, cmds);
    SLOGI("get available command with size %{public}d", static_cast<int32_t>(cmds.size()));
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

int32_t AVCastControllerItem::ProvideKeyResponse(const std::string &assetId, const std::vector<uint8_t> &response)
{
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, AVSESSION_ERROR, "cast controller proxy is nullptr");
    return castControllerProxy_->ProvideKeyResponse(assetId, response);
}

int32_t AVCastControllerItem::AddAvailableCommand(const int32_t cmd)
{
    SLOGI("add available command %{/public}d", cmd);
    std::vector<int32_t> cmds(AVCastControlCommand::CAST_CONTROL_CMD_MAX);
    validCommandsChangecallback_(cmd, cmds);
    SLOGI("add available command with size %{public}d", static_cast<int32_t>(cmds.size()));
    if (cmds.empty()) {
        SLOGI("check is sink session with empty, not set");
    } else {
        castControllerProxy_->SetValidAbility(cmds);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::RemoveAvailableCommand(const int32_t cmd)
{
    SLOGI("remove available command %{/public}d", cmd);
    std::vector<int32_t> cmds(AVCastControlCommand::CAST_CONTROL_CMD_MAX);
    validCommandsChangecallback_(cmd + removeCmdStep_, cmds);
    SLOGI("remove available command with size %{public}d", static_cast<int32_t>(cmds.size()));
    if (cmds.empty()) {
        SLOGI("check is sink session with empty, not set");
    } else {
        castControllerProxy_->SetValidAbility(cmds);
    }
    return AVSESSION_SUCCESS;
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
    SLOGI("Start cast controller destroy process");
    if (castControllerProxy_) {
        castControllerProxy_ = nullptr;
    }
    std::lock_guard lockGuard(itemCallbackLock_);
    if (callback_) {
        callback_ = nullptr;
    }
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
