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

void AVCastControllerItem::Init(std::shared_ptr<IAVCastControllerProxy> castControllerProxy)
{
    castControllerProxy_ = castControllerProxy;
    castControllerProxy_->RegisterControllerListener(shared_from_this());
}

void AVCastControllerItem::OnStateChange(const AVCastPlayerState& state)
{
    SLOGI("OnStateChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnStateChange(state);
}

void AVCastControllerItem::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    SLOGI("OnMediaItemChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnMediaItemChange(avQueueItem);
}

void AVCastControllerItem::OnVolumeChange(const int32_t volume)
{
    SLOGI("OnVolumeChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnVolumeChange(volume);
}

void AVCastControllerItem::OnLoopModeChange(const int32_t loopMode)
{
    SLOGI("OnLoopModeChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnLoopModeChange(loopMode);
}

void AVCastControllerItem::OnPlaySpeedChange(const int32_t playSpeed)
{
    SLOGI("OnPlaySpeedChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlaySpeedChange(playSpeed);
}

void AVCastControllerItem::OnPositionChange(const int32_t position, const int32_t bufferPosition, const int32_t duration)
{
    SLOGI("OnPositionChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPositionChange(position, bufferPosition, duration);
}

void AVCastControllerItem::OnVideoSizeChange(const int32_t width, const int32_t height)
{
    SLOGI("OnVideoSizeChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnVideoSizeChange(width, height);
}

void AVCastControllerItem::OnError(const int32_t errorCode, const std::string& errorMsg)
{
    SLOGI("OnError");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnError(errorCode, errorMsg);
}

int32_t AVCastControllerItem::SendControlCommand(const AVCastControlCommand& cmd)
{
    SLOGI("Call SendControlCommand of cast controller proxy");
    castControllerProxy_->SendControlCommand(cmd);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::SetMediaList(const MediaInfoHolder& mediaInfoHolder)
{
    SLOGI("Call Start of cast controller proxy");
    castControllerProxy_->SetMediaList(mediaInfoHolder);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::UpdateMediaInfo(const MediaInfo& mediaInfo)
{
    SLOGI("Call Update of cast controller proxy");
    castControllerProxy_->UpdateMediaInfo(mediaInfo);
    return AVSESSION_SUCCESS;
}


int32_t AVCastControllerItem::GetDuration(int32_t& duration)
{
    return castControllerProxy_->GetDuration(duration);
}

int32_t AVCastControllerItem::GetPosition(int32_t& position)
{
    return castControllerProxy_->GetPosition(position);
}

int32_t AVCastControllerItem::GetVolume(int32_t& volume)
{
    return castControllerProxy_->GetVolume(volume);
}

int32_t AVCastControllerItem::GetLoopMode(int32_t& loopMode)
{
    return castControllerProxy_->GetLoopMode(loopMode);
}

int32_t AVCastControllerItem::GetPlaySpeed(int32_t& playSpeed)
{
    return castControllerProxy_->GetPlaySpeed(playSpeed);
}

int32_t AVCastControllerItem::GetPlayState(AVCastPlayerState& playerState)
{
    return castControllerProxy_->GetPlayState(playerState);
}

int32_t AVCastControllerItem::SetDisplaySurface(std::string& surfaceId)
{
    return castControllerProxy_->SetDisplaySurface(surfaceId);
}

bool AVCastControllerItem::RegisterControllerListener(std::shared_ptr<IAVCastControllerProxy> castControllerProxy)
{
    SLOGI("Call RegisterControllerListener of cast controller proxy");
    return castControllerProxy->RegisterControllerListener(shared_from_this());
}

int32_t AVCastControllerItem::RegisterCallbackInner(const sptr<IRemoteObject>& callback)
{
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
    if (callback_) {
        callback_ = nullptr;
    }
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
