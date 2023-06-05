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
}

void AVCastControllerItem::OnPlayerStatusChanged(const AVPlaybackState playbackState)
{

}

// void AVCastControllerItem::OnPositionChanged(const int32_t position, int32_t bufferPosition, int32_t duration)
// {

// }

// void AVCastControllerItem::OnMediaItemChanged(const PlayInfo playInfo)
// {

// }

void AVCastControllerItem::OnVolumeChanged(const int32_t volume)
{

}

void AVCastControllerItem::OnPlaySpeedChanged(const float playSpeed)
{

}

void AVCastControllerItem::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{

}

// void AVCastControllerItem::OnLoopModeChanged(const int32_t loopMode)
// {

// }

std::string AVCastControllerItem::GetSurfaceId()
{
    return surfaceId_;
}

int32_t AVCastControllerItem::GetCurrentIndex()
{
    return currentTime_;
}

int32_t AVCastControllerItem::Start(const PlayInfoHolder& playInfoHolder)
{
    castControllerProxy_->Start(playInfoHolder);
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::SendControlCommand(const AVCastControlCommand& cmd)
{
    castControllerProxy_->SendControlCommand(cmd);
    return AVSESSION_SUCCESS;
}

void AVCastControllerItem::RegisterCastControllerProxyListener(int64_t castHandle)
{
    AVRouter::GetInstance().RegisterCastControllerProxyListener(castHandle, shared_from_this());
}

int32_t AVCastControllerItem::RegisterCallbackInner(const sptr<IRemoteObject>& callback)
{
    callback_ = iface_cast<AVCastControllerCallbackProxy>(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, AVSESSION_ERROR, "callback_ is nullptr");
    return AVSESSION_SUCCESS;
}

int32_t AVCastControllerItem::Destroy()
{
    if (castControllerProxy_) {
        castControllerProxy_ = nullptr;
    }
    if (callback_) {
        callback_ = nullptr;
    }
    return AVSESSION_SUCCESS;
}
} // OHOS::AVSession
