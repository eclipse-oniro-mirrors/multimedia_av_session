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

#ifndef OHOS_AVCAST_CONTROLLER_ITEM_H
#define OHOS_AVCAST_CONTROLLER_ITEM_H

#include "i_avcast_controller_proxy.h"
#include "avcast_controller_callback_proxy.h"
#include "avcast_controller_stub.h"

namespace OHOS::AVSession {
class AVCastControllerItem : public AVCastControllerStub, public IAVCastControllerProxyListener, public std::enable_shared_from_this<AVCastControllerItem> {
public:
    AVCastControllerItem();

    void Init(std::shared_ptr<IAVCastControllerProxy> castControllerProxy);

    void OnStateChange(const AVCastPlayerState& state) override;

    void OnMediaItemChange(const AVQueueItem& avQueueItem) override;

    void OnVolumeChange(const int32_t volume) override;

    void OnLoopModeChange(const int32_t loopMode) override;

    void OnPlaySpeedChange(const double playSpeed) override;

    void OnPositionChange(const int32_t position) override;

    void OnVideoSizeChange(const int32_t width, const int32_t height) override;
    
    void OnError(const int32_t errorCode, const std::string& errorMsg) override;

    int32_t GetDuration() override;

    std::string GetSurfaceId() override;

    int32_t GetVolume() override;

    int32_t GetLoopMode() override;

    double GetPlaySpeed() override;

    int32_t GetCurrentTime() override;

    int32_t SendControlCommand(const AVCastControlCommand& cmd) override;

    int32_t Start(const PlayInfoHolder& playInfoHolder) override;

    int32_t UpdateMediaInfo(const MediaInfo& mediaInfo) override;

    void RegisterControllerListener(std::shared_ptr<IAVCastControllerProxy> castControllerProxy);

    int32_t Destroy() override;

protected:
    int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) override;

private:
    std::shared_ptr<IAVCastControllerProxy> castControllerProxy_;
    int32_t duration_;
    std::string surfaceId_;
    int32_t volume_;
    int32_t loopMode_;
    double playSpeed_;
    int32_t currentTime_;
    sptr<IAVCastControllerCallback> callback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCAST_CONTROLLER_ITEM_H
