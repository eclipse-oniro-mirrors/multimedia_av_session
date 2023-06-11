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

#ifndef OHOS_AVCAST_CONTROLLER_PROXY_H
#define OHOS_AVCAST_CONTROLLER_PROXY_H

#include <mutex>

#include "iavcast_controller.h"
#include "iremote_proxy.h"

namespace OHOS::AVSession {
class AVCastControllerProxy : public IRemoteProxy<IAVCastController> {
public:
    explicit AVCastControllerProxy(const sptr<IRemoteObject>& impl);

    ~AVCastControllerProxy() override;

    // void Init(const std::shared_ptr<IAVCastControllerProxy> castControllerProxy) override;

    int32_t Start(const PlayInfoHolder& PlayInfoHolder) override;

    int32_t UpdateMediaInfo(const MediaInfo& mediaInfo) override;

    int32_t SendControlCommand(const AVCastControlCommand& cmd) override;

    int32_t RegisterCallback(const std::shared_ptr<AVCastControllerCallback>& callback) override;

    int32_t GetDuration(int32_t& duration) override;

    int32_t GetPosition(int32_t& position) override;

    int32_t GetVolume(int32_t& volume) override;

    int32_t GetLoopMode(int32_t& loopMode) override;

    int32_t GetPlaySpeed(int32_t& playSpeed) override;

    int32_t GetPlayState(AVCastPlayerState& playerState) override;

    int32_t SetDisplaySurface(std::string& surfaceId) override;

    int32_t Destroy() override;
    
protected:
    int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) override;

private:
    static inline BrokerDelegator<AVCastControllerProxy> delegator_;
    AVPlaybackState currentState_;
    bool isDestroy_ = false;

    std::recursive_mutex controllerProxyLock_;
};
}

#endif // OHOS_AVCAST_CONTROLLER_PROXY_H
