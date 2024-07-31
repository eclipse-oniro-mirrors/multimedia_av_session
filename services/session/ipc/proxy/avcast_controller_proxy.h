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

    int32_t SendControlCommand(const AVCastControlCommand& cmd) override;

    int32_t Start(const AVQueueItem& avQueueItem) override;

    int32_t Prepare(const AVQueueItem& avQueueItem) override;

    int32_t SetCastPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) override;

    int32_t RegisterCallback(const std::shared_ptr<AVCastControllerCallback>& callback) override;

    int32_t GetDuration(int32_t& duration) override;

    int32_t GetCastAVPlaybackState(AVPlaybackState& state) override;

    int32_t GetCurrentItem(AVQueueItem& currentItem) override;

    int32_t GetValidCommands(std::vector<int32_t>& cmds) override;

    int32_t SetDisplaySurface(std::string& surfaceId) override;

    int32_t ProcessMediaKeyResponse(const std::string& assetId, const std::vector<uint8_t>& response) override;

    int32_t AddAvailableCommand(const int32_t cmd) override;

    int32_t RemoveAvailableCommand(const int32_t cmd) override;

    int32_t Destroy() override;
    
protected:
    int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) override;

private:
    static inline BrokerDelegator<AVCastControllerProxy> delegator_;
    AVPlaybackState currentState_;
    bool isDestroy_ = false;

    std::recursive_mutex controllerProxyLock_;
    const size_t defaultIpcCapacity = 1048576; // Increase the IPC default capacity(200K) to 1M
};
}
#endif // OHOS_AVCAST_CONTROLLER_PROXY_H
