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

#ifndef OHOS_AVSESSION_CONTROLLER_PROXY_H
#define OHOS_AVSESSION_CONTROLLER_PROXY_H

#include <mutex>

#include "iavsession_controller.h"
#include "iremote_proxy.h"

namespace OHOS::AVSession {
class AVSessionControllerProxy : public IRemoteProxy<IAVSessionController> {
public:
    explicit AVSessionControllerProxy(const sptr<IRemoteObject>& impl);

    ~AVSessionControllerProxy() override;

    int32_t GetAVCallState(AVCallState& avCallState) override;

    int32_t GetAVCallMetaData(AVCallMetaData& avCallMetaData) override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

    int32_t GetAVMetaData(AVMetaData& data) override;

    int32_t SendAVKeyEvent(const MMI::KeyEvent& keyEvent) override;

    int32_t GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent& ability) override;

    int32_t GetValidCommands(std::vector<int32_t>& cmds) override;

    int32_t IsSessionActive(bool& isActive) override;

    int32_t SendControlCommand(const AVControlCommand& cmd) override;

    int32_t SendCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) override;

    int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback) override;

    int32_t SetAVCallMetaFilter(const AVCallMetaData::AVCallMetaMaskType& filter) override;

    int32_t SetAVCallStateFilter(const AVCallState::AVCallStateMaskType& filter) override;

    int32_t SetMetaFilter(const AVMetaData::MetaMaskType& filter) override;

    int32_t SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) override;

    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;

    int32_t GetAVQueueTitle(std::string& title) override;

    int32_t SkipToQueueItem(int32_t& itemId) override;

    int32_t GetExtras(AAFwk::WantParams& extras) override;

    int32_t Destroy() override;

    std::string GetSessionId() override;

    int64_t GetRealPlaybackPosition() override;

    bool IsDestroy() override;

protected:
    int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) override;

private:
    static inline BrokerDelegator<AVSessionControllerProxy> delegator_;
    const size_t defaultIpcCapacity = 1048576; // Increase the IPC default capacity(200K) to 1M
    std::recursive_mutex currentStateLock_;
    AVPlaybackState currentState_;
    bool isDestroy_ = false;
    const int32_t MAX_ITEM_NUMBER = 1000;
    const int32_t MAX_IMAGE_SIZE = 10 * 1024 * 1024;

    std::recursive_mutex controllerProxyLock_;
};
}

#endif // OHOS_AVSESSION_CONTROLLER_PROXY_H