/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "iavsession_controller.h"
#include "iremote_proxy.h"

namespace OHOS::AVSession {
class AVSessionControllerProxy : public IRemoteProxy<IAVSessionController> {
public:
    explicit AVSessionControllerProxy(const sptr<IRemoteObject> &impl);

    int32_t GetAVPlaybackState(AVPlaybackState &state) override;

    int32_t GetAVMetaData(AVMetadata &data) override;

    int32_t GetAVVolumeInfo(AVVolumeInfo &info) override;

    int32_t SendSystemMediaKeyEvent(MMI::KeyEvent& keyEvent) override;

    int32_t GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent &ability) override;

    int32_t GetSupportedCommand(std::vector<int32_t> &cmds) override;

    int32_t IsSessionActive(bool &isActive) override;

    int32_t SendCommand(AVControlCommand &cmd) override;

    int32_t RegisterCallback(std::shared_ptr<AVControllerCallback> &callback) override;

    int32_t SetMetaFilter(std::bitset<AVMetadata::META_KEY_MAX> &filter) override;

    int32_t Release() override;

protected:
    int32_t RegisterCallbackInner(const sptr<IAVControllerCallback>& callback) override;

private:
    static inline BrokerDelegator<AVSessionControllerProxy> delegator_;
};
}

#endif // OHOS_AVSESSION_CONTROLLER_PROXY_H