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

#ifndef OHOS_AVCONTROLLER_ITEM_H
#define OHOS_AVCONTROLLER_ITEM_H

#include <string>

#include "avcontroller_callback_proxy.h"
#include "avsession_controller_stub.h"

namespace OHOS::AVSession {
class AVSessionItem;
class AVControllerItem : public AVSessionControllerStub {
public:
    AVControllerItem(pid_t pid, sptr<AVSessionItem> &session);

    ~AVControllerItem() override;

    int32_t GetAVPlaybackState(AVPlaybackState &state) override;

    int32_t GetAVMetaData(AVMetaData &data) override;

    int32_t sendMediaButtonEvent(MMI::KeyEvent& keyEvent) override;

    int32_t GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent &ability) override;

    int32_t GetSupportedCommand(std::vector<int32_t> &cmds) override;

    int32_t IsSessionActive(bool &isActive) override;

    int32_t SendCommand(AVControlCommand &cmd) override;

    int32_t SetMetaFilter(const AVMetaData::MetaMaskType &filter) override;

    int32_t Release() override;

    void HandleSessionRelease(const AVSessionDescriptor &descriptor);

    void HandlePlaybackStateChange(const AVPlaybackState &state);

    void HandleMetaDataChange(const AVMetaData &data);

    void HandleActiveStateChange(bool isActive);

    pid_t GetPid() const;

    void ClearSession();

    bool HasSession(int32_t sessionId);

    void SetServiceCallbackForRelease(const std::function<void(AVControllerItem&)>& callback);

protected:
    int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) override;

private:
    pid_t pid_;
    sptr<AVSessionItem> session_;
    sptr<IAVControllerCallback> callback_;
    AVMetaData::MetaMaskType metaMask_;
    std::function<void(AVControllerItem&)> serviceCallback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCONTROLLER_ITEM_H