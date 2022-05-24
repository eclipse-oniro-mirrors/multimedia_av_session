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

#ifndef OHOS_AVSESSION_ITEM_H
#define OHOS_AVSESSION_ITEM_H

#include <string>
#include <map>
#include "avsession_stub.h"
#include "avsession_callback_proxy.h"

namespace OHOS::AVSession {
class AVControllerItem;
class AVSessionItem : public AVSessionStub {
public:
    explicit AVSessionItem(const AVSessionDescriptor& descriptor);

    ~AVSessionItem() override;

    int32_t GetSessionId() override;

    int32_t GetAVMetaData(AVMetaData& meta) override;

    int32_t SetAVMetaData(const AVMetaData& meta) override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

    int32_t SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability) override;

    std::shared_ptr<AVSessionController> GetController() override;

    int32_t RegisterCallback(std::shared_ptr<AVSessionCallback>& callback) override;

    int32_t Active() override;

    int32_t Disactive() override;

    bool IsActive() override;

    int32_t Release() override;

    int32_t AddSupportCommand(const std::string& cmd) override;

    AVSessionDescriptor GetDescriptor();

    AVPlaybackState GetPlaybackState();

    AVMetaData GetMetaData();

    std::vector<std::string> GetSupportCommand();

    void ExecuteControllerCommand(const AVControlCommand& cmd);

    int32_t AddController(pid_t pid, sptr<AVControllerItem>& controller);

    int32_t RemoveController(pid_t pid);

    int32_t RegisterCallbackForRemote(std::shared_ptr<AVSessionCallback>& callback);

    int32_t UnRegisterCallbackForRemote();

    void SetPid(pid_t pid);

    void SetUid(uid_t uid);

    pid_t GetPid();

    uid_t GetUid();

protected:
    int32_t RegisterCallbackInner(sptr<IRemoteObject>& callback) override;

private:
    std::map<pid_t, sptr<AVControllerItem>> controllers_;
    AVSessionDescriptor descriptor_;
    AVPlaybackState playbackState_;
    AVMetaData metaData_;
    pid_t pid_ {};
    uid_t uid_ {};
    AbilityRuntime::WantAgent::WantAgent launchAbility_;
    std::vector<std::string> supportedCmd_;
    sptr<AVSessionCallbackProxy> callback_;
    std::shared_ptr<AVSessionCallback> remoteCallback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_ITEM_H