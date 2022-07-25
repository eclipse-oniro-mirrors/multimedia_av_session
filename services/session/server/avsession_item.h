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

#ifndef OHOS_AVSESSION_ITEM_H
#define OHOS_AVSESSION_ITEM_H

#include <string>
#include <map>
#include "avsession_stub.h"
#include "avsession_callback_proxy.h"
#include "avcontrol_command.h"
#include "want_agent_adapter.h"

namespace OHOS::AVSession {
class AVControllerItem;
class AVSessionItem : public AVSessionStub {
public:
    explicit AVSessionItem(const AVSessionDescriptor& descriptor);

    ~AVSessionItem() override;

    std::string GetSessionId() override;

    int32_t GetAVMetaData(AVMetaData& meta) override;

    int32_t SetAVMetaData(const AVMetaData& meta) override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

    int32_t Activate() override;

    int32_t Deactivate() override;

    bool IsActive() override;

    int32_t Destroy() override;

    int32_t AddSupportCommand(int32_t cmd) override;

    int32_t DeleteSupportCommand(int32_t cmd) override;

    AVSessionDescriptor GetDescriptor();

    int32_t SetAVPlaybackState(const AVPlaybackState& state) override;

    AVPlaybackState GetPlaybackState();

    AVMetaData GetMetaData();

    std::vector<int32_t> GetSupportCommand();

    sptr<WantAgentAdapter> GetLaunchAbility();

    void HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent);

    void ExecuteControllerCommand(const AVControlCommand& cmd);

    int32_t AddController(pid_t pid, sptr<AVControllerItem>& controller);

    int32_t RegisterCallbackForRemote(std::shared_ptr<AVSessionCallback>& callback);

    int32_t UnRegisterCallbackForRemote();

    void SetPid(pid_t pid);

    void SetUid(uid_t uid);

    pid_t GetPid() const;

    pid_t GetUid() const;

    std::string GetAbilityName() const;

    void SetTop(bool top);

    void HandleControllerRelease(pid_t pid);

    void SetServiceCallbackForRelease(const std::function<void(AVSessionItem&)>& callback);

protected:
    int32_t RegisterCallbackInner(const sptr<IAVSessionCallback>& callback) override;
    sptr<IRemoteObject> GetControllerInner() override;
    int32_t SetLaunchAbilityInner(const sptr<WantAgentAdapter>& ability) override;

private:
    void HandleOnPlay(const AVControlCommand& cmd);
    void HandleOnPause(const AVControlCommand& cmd);
    void HandleOnStop(const AVControlCommand& cmd);
    void HandleOnPlayNext(const AVControlCommand& cmd);
    void HandleOnPlayPrevious(const AVControlCommand& cmd);
    void HandleOnFastForward(const AVControlCommand& cmd);
    void HandleOnRewind(const AVControlCommand& cmd);
    void HandleOnSeek(const AVControlCommand& cmd);
    void HandleOnSetSpeed(const AVControlCommand& cmd);
    void HandleOnSetLoopMode(const AVControlCommand& cmd);
    void HandleOnToggleFavorite(const AVControlCommand& cmd);

    using HandlerFuncType = void(AVSessionItem::*)(const AVControlCommand&);
    static inline HandlerFuncType cmdHandlers[] = {
        [AVControlCommand::SESSION_CMD_PLAY] = &AVSessionItem::HandleOnPlay,
        [AVControlCommand::SESSION_CMD_PAUSE] = &AVSessionItem::HandleOnPause,
        [AVControlCommand::SESSION_CMD_STOP] = &AVSessionItem::HandleOnStop,
        [AVControlCommand::SESSION_CMD_PLAY_NEXT] = &AVSessionItem::HandleOnPlayNext,
        [AVControlCommand::SESSION_CMD_PLAY_PREVIOUS] = &AVSessionItem::HandleOnPlayPrevious,
        [AVControlCommand::SESSION_CMD_FAST_FORWARD] = &AVSessionItem::HandleOnFastForward,
        [AVControlCommand::SESSION_CMD_REWIND] = &AVSessionItem::HandleOnRewind,
        [AVControlCommand::SESSION_CMD_SEEK] = &AVSessionItem::HandleOnSeek,
        [AVControlCommand::SESSION_CMD_SET_SPEED] = &AVSessionItem::HandleOnSetSpeed,
        [AVControlCommand::SESSION_CMD_SET_LOOP_MODE] = &AVSessionItem::HandleOnSetLoopMode,
        [AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE] = &AVSessionItem::HandleOnToggleFavorite,
    };

    std::recursive_mutex lock_;
    std::map<pid_t, sptr<AVControllerItem>> controllers_;
    AVSessionDescriptor descriptor_;
    AVPlaybackState playbackState_;
    AVMetaData metaData_;
    sptr<WantAgentAdapter> launchAbility_;
    std::vector<int32_t> supportedCmd_;
    sptr<IAVSessionCallback> callback_;
    std::shared_ptr<AVSessionCallback> remoteCallback_;
    std::function<void(AVSessionItem&)> serviceCallback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_ITEM_H