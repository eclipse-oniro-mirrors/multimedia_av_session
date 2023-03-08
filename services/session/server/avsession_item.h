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
#include "audio_info.h"

namespace OHOS::AVSession {
class AVControllerItem;
class RemoteSessionSink;
class RemoteSessionSource;
class AVSessionItem : public AVSessionStub {
public:
    explicit AVSessionItem(const AVSessionDescriptor& descriptor);

    ~AVSessionItem() override;

    std::string GetSessionId() override;

    int32_t GetAVMetaData(AVMetaData& meta) override;

    int32_t SetAVMetaData(const AVMetaData& meta) override;

    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;

    int32_t SetAVQueueItems(const std::vector<AVQueueItem>& items) override;
    
    int32_t GetAVQueueTitle(std::string& title) override;

    int32_t SetAVQueueTitle(const std::string& title) override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

    int32_t SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability) override;

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

    std::vector<AVQueueItem> GetQueueItems();

    std::string GetQueueTitle();

    std::vector<int32_t> GetSupportCommand();

    AbilityRuntime::WantAgent::WantAgent GetLaunchAbility();

    void HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent);

    void HandleOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo);

    void HandleSkipToQueueItem(const int32_t& itemId);

    void ExecuteControllerCommand(const AVControlCommand& cmd);

    void ExecueCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs);

    int32_t AddController(pid_t pid, sptr<AVControllerItem>& controller);

    void SetPid(pid_t pid);

    void SetUid(pid_t uid);

    pid_t GetPid() const;

    pid_t GetUid() const;

    std::string GetAbilityName() const;

    std::string GetBundleName() const;

    void SetTop(bool top);

    std::shared_ptr<RemoteSessionSource> GetRemoteSource();

    void HandleControllerRelease(pid_t pid);

    void SetServiceCallbackForRelease(const std::function<void(AVSessionItem&)>& callback);

    void SetOutputDevice(const OutputDeviceInfo& info);

    void GetOutputDevice(OutputDeviceInfo& info);

    int32_t CastAudioToRemote(const std::string& sourceDevice, const std::string& sinkDevice,
                              const std::string& sinkCapability);

    int32_t SourceCancelCastAudio(const std::string& sinkDevice);

    int32_t CastAudioFromRemote(const std::string& sourceSessionId, const std::string& sourceDevice,
                                const std::string& sinkDevice, const std::string& sourceCapability);

    int32_t SinkCancelCastAudio();

    int32_t SetSessionEvent(const std::string& event, const AAFwk::WantParams& args) override;
protected:
    int32_t RegisterCallbackInner(const sptr<IAVSessionCallback>& callback) override;
    sptr<IRemoteObject> GetControllerInner() override;

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
    std::vector<AVQueueItem> queueItems_;
    std::string queueTitle_;
    AbilityRuntime::WantAgent::WantAgent launchAbility_;
    std::vector<int32_t> supportedCmd_;
    sptr<IAVSessionCallback> callback_;
    std::shared_ptr<AVSessionCallback> remoteCallback_;
    std::function<void(AVSessionItem&)> serviceCallback_;
    friend class AVSessionDumper;

    std::shared_ptr<RemoteSessionSource> remoteSource_;
    std::shared_ptr<RemoteSessionSink> remoteSink_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_ITEM_H