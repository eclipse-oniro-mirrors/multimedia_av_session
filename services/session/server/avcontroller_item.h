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

#ifndef OHOS_AVCONTROLLER_ITEM_H
#define OHOS_AVCONTROLLER_ITEM_H

#include <string>

#include "avsession_item.h"
#include "avcontroller_callback_proxy.h"
#include "avsession_controller_stub.h"
#include "audio_info.h"

namespace OHOS::AVSession {
class AVControllerItem : public AVSessionControllerStub {
public:
    AVControllerItem(pid_t pid, const sptr<AVSessionItem>& session);

    ~AVControllerItem() override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

    int32_t GetAVMetaData(AVMetaData& data) override;
    
    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;

    int32_t GetAVQueueTitle(std::string& title) override;

    int32_t SkipToQueueItem(int32_t& itemId) override;

    int32_t GetExtras(AAFwk::WantParams& extras) override;

    int32_t SendAVKeyEvent(const MMI::KeyEvent& keyEvent) override;

    int32_t GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent& ability) override;

    int32_t GetValidCommands(std::vector<int32_t>& cmds) override;

    int32_t IsSessionActive(bool& isActive) override;

    int32_t SendControlCommand(const AVControlCommand& cmd) override;

    int32_t SendCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) override;

    int32_t SetMetaFilter(const AVMetaData::MetaMaskType& filter) override;

    int32_t SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) override;

    int32_t Destroy() override;

    std::string GetSessionId() override;

    void HandleSessionDestroy();

    void HandlePlaybackStateChange(const AVPlaybackState& state);

    void HandleMetaDataChange(const AVMetaData& data);

    void HandleActiveStateChange(bool isActive);

    void HandleValidCommandChange(const std::vector<int32_t>& cmds);

    void HandleOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo);

    void HandleSetSessionEvent(const std::string& event, const AAFwk::WantParams& args);

    void HandleQueueItemsChange(const std::vector<AVQueueItem>& items);
    
    void HandleQueueTitleChange(const std::string& title);

    void HandleExtrasChange(const AAFwk::WantParams& extras);

    pid_t GetPid() const;

    bool HasSession(const std::string& sessionId);

    void SetServiceCallbackForRelease(const std::function<void(AVControllerItem&)>& callback);

protected:
    int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) override;

private:
    pid_t pid_;
    std::string sessionId_;
    sptr<AVSessionItem> session_;
    sptr<IAVControllerCallback> callback_;
    AVMetaData::MetaMaskType metaMask_;
    AVPlaybackState::PlaybackStateMaskType playbackMask_;
    std::function<void(AVControllerItem&)> serviceCallback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCONTROLLER_ITEM_H