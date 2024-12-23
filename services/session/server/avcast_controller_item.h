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
#include "avcast_control_command.h"

namespace OHOS::AVSession {
class AVCastControllerItem : public AVCastControllerStub, public IAVCastControllerProxyListener,
    public std::enable_shared_from_this<IAVCastControllerProxyListener> {
public:
    AVCastControllerItem();

    ~AVCastControllerItem();

    void Init(std::shared_ptr<IAVCastControllerProxy> castControllerProxy,
        const std::function<void(int32_t, std::vector<int32_t>&)>& validCommandsChangecallback,
        const std::function<void()>& preparecallback);

    void OnCastPlaybackStateChange(const AVPlaybackState& state) override;

    void OnMediaItemChange(const AVQueueItem& avQueueItem) override;

    void OnPlayNext() override;

    void OnPlayPrevious() override;

    void OnSeekDone(const int32_t seekNumber) override;

    void OnVideoSizeChange(const int32_t width, const int32_t height) override;

    void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) override;

    void OnEndOfStream(const int32_t isLooping) override;

    void OnPlayRequest(const AVQueueItem& avQueueItem) override;

    void OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData) override;

    void OnValidCommandChange(const std::vector<int32_t> &cmds) override;

    int32_t SendControlCommand(const AVCastControlCommand& cmd) override;

    int32_t Start(const AVQueueItem& avQueueItem) override;

    int32_t Prepare(const AVQueueItem& avQueueItem) override;

    int32_t GetDuration(int32_t& duration) override;

    int32_t GetCastAVPlaybackState(AVPlaybackState& avPlaybackState) override;

    int32_t GetCurrentItem(AVQueueItem& currentItem) override;

    int32_t GetValidCommands(std::vector<int32_t>& cmds) override;

    int32_t SetDisplaySurface(std::string& surfaceId) override;

    int32_t SetCastPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) override;

    int32_t ProcessMediaKeyResponse(const std::string& assetId, const std::vector<uint8_t>& response) override;

    bool RegisterControllerListener(std::shared_ptr<IAVCastControllerProxy> castControllerProxy);

    int32_t AddAvailableCommand(const int32_t cmd) override;

    int32_t RemoveAvailableCommand(const int32_t cmd) override;

    int32_t HandleCastValidCommandChange(const std::vector<int32_t> &cmds);

    void SetSessionTag(const std::string& tag);

    int32_t Destroy() override;

protected:
    int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) override;

private:
    std::shared_ptr<IAVCastControllerProxy> castControllerProxy_;
    sptr<IAVCastControllerCallback> callback_;
    std::recursive_mutex itemCallbackLock_;
    AVPlaybackState::PlaybackStateMaskType castPlaybackMask_;
    AVQueueItem currentAVQueueItem_;
    std::vector<int32_t> supportedCastCmds_;
    std::function<void(int32_t, std::vector<int32_t>&)> validCommandsChangecallback_;
    std::function<void()> preparecallback_;
    int32_t removeCmdStep_ = 1000;
    int32_t currentState_ = AVPlaybackState::PLAYBACK_STATE_INITIAL;
    std::string sessionTag_;
    bool isSessionCallbackAvailable_ = true;
    std::mutex callbackToSessionLock_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCAST_CONTROLLER_ITEM_H
