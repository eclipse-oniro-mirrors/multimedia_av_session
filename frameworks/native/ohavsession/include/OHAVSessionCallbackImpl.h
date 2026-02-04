/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_OHAVSESSION_CALLBACKIMPL_H
#define OHOS_OHAVSESSION_CALLBACKIMPL_H

#include "native_avmetadata.h"
#include "native_avsession.h"
#include "avsession_info.h"

namespace OHOS::AVSession {

class OHAVSessionCallbackImpl : public AVSessionCallback {
public:
    OHAVSessionCallbackImpl();
    ~OHAVSessionCallbackImpl() override;
    void InitSharedPtrMember();

    void OnPlay(const AVControlCommand& cmd) override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext(const AVControlCommand& cmd) override;
    void OnPlayPrevious(const AVControlCommand& cmd) override;
    void OnFastForward(int64_t time, const AVControlCommand& cmd) override;
    void OnRewind(int64_t time, const AVControlCommand& cmd) override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override {};
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediaId) override;
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override {};
    void OnOutputDeviceChange(const int32_t connectionState,
        const OHOS::AVSession::OutputDeviceInfo& outputDeviceInfo) override;
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override {};
    void OnSkipToQueueItem(int32_t itemId) override {};
    void OnAVCallAnswer() override {};
    void OnAVCallHangUp() override {};
    void OnAVCallToggleCallMute() override {};
    void OnPlayFromAssetId(int64_t assetId) override {};
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override {};

    AVSession_ErrCode SetPlayCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback, void* userData);
    AVSession_ErrCode SetPauseCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback, void* userData);
    AVSession_ErrCode SetStopCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback, void* userData);
    AVSession_ErrCode SetPlayNextCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback, void* userData);
    AVSession_ErrCode SetPlayPreviousCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback, void* userData);
    AVSession_ErrCode UnSetPlayCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback);
    AVSession_ErrCode UnSetPauseCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback);
    AVSession_ErrCode UnSetStopCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback);
    AVSession_ErrCode UnSetPlayNextCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback);
    AVSession_ErrCode UnSetPlayPreviousCallback(OH_AVSession* avsession, AVSession_ControlCommand command,
        OH_AVSessionCallback_OnCommand callback);

    AVSession_ErrCode RegisterForwardCallback(OH_AVSession* avsession,
        OH_AVSessionCallback_OnFastForward callback, void* userData);
    AVSession_ErrCode UnregisterForwardCallback(OH_AVSession* avsession,
        OH_AVSessionCallback_OnFastForward callback);
    AVSession_ErrCode RegisterRewindCallback(OH_AVSession* avsession,
        OH_AVSessionCallback_OnRewind callback, void* userData);
    AVSession_ErrCode UnregisterRewindCallback(OH_AVSession* avsession,
        OH_AVSessionCallback_OnRewind callback);
    AVSession_ErrCode RegisterSeekCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSeek callback, void* userData);
        AVSession_ErrCode UnregisterSeekCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSeek callback);
    AVSession_ErrCode RegisterSetLoopModeCallback(OH_AVSession* avsession,
        OH_AVSessionCallback_OnSetLoopMode callback, void* userData);
    AVSession_ErrCode UnregisterSetLoopModeCallback(OH_AVSession* avsession,
        OH_AVSessionCallback_OnSetLoopMode callback);
    AVSession_ErrCode RegisterToggleFavoriteCallback(OH_AVSession* session,
        OH_AVSessionCallback_OnToggleFavorite callback, void* userData);
    AVSession_ErrCode UnregisterToggleFavoriteCallback(OH_AVSession* session,
        OH_AVSessionCallback_OnToggleFavorite callback);
    AVSession_ErrCode RegisterOutputDeviceChangeCallback(OH_AVSession* session,
        OH_AVSessionCallback_OutputDeviceChange callback);
    AVSession_ErrCode UnregisterOutputDeviceChangeCallback(OH_AVSession* session,
        OH_AVSessionCallback_OutputDeviceChange callback);

private:
    OH_AVSession* avsession_ = {nullptr};
    std::vector<std::pair<OH_AVSessionCallback_OnCommand, void*>> playCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnCommand, void*>> pauseCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnCommand, void*>> stopCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnCommand, void*>> playNextCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnCommand, void*>> playPreviousCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnFastForward, void*>> forwardCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnRewind, void*>> rewindCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnSeek, void*>> seekCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnSetLoopMode, void*>> setLoopModeCallbacks_;
    std::vector<std::pair<OH_AVSessionCallback_OnToggleFavorite, void*>> toggleFavoriteCallbacks_;
    std::vector<OH_AVSessionCallback_OutputDeviceChange> outputDeviceChangeCallbacks_;
};
}
#endif // OHOS_OHAVSESSION_CALLBACKIMPL_H