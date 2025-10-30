/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_CALLBACK_CLIENT_H
#define OHOS_AVSESSION_CALLBACK_CLIENT_H

#include "av_session_callback_stub.h"
#include "avsession_info.h"
#include "key_event.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
class AVSessionCallbackClient : public AVSessionCallbackStub {
public:
    explicit AVSessionCallbackClient(const std::shared_ptr<AVSessionCallback>& callback);
    ~AVSessionCallbackClient();

    ErrCode OnAVCallAnswer() override;
    ErrCode OnAVCallHangUp() override;
    ErrCode OnAVCallToggleCallMute() override;
    ErrCode OnPlay(const AVControlCommand& cmd) override;
    ErrCode OnPause() override;
    ErrCode OnStop() override;
    ErrCode OnPlayNext(const AVControlCommand& cmd) override;
    ErrCode OnPlayPrevious(const AVControlCommand& cmd) override;
    ErrCode OnFastForward(int64_t time, const AVControlCommand& cmd) override;
    ErrCode OnRewind(int64_t time, const AVControlCommand& cmd) override;
    ErrCode OnSeek(int64_t time) override;
    ErrCode OnSetSpeed(double speed) override;
    ErrCode OnSetLoopMode(int32_t loopMode) override;
    ErrCode OnSetTargetLoopMode(int32_t targetLoopMode) override;
    ErrCode OnToggleFavorite(const std::string& mediaId) override;
    ErrCode OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;
    ErrCode OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override;
    ErrCode OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) override;
    ErrCode OnSkipToQueueItem(int32_t itemId) override;
    ErrCode OnPlayFromAssetId(int64_t assetId) override;
    ErrCode OnPlayWithAssetId(const std::string& assetId) override;
    ErrCode OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override;
    ErrCode OnCustomData(const AAFwk::WantParams& extras) override;

private:
    std::shared_ptr<AVSessionCallback> callback_;
    static constexpr const char* EVENT_NAME = "AVSessionCallback";
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CALLBACK_CLIENT_H