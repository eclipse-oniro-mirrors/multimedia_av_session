/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_AVSESSION_CALLBACK_PROXY_H
#define OHOS_AVSESSION_CALLBACK_PROXY_H

#include "iremote_proxy.h"
#include "iavsession_callback.h"

namespace OHOS::AVSession {
class AVSessionCallbackProxy : public IRemoteProxy<IAVSessionCallback> {
public:
    explicit AVSessionCallbackProxy(const sptr<IRemoteObject>& impl);
    void OnAVCallAnswer() override;
    void OnAVCallHangUp() override;
    void OnAVCallToggleCallMute() override;
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward(int64_t time) override;
    void OnRewind(int64_t time) override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediaId) override;
    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override;
    void OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) override;
    void OnSkipToQueueItem(int32_t itemId) override;
    void OnPlayFromAssetId(int64_t assetId) override;
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override;
private:
    static inline BrokerDelegator<AVSessionCallbackProxy> delegator_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CALLBACK_PROXY_H