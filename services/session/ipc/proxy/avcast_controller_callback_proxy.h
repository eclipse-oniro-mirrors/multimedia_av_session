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

#ifndef OHOS_AVCAST_CONTROLLER_CALLBACK_PROXY_H
#define OHOS_AVCAST_CONTROLLER_CALLBACK_PROXY_H

#include "iavcast_controller_callback.h"
#include "iremote_proxy.h"

namespace OHOS::AVSession {
class AVCastControllerCallbackProxy : public IRemoteProxy<IAVCastControllerCallback> {
public:
    explicit AVCastControllerCallbackProxy(const sptr<IRemoteObject>& impl);

    void OnCastPlaybackStateChange(const AVPlaybackState& state) override;

    void OnMediaItemChange(const AVQueueItem& avQueueItem) override;

    void OnPlayNext() override;

    void OnPlayPrevious() override;

    void OnSeekDone(const int32_t seekNumber) override;

    void OnVideoSizeChange(const int32_t width, const int32_t height) override;
    
    void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) override;

private:
    static inline BrokerDelegator<AVCastControllerCallbackProxy> delegator_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCONTROLLER_CALLBACK_PROXY_H