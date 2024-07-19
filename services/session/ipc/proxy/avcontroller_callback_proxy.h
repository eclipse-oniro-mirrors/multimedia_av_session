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

#ifndef OHOS_AVCONTROLLER_CALLBACK_PROXY_H
#define OHOS_AVCONTROLLER_CALLBACK_PROXY_H

#include <mutex>

#include "iavcontroller_callback.h"
#include "iremote_proxy.h"

namespace OHOS::AVSession {
class AVControllerCallbackProxy : public IRemoteProxy<IAVControllerCallback> {
public:
    explicit AVControllerCallbackProxy(const sptr<IRemoteObject>& impl);

    void OnSessionDestroy() override;

    void OnAVCallMetaDataChange(const AVCallMetaData& data) override;

    void OnAVCallStateChange(const AVCallState& state) override;

    void OnPlaybackStateChange(const AVPlaybackState& state) override;

    void OnMetaDataChange(const AVMetaData& data) override;

    void OnActiveStateChange(bool isActive) override;

    void OnValidCommandChange(const std::vector<int32_t>& cmds) override;

    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override;

    void OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args) override;

    void OnQueueItemsChange(const std::vector<AVQueueItem>& items) override;

    void OnQueueTitleChange(const std::string& title) override;

    void OnExtrasChange(const AAFwk::WantParams& extras) override;

private:
    int32_t GetPixelMapBuffer(AVMetaData& metaData, MessageParcel& parcel);
    static inline BrokerDelegator<AVControllerCallbackProxy> delegator_;
    std::mutex onMetadataChangeLock_;
    std::mutex onPlaybackChangeLock_;
    std::mutex onValidCommandChangeLock_;
    const size_t defaultIpcCapacity = 1048576; // Increase the IPC default capacity(200K) to 1M
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCONTROLLER_CALLBACK_PROXY_H