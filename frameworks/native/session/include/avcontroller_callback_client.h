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

#ifndef OHOS_AVCONTROLLER_CALLBACK_CLIENT_H
#define OHOS_AVCONTROLLER_CALLBACK_CLIENT_H

#include "av_controller_callback_stub.h"
#include "avsession_info.h"

namespace OHOS::AVSession {
class AVControllerCallbackClient : public AVControllerCallbackStub {
public:
    explicit AVControllerCallbackClient(const std::shared_ptr<AVControllerCallback>& callback);
    ~AVControllerCallbackClient();

    ErrCode OnSessionDestroy() override;

    ErrCode OnAVCallMetaDataChange(const AVCallMetaData& data) override;

    ErrCode OnAVCallStateChange(const AVCallState& state) override;

    ErrCode OnPlaybackStateChange(const AVPlaybackState& state) override;

    ErrCode OnMetaDataChange(const AVMetaData& data) override;

    ErrCode OnActiveStateChange(bool isActive) override;

    ErrCode OnValidCommandChange(const std::vector<int32_t>& cmds) override;

    ErrCode OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& info) override;

    ErrCode AddListenerForPlaybackState(const std::function<void(const AVPlaybackState&)>& listener);

    ErrCode RemoveListenerForPlaybackState();

    ErrCode OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args) override;

    ErrCode OnQueueItemsChange(const std::vector<AVQueueItem>& items) override;

    ErrCode OnQueueTitleChange(const std::string& title) override;

    ErrCode OnExtrasChange(const AAFwk::WantParams& extras) override;

    ErrCode OnCustomData(const AAFwk::WantParams& extras) override;

    ErrCode OnDesktopLyricVisibilityChanged(bool isVisible) override;

    ErrCode OnDesktopLyricStateChanged(const DesktopLyricState& state) override;
private:
    std::shared_ptr<AVControllerCallback> callback_;
    std::function<void(const AVPlaybackState&)> playbackStateListener_;
    static constexpr const char* EVENT_NAME = "AVControllerCallback";
};
}
#endif // OHOS_AVCONTROLLER_CALLBACK_CLIENT_H