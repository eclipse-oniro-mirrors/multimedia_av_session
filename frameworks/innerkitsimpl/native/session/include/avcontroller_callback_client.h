/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "avcontroller_callback_stub.h"
#include "avsession_info.h"

namespace OHOS::AVSession {
class AVControllerCallbackClient : public AVControllerCallbackStub {
public:
    explicit AVControllerCallbackClient(const std::shared_ptr<AVControllerCallback>& callback);

    void OnSessionDestroy() override;

    void OnPlaybackStateChange(const AVPlaybackState &state) override;

    void OnMetaDataChange(const AVMetaData &data) override;

    void OnActiveStateChange(bool isActive) override;

    void OnValidCommandChange(const std::vector<int32_t> &cmds) override;

    void AddListenerForPlaybackState(const std::function<void(const AVPlaybackState&)> &listener);

private:
    std::shared_ptr<AVControllerCallback> callback_;
    std::function<void(const AVPlaybackState&)> playbackStateListener_;
};
}
#endif // OHOS_AVCONTROLLER_CALLBACK_CLIENT_H