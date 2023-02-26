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

#ifndef OHOS_AVSESSION_CALLBACK_CLIENT_H
#define OHOS_AVSESSION_CALLBACK_CLIENT_H

#include "avsession_callback_stub.h"
#include "avsession_info.h"
#include "key_event.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
class AVSessionCallbackClient : public AVSessionCallbackStub {
public:
    explicit AVSessionCallbackClient(const std::shared_ptr<AVSessionCallback>& callback);
    ~AVSessionCallbackClient();

    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward() override;
    void OnRewind() override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediald) override;
    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;
    void OnOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo) override;
    void OnSkipToQueueItem(int32_t itemId) override;

private:
    std::shared_ptr<AVSessionCallback> callback_;
    static constexpr const char* EVENT_NAME = "AVSessionCallback";
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CALLBACK_CLIENT_H