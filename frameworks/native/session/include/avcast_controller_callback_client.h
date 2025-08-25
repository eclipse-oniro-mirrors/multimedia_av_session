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

#ifndef OHOS_AVCAST_CONTROLLER_CALLBACK_CLIENT_H
#define OHOS_AVCAST_CONTROLLER_CALLBACK_CLIENT_H

#include "av_cast_controller_callback_stub.h"
#include "avsession_info.h"

namespace OHOS::AVSession {
class AVCastControllerCallbackClient : public AVCastControllerCallbackStub {
public:
    explicit AVCastControllerCallbackClient(const std::shared_ptr<AVCastControllerCallback>& callback);
    ~AVCastControllerCallbackClient();

    ErrCode OnCastPlaybackStateChange(const AVPlaybackState& state) override;

    ErrCode OnMediaItemChange(const AVQueueItem& avQueueItem) override;

    ErrCode OnPlayNext() override;

    ErrCode OnPlayPrevious() override;

    ErrCode OnSeekDone(const int32_t seekNumber) override;

    ErrCode OnVideoSizeChange(const int32_t width, const int32_t height) override;

    ErrCode OnPlayerError(const int32_t errorCode, const std::string& errorMsg) override;

    ErrCode OnEndOfStream(const int32_t isLooping) override;

    ErrCode OnPlayRequest(const AVQueueItem& avQueueItem) override;

    ErrCode OnKeyRequest(const std::string &assetId, const std::vector<uint8_t> &keyRequestData) override;

    ErrCode OnCastValidCommandChanged(const std::vector<int32_t>& cmds) override;

    ErrCode onDataSrcRead(const std::shared_ptr<AVSharedMemoryBase>& mem, uint32_t length,
        int64_t pos, int32_t& result) override;

    ErrCode OnCustomData(const AAFwk::WantParams& extras) override;

    void AddListenerForCastPlaybackState(const std::function<void(const AVPlaybackState&)>& listener);

private:
    std::function<void(const AVPlaybackState&)> castPlaybackStateListener_;
    std::shared_ptr<AVCastControllerCallback> callback_;
    static constexpr const char* EVENT_NAME = "AVCastControllerCallback";
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCAST_CONTROLLER_CALLBACK_CLIENT_H
