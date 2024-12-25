/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CJ_AVSESSION_CAST_CONTROLLER_CALLBACK_H
#define OHOS_CJ_AVSESSION_CAST_CONTROLLER_CALLBACK_H

#include <vector>
#include <list>
#include <functional>

#include "avsession_info.h"
#include "cj_avsession_prototypes.h"
#include "cj_avsession_cast_controller_ffi.h"

namespace OHOS::AVSession {

class CJAVCastControllerCallback : public AVCastControllerCallback {
    friend class CJAVCastControllerImpl;
protected:
    void AddCallback(DoCallFunc doCall);

public:
    enum {
        EVENT_CAST_PLAYBACK_STATE_CHANGE = 0,
        EVENT_CAST_MEDIA_ITEM_CHANGE,
        EVENT_CAST_PLAY_NEXT,
        EVENT_CAST_PLAY_PREVIOUS,
        EVENT_CAST_END_OF_STREAM,
        EVENT_CAST_REQUEST_PLAY,
        EVENT_CAST_SEEK_DONE,
        EVENT_CAST_VALID_COMMAND_CHANGED,
        EVENT_CAST_ERROR,
        EVENT_CAST_KEY_REQUEST,
        EVENT_CAST_TYPE_MAX,
    };

    CJAVCastControllerCallback();

    void OnCastPlaybackStateChange(const AVPlaybackState& state);

    void OnMediaItemChange(const AVQueueItem& avQueueItem);

    void OnPlayNext();

    void OnPlayPrevious();

    void OnSeekDone(const int32_t seekNumber);

    void OnVideoSizeChange(const int32_t width, const int32_t height);

    void OnPlayerError(const int32_t errorCode, const std::string& errorMsg);

    void OnEndOfStream(const int32_t isLooping);

    void OnPlayRequest(const AVQueueItem& avQueueItem);

    void OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData);

    void OnCastValidCommandChanged(const std::vector<int32_t> &cmds);
private:
    // std::shared_ptr<CJAVSessionCastControllerImpl> controller_;
    std::function<void(CCallbackData*)> doCall_;
};

} // namespace AVSession::OHOS

#endif // OHOS_CJ_AVSESSION_CAST_CONTROLLER_CALLBACK_H