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

#ifndef OHOS_NAPI_AVCAST_CONTROLLER_CALLBACK_H
#define OHOS_NAPI_AVCAST_CONTROLLER_CALLBACK_H

#include <list>
#include "avsession_info.h"
#include "avsession_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_async_callback.h"

namespace OHOS::AVSession {
class NapiAVCastControllerCallback : public AVCastControllerCallback {
public:
    enum {
        EVENT_CAST_STATE_CHANGE,
        EVENT_CAST_MEDIA_ITEM_CHANGE,
        EVENT_CAST_VOLUME_CHANGE,
        EVENT_CAST_LOOP_MODE_CHANGE,
        EVENT_CAST_PLAY_SPEED_CHANGE,
        EVENT_CAST_POSITON_CHANGE,
        EVENT_CAST_VIDEO_SIZE_CHANGE,
        EVENT_CAST_ERROR,
        EVENT_CAST_TYPE_MAX,
    };

    NapiAVCastControllerCallback();
    ~NapiAVCastControllerCallback() override;

    void OnStateChange(const AVCastPlayerState& state) override;
    void OnMediaItemChange(const AVQueueItem& avQueueItem) override;
    void OnVolumeChange(const int32_t volume) override;
    void OnLoopModeChange(const int32_t loopMode) override;
    void OnPlaySpeedChange(const int32_t playSpeed) override;
    void OnPositionChange(const int32_t position, const int32_t bufferPosition, const int32_t duration) override;
    void OnVideoSizeChange(const int32_t width, const int32_t height) override;
    void OnError(const int32_t errorCode, const std::string& errorMsg) override;

    napi_status AddCallback(napi_env env, int32_t event, napi_value callback);
    napi_status RemoveCallback(napi_env env, int32_t event, napi_value callback);

private:
    void HandleEvent(int32_t event);

    template<typename T>
    void HandleEvent(int32_t event, const T& param);

    template<typename T>
    void HandleEvent(int32_t event, const std::string& firstParam, const T& secondParam);

    template<typename T>
    void HandleEvent(int32_t event, const int32_t firstParam, const T& secondParam);

    void HandleEvent(int32_t event, const int32_t firstParam, const int32_t secondParam, const int32_t thirdParam);

    std::mutex lock_;
    std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    std::list<napi_ref> callbacks_[EVENT_CAST_TYPE_MAX] {};
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVCAST_CONTROLLER_CALLBACK_H
