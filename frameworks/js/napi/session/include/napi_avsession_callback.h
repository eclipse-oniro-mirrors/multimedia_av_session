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

#ifndef OHOS_NAPI_AVSESSION_CALLBACK_H
#define OHOS_NAPI_AVSESSION_CALLBACK_H

#include <list>
#include "avsession_info.h"
#include "key_event.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_async_callback.h"

namespace OHOS::AVSession {
class NapiAVSessionCallback : public AVSessionCallback {
public:
    enum {
        EVENT_PLAY,
        EVENT_PAUSE,
        EVENT_STOP,
        EVENT_PLAY_NEXT,
        EVENT_PLAY_PREVIOUS,
        EVENT_FAST_FORWARD,
        EVENT_REWIND,
        EVENT_SEEK,
        EVENT_SET_SPEED,
        EVENT_SET_LOOP_MODE,
        EVENT_TOGGLE_FAVORITE,
        EVENT_MEDIA_KEY_EVENT,
        EVENT_OUTPUT_DEVICE_CHANGED,
        EVENT_TYPE_MAX
    };

    NapiAVSessionCallback();
    ~NapiAVSessionCallback() override;

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
    void OnToggleFavorite(const std::string& assertId) override;
    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;

    napi_status AddCallback(napi_env env, int32_t event, napi_value callback);
    napi_status RemoveCallback(napi_env env, int32_t event, napi_value callback);

private:
    void HandleEvent(int32_t event);

    template<typename T>
    void HandleEvent(int32_t event, const T& param);

    std::mutex lock_;
    std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    std::list<napi_ref> callbacks_[EVENT_TYPE_MAX] {};
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVSESSION_CALLBACK_H