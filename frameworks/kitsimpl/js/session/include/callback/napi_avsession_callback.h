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

#include "avsession_info.h"
#include "key_event.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "utils/avsession_napi_utils.h"
#include "utils/uv_queue.h"

namespace OHOS {
namespace AVSession {
static const std::string PLAY_CALLBACK = "play";
static const std::string PAUSE_CALLBACK = "pause";
static const std::string STOP_CALLBACK = "stop";
static const std::string PLAYNEXT_CALLBACK = "playNext";
static const std::string PLAYPREVIOUS_CALLBACK = "playPrevious";
static const std::string FASTFORWARD_CALLBACK = "fastForward";
static const std::string REWIND_CALLBACK = "rewind";
static const std::string HANDLEKEYEVENT_CALLBACK = "handleKeyEvent";
static const std::string SEEK_CALLBACK = "seek";
static const std::string SETSPEED_CALLBACK = "setSpeed";
static const std::string SETLOOPMODE_CALLBACK = "setLoopMode";
static const std::string TOGGLEFAVORITE_CALLBACK = "toggleFavorite";
static const std::string OUTPUTDEVICECHANGED_CALLBACK = "outputDeviceChanged";
static const std::vector<std::string> CALLBACK_VECTOR{PLAY_CALLBACK, PAUSE_CALLBACK, STOP_CALLBACK, PLAYNEXT_CALLBACK,
    PLAYPREVIOUS_CALLBACK, FASTFORWARD_CALLBACK, REWIND_CALLBACK, HANDLEKEYEVENT_CALLBACK, SEEK_CALLBACK,
    SETSPEED_CALLBACK, SETLOOPMODE_CALLBACK, TOGGLEFAVORITE_CALLBACK, OUTPUTDEVICECHANGED_CALLBACK};

class NapiAVSessionCallback : public AVSessionCallback, public std::enable_shared_from_this<NapiAVSessionCallback> {
public:
    explicit NapiAVSessionCallback();
    virtual ~NapiAVSessionCallback();

    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward() override;
    void OnRewind() override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(int32_t speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediald) override;
    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;
    void SaveCallbackReference(const std::string& callbackName, napi_value callback, napi_env env);
    void ReleaseCallbackReference(const std::string& callbackName);

private:
    napi_env env_;
    std::mutex mutex_;
    std::shared_ptr<UvQueue> uvQueue_;
    napi_ref play_callback_;
    napi_ref pause_callback_;
    napi_ref stop_callback_;
    napi_ref playnext_callback_;
    napi_ref playprevious_callback_;
    napi_ref fastforward_callback_;
    napi_ref rewind_callback_;
    napi_ref mediakeyevent_callback_;
    napi_ref seek_callback_;
    napi_ref setspeed_callback_;
    napi_ref setloopmode_callback_;
    napi_ref togglefavorite_callback_;
    napi_ref outputDeviceChanged_callback_;
};
} // namespace AVSession
} // namespace OHOS
#endif // OHOS_NAPI_AVSESSION_CALLBACK_H
