/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TAIHE_AV_SESSION_CALLBACK_H
#define TAIHE_AV_SESSION_CALLBACK_H

#include <list>

#include "avsession_info.h"
#include "key_event.h"
#include "taihe_async_callback.h"
#include "event_handler.h"
#include "taihe_utils.h"
#include "taihe_avsession_enum.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheAVSessionCallback : public OHOS::AVSession::AVSessionCallback {
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
        EVENT_OUTPUT_DEVICE_CHANGE,
        EVENT_SEND_COMMON_COMMAND,
        EVENT_SKIP_TO_QUEUE_ITEM,
        EVENT_AVCALL_ANSWER,
        EVENT_AVCALL_HANG_UP,
        EVENT_AVCALL_TOGGLE_CALL_MUTE,
        EVENT_PLAY_FROM_ASSETID,
        EVENT_PLAY_WITH_ASSETID,
        EVENT_DISPLAY_CHANGE,
        EVENT_CUSTOM_DATA_CHANGE,
        EVENT_SET_TARGET_LOOP_MODE,
        EVENT_TYPE_MAX
    };

    TaiheAVSessionCallback(ani_env* env);
    ~TaiheAVSessionCallback() override;

    void OnPlay(const OHOS::AVSession::AVControlCommand& cmd) override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext(const OHOS::AVSession::AVControlCommand& cmd) override;
    void OnPlayPrevious(const OHOS::AVSession::AVControlCommand& cmd) override;
    void OnFastForward(int64_t time, const OHOS::AVSession::AVControlCommand& cmd) override;
    void OnRewind(int64_t time, const OHOS::AVSession::AVControlCommand& cmd) override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnSetTargetLoopMode(int32_t targetLoopMode) override;
    void OnToggleFavorite(const std::string &assertId) override;
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent &keyEvent) override;
    void OnOutputDeviceChange(const int32_t connectionState,
        const OHOS::AVSession::OutputDeviceInfo &outputDeviceInfo) override;
    void OnCommonCommand(const std::string &commonCommand, const OHOS::AAFwk::WantParams &commandArgs) override;
    void OnSkipToQueueItem(int32_t itemId) override;
    void OnAVCallAnswer() override;
    void OnAVCallHangUp() override;
    void OnAVCallToggleCallMute() override;
    void OnPlayFromAssetId(int64_t assetId) override;
    void OnPlayWithAssetId(const std::string &assetId) override;
    void OnCastDisplayChange(const OHOS::AVSession::CastDisplayInfo &castDisplayInfo) override;
    void OnCustomData(const OHOS::AAFwk::WantParams &customData) override;

    int32_t AddCallback(int32_t event, std::shared_ptr<uintptr_t> callback);
    int32_t RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> callback);

    bool IsCallbacksEmpty(int32_t event);

private:
    using TaiheFuncExecute = std::function<void(std::shared_ptr<uintptr_t> method)>;

    void HandleEvent(int32_t event, TaiheFuncExecute callback);

    struct DataContext {
        string assetId;
        string playAssetId;
        string commonCommand;
    };

    ani_env *env_ = nullptr;
    std::mutex lock_;
    std::shared_ptr<TaiheAsyncCallback> asyncCallback_;
    std::list<std::shared_ptr<uintptr_t>> callbacks_[EVENT_TYPE_MAX] {};
    std::shared_ptr<bool> isValid_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
    DataContext dataContext_ {};
};
} // namespace ANI::AVSession
#endif // TAIHE_AV_SESSION_CALLBACK_H