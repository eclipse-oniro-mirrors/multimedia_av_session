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

#ifndef OHOS_CJ_AVSESSION_CALLBACK_H
#define OHOS_CJ_AVSESSION_CALLBACK_H

#include <list>
#include <vector>
#include <map>

#include "avsession_info.h"
#include "cj_avsession_prototypes.h"

namespace OHOS::AVSession {

class CJAVSessionCallback : public AVSessionCallback {
public:
    CJAVSessionCallback();
    ~CJAVSessionCallback() = default;

    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward(int64_t time) override;
    void OnRewind(int64_t time) override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& assertId) override;
    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override;
    void OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) override;
    void OnSkipToQueueItem(int32_t itemId) override;
    void OnAVCallAnswer() override;
    void OnAVCallHangUp() override;
    void OnAVCallToggleCallMute() override;
    void OnPlayFromAssetId(int64_t assetId) override;
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override;
    void OnCastDisplaySizeChange(const CastDisplayInfo& castDisplayInfo) override;

    void RegisterCallback(int32_t type, int64_t id);
    void UnRegisterCallback(int32_t type);

private:
    void InitPlay(int64_t id);
    void InitPause(int64_t id);
    void InitStop(int64_t id);
    void InitPlayNext(int64_t id);
    void InitPlayPrevious(int64_t id);
    void InitFastForward(int64_t id);
    void InitFastForwardWithTime(int64_t id);
    void InitRewind(int64_t id);
    void InitRewindWithTime(int64_t id);
    void InitPlayFromAssetId(int64_t id);
    void InitSeek(int64_t id);
    void InitSetSpeed(int64_t id);
    void InitSetLoopMode(int64_t id);
    void InitToggleFavorite(int64_t id);
    void InitSkipToQueueItem(int64_t id);
    void InitHandleKeyEvent(int64_t id);
    void InitOutputDeviceChange(int64_t id);
    void InitCommonCommand(int64_t id);
    void InitAnswer(int64_t id);
    void InitHangUp(int64_t id);
    void InitToggleCallMute(int64_t id);
    void InitCastDisplayChange(int64_t id);

    std::function<void(void)> play;
    std::function<void(void)> pause;
    std::function<void(void)> stop;
    std::function<void(void)> playNext;
    std::function<void(void)> playPrevious;
    std::function<void(int64_t)> fastForward;
    std::function<void(int64_t)> rewind;
    std::function<void(int64_t)> playFromAssetId;
    std::function<void(int64_t)> seek;
    std::function<void(double)> setSpeed;
    std::function<void(int32_t)> setLoopMode;
    std::function<void(const char*)> toggleFavorite;
    std::function<void(int32_t)> skipToQueueItem;
    std::function<void(CKeyEvent)> handleKeyEvent;
    std::function<void(int32_t, COutputDeviceInfo)> outputDeviceChange;
    std::function<void(const char*, CArray)> commonCommand;
    std::function<void(void)> answer;
    std::function<void(void)> hangUp;
    std::function<void(void)> toggleCallMute;
    std::function<void(const CCastDisplayInfo)> castDisplayChange;
    std::function<void(const CCastDisplayInfo)> castDisplaySizeChange;
    std::map<int32_t, void(CJAVSessionCallback::*)(int64_t)> typeToCallbackMap_;
    std::vector<std::shared_ptr<std::recursive_mutex>> callbackMutexMap_;
};

} // namespace OHOS::AVSession
#endif // OHOS_CJ_AVSESSION_CALLBACK_H
