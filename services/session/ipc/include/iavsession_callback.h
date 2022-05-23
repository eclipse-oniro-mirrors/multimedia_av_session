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

#ifndef OHOS_AVSESSION_CALLBACK_H
#define OHOS_AVSESSION_CALLBACK_H

#include "avsession_info.h"
#include "key_event.h"
#include "iremote_broker.h"

namespace OHOS::AVSession {
class IAVSessionCallback : public AVSessionCallback, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.AVSession.IAVSessionCallback");

    enum {
        LOOP_MODE_SEQUENCE,
        LOOP_MODE_SINGLE,
        LOOP_MODE_LIST,
        LOOP_MODE_SHUFFLE
    };

    enum {
        SESSION_CALLBACK_ON_PLAY,
        SESSION_CALLBACK_ON_PAUSE,
        SESSION_CALLBACK_ON_STOP,
        SESSION_CALLBACK_ON_PLAY_NEXT,
        SESSION_CALLBACK_ON_PLAY_PREVIOUS,
        SESSION_CALLBACK_ON_FAST_FORWARD,
        SESSION_CALLBACK_ON_REWIND,
        SESSION_CALLBACK_ON_SEEK,
        SESSION_CALLBACK_ON_SET_SPEED,
        SESSION_CALLBACK_ON_SET_LOOPMODE,
        SESSION_CALLBACK_ON_TOGGLE_FAVORITE,
        SESSION_CALLBACK_ON_VOLUME_CHANGED,
        SESSION_CALLBACK_ON_MEDIA_KEY_EVENT,
        SESSION_CALLBACK_MAX
    };

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

    void OnVolumeChanged(const AVVolumeInfo& volume) override;

    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CALLBACK_H