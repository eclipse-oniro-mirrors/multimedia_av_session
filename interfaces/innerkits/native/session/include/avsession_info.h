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

#ifndef OHOS_AVSESSION_INFO_H
#define OHOS_AVSESSION_INFO_H

#include <string>
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avsession_descriptor.h"
#include "key_event.h"

namespace OHOS::AVSession {
using DeathCallback = std::function<void()>;

class SessionListener {
public:
    virtual void OnSessionCreate(const AVSessionDescriptor& descriptor) = 0;

    virtual void OnSessionRelease(const AVSessionDescriptor& descriptor) = 0;

    virtual void OnTopSessionChanged(const AVSessionDescriptor& descriptor) = 0;

    virtual ~SessionListener() = default;
};

class AVSessionCallback {
public:
    virtual void OnPlay() = 0;
    virtual void OnPause() = 0;
    virtual void OnStop() = 0;
    virtual void OnPlayNext() = 0;
    virtual void OnPlayPrevious() = 0;
    virtual void OnFastForward() = 0;
    virtual void OnRewind() = 0;
    virtual void OnSeek(int64_t time) = 0;
    virtual void OnSetSpeed(double speed) = 0;
    virtual void OnSetLoopMode(int32_t loopMode) = 0;
    virtual void OnToggleFavorite(const std::string& mediald) = 0;
    virtual void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) = 0;
    virtual ~AVSessionCallback() = default;
};

class AVControllerCallback {
public:
    virtual void OnSessionDestroy() = 0;

    virtual void OnPlaybackStateChange(const AVPlaybackState &state) = 0;

    virtual void OnMetaDataChange(const AVMetaData &data) = 0;

    virtual void OnActiveStateChange(bool isActive) = 0;

    virtual void OnValidCommandChange(const std::vector<int32_t> &cmds) = 0;

    virtual ~AVControllerCallback() = default;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_INFO_H