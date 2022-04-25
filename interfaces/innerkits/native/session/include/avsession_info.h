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

#ifndef OHOS_AVSESSION_INFO_H
#define OHOS_AVSESSION_INFO_H

#include <cinttypes>
#include <functional>
#include <string>

namespace OHOS::AVSession {
enum PlaybackState {
    PLAYBACK_STATE_INVALID = -1,
    PLAYBACK_STATE_NEW,
    PLAYBACK_STATE_PREPARED,
    PLAYBACK_STATE_PLAYING,
    PLAYBACK_STATE_PAUSED,
    PLAYBACK_STATE_STOPPED,
    PLAYBACK_STATE_RELEASED
};

/*
enum AVMetadataKey {
    METADATA_KEY_TITLE = "title",
    METADATA_KEY_SUBTITLE = "subtitle",
    METADATA_KEY_ARTIST = "artist",
    METADATA_KEY_DURATION = "duration",
    METADATA_KEY_DATE = "date",
    METADATA_KEY_DISPLAY_ICON = "display_icon"
};
*/

enum AVCommand {
    AV_CMD_STOP = 0,
    AV_CMD_PLAY,
    AV_CMD_PAUSE,
    AV_CMD_PLAY_NEXT,
    AV_CMD_PLAY_PREVIOUS,
    AV_CMD_SEEK,
    AV_CMD_SET_SPEED
};

struct SessionDescriptor {
    int32_t sessionId = -1;
    std::string tag;
    std::string bundleName;
    bool active {};
};

struct SessionCommand {
    AVCommand cmd;
    int32_t para;
};

struct AVPlaybackState {
    PlaybackState state;
    int32_t currentTime;
};

using DeathCallback = std::function<void()>;

class SessionListener {
public:
    virtual void OnSessionCreate(const SessionDescriptor& descriptor) = 0;

    virtual void OnSessionRelease(const SessionDescriptor& descriptor) = 0;

    virtual ~SessionListener() = default;
};

class AVSessionCallback {
public:
    virtual void OnPlay() = 0;

    virtual void OnStop() = 0;

    virtual ~AVSessionCallback() = default;
};

class AVSessionControllerCallback {
public:
    virtual void OnSessionRelease() = 0;

    virtual ~AVSessionControllerCallback() = default;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_INFO_H