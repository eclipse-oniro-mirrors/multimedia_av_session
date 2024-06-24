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

#ifndef MIGRATE_AVSESSION_CONSTANT_H
#define MIGRATE_AVSESSION_CONSTANT_H

#include <iostream>
#include <string>

namespace OHOS::AVSession {
constexpr int32_t PROCESS_STATE_IDLE = 0;
constexpr int32_t PROCESS_STATE_CONNECTING = 1;
constexpr int32_t PROCESS_STATE_CONNECTED = 2;

constexpr int32_t MEDIA_SESSION_PLAYBACK_STATE_PLAY = 3;
constexpr int32_t MEDIA_SESSION_PLAYBACK_STATE_PAUSE = 2;
constexpr int32_t MEDIA_SESSION_PLAYBACK_STATE_STOP = 1;
constexpr int32_t MEDIA_SESSION_PLAYBACK_STATE_ERROR = 7;

constexpr int32_t HEART_BEAT_TIME = 180000;

constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_COMMAND = 30;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_MEDIABUTTON_EVENT = 31;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_PLAY_FROM_SEARCH = 37;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_PLAY_FROM_MEDIAID = 38;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_CUSTOMACTION = 50;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_PLAY = 36;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_PLAY_FROM_URI = 39;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_PAUSE = 41;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_SKIP_TO_NEXT = 42;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_SKIP_TO_PREVIOUS = 43;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_STOP = 46;
constexpr int32_t SYNC_MEDIASESSION_CALLBACK_ON_SET_RATING = 48;
constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_AUDIOINFO_CHANGED = 18;

constexpr int32_t MSG_HEAD_LENGTH = 2;
constexpr int32_t MSG_HEAD_MODE = 100;

constexpr int32_t SYNC_CONTROLLER_LIST = 1;
constexpr int32_t SYNC_CONTROLLER = 2;
constexpr int32_t SYNC_COMMAND = 3;
constexpr int32_t SYNC_HEARTBEAT = 4;
constexpr int32_t GET_HISTORY_MEDIA_INFO = 5;
constexpr int32_t COLD_START = 6;

constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_DESTROYED = 11;
constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_SESSION_EVENT = 12;
constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED = 13;
constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED = 14;

constexpr int REASON_EXIST = -3;

const std::string EMIT_UTF8 = "emitUTF8";
const std::string PLAYBACK_SPEED = "playbackSpeed";
const std::string PLAYBACK_POSITION_ELAPSED_TIME = "playbackPositionElapsedTime_";
const std::string PLAYBACK_POSITION_UPDATE_TIME = "playbackPositionUpdateTime_";
const std::string PLAYBACK_GET_ACTIVE_ITEM_ID = "playbackGetActiveItemId";

const std::string EVENT_COMMAND_UNLOCK_LYRIC = "EVENT_COMMAND_UNLOCK_LYRIC";
const std::string EVENT_COMMAND_SHOW_LYRIC = "EVENT_COMMAND_SHOW_LYRIC";
const std::string EVENT_COMMAND_HIDE_LYRIC = "EVENT_COMMAND_HIDE_LYRIC";

const std::string MEDIA_CONTROLLER_LIST = "MediaControllerList";

const std::string HISTORY_MEDIA_PLAYER_INFO = "HistoryMediaPlayerInfo";

const std::string MEDIA_SESSION = "MediaSession";

const std::string METADATA_TITLE = "MetadataTitle";

const std::string METADATA_ARTIST = "MetadataArtist";

const std::string METADATA_ART = "MetadataArt";

const std::string PLAYBACK_STATE = "PlaybackState";

const std::string SESSION_INFO = "SessionInfo";

const std::string RATING = "Rating";

const std::string LYRIC_STATE = "LyricState";

const std::string PLAYBACK_INFO = "PlaybackInfo";

const std::string MEDIA_COMMAND = "MediaCommand";

const std::string COMMAND = "command";

const std::string QUERY = "query";

const std::string EVENT = "event";

const std::string EXTRAS = "extras";

const std::string PLAYER_ID = "PlayerId";

const std::string PACKAGE_NAME = "PackageName";

const std::string MEDIA_INFO = "MediaInfo";

const std::string CALLBACK_INFO = "CallbackInfo";

const std::string VOLUME_INFO = "VolumeInfo";

const std::string METADATA_MASK_ALL = "11111111111111111";
const std::string METADATA_MASK_NULL = "00000000000000000";
const std::string PLAYBACK_MASK_ALL = "111111111";
const std::string PLAYBACK_MASK_NULL = "000000000";
constexpr int32_t VOLUMN_INFO = 15;

const std::string CONFIG_SOFTBUS_SESSION_TAG = "Media_Session_RemoteCtrl";
} // namespace OHOS::AVSession

#endif // MIGRATE_AVSESSION_CONSTANT_H