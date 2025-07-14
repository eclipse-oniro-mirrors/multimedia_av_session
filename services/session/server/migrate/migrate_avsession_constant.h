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
constexpr int32_t HEART_BEAT_TIME_FOR_NEXT = 30000;
constexpr int32_t SILENT_HEART_BEAT_TIME_FOR_NEXT = 3600000;

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
constexpr int32_t MSG_HEAD_MODE_FOR_NEXT = 101;

constexpr int32_t SYNC_CONTROLLER_LIST = 1;
constexpr int32_t SYNC_CONTROLLER = 2;
constexpr int32_t SYNC_COMMAND = 3;
constexpr int32_t SYNC_HEARTBEAT = 4;
constexpr int32_t GET_HISTORY_MEDIA_INFO = 5;
constexpr int32_t COLD_START = 6;
constexpr int32_t SYNC_FOCUS_META_INFO = 7;
constexpr int32_t SYNC_FOCUS_PLAY_STATE = 8;
constexpr int32_t SYNC_FOCUS_VALID_COMMANDS = 9;
constexpr int32_t SYNC_FOCUS_BUNDLE_IMG = 10;

constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_DESTROYED = 11;
constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_SESSION_EVENT = 12;
constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED = 13;
constexpr int32_t SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED = 14;
constexpr int32_t SYNC_FOCUS_SESSION_INFO = 15;
constexpr int32_t SYNC_FOCUS_MEDIA_IMAGE = 16;

constexpr int32_t SYNC_SET_VOLUME_COMMAND = 17;
constexpr int32_t SYNC_AVAIL_DEVICES_LIST = 18;
constexpr int32_t SYNC_CURRENT_DEVICE = 19;
constexpr int32_t SYNC_SWITCH_AUDIO_DEVICE_COMMAND = 20;

constexpr int32_t SYNC_MEDIA_CONTROL_NEED_STATE = 21;

constexpr int32_t MESSAGE_CODE_CONNECT_SERVER = 1;
constexpr int32_t DEFAULT_NUM = 0;

constexpr int REASON_EXIST = -3;

#define EMIT_UTF8 "emitUTF8"
#define PLAYBACK_SPEED "playbackSpeed"
#define PLAYBACK_POSITION_ELAPSED_TIME "playbackPositionElapsedTime_"
#define PLAYBACK_POSITION_UPDATE_TIME "playbackPositionUpdateTime_"
#define PLAYBACK_GET_ACTIVE_ITEM_ID "playbackGetActiveItemId"

#define DEFAULT_STRING "DEFAULT"
#define METADATA_ASSET_ID "MetadataAssetId"
#define FAVOR_STATE "FavorState"
#define VALID_COMMANDS "ValidCommands"
#define BUNDLE_ICON "BundleIcon"
#define COMMAND_CODE "CommandCode"
#define COMMAND_ARGS "CommandArgs"
#define EMPTY_SESSION "Empty"
#define MIGRATE_SESSION_ID "SessionId"
#define MIGRATE_BUNDLE_NAME "BundleName"
#define MIGRATE_ABILITY_NAME "AbilityName"
#define NEED_STATE "NeedState"

#define EVENT_COMMAND_UNLOCK_LYRIC "EVENT_COMMAND_UNLOCK_LYRIC"
#define EVENT_COMMAND_SHOW_LYRIC "EVENT_COMMAND_SHOW_LYRIC"
#define EVENT_COMMAND_HIDE_LYRIC "EVENT_COMMAND_HIDE_LYRIC"

#define MEDIA_CONTROLLER_LIST "MediaControllerList"

#define MEDIA_AVAILABLE_DEVICES_LIST "MediaAvailableDevicesList"

#define HISTORY_MEDIA_PLAYER_INFO "HistoryMediaPlayerInfo"

#define MEDIA_SESSION "MediaSession"

#define METADATA_TITLE "MetadataTitle"

#define METADATA_ARTIST "MetadataArtist"

#define METADATA_IMAGE "MetadataArt"

#define PLAYBACK_STATE "PlaybackState"

#define SESSION_INFO "SessionInfo"

#define RATING "Rating"

#define LYRIC_STATE "LyricState"

#define PLAYBACK_INFO "PlaybackInfo"

#define MEDIA_COMMAND "MediaCommand"

#define COMMAND "command"

#define QUERY "query"

#define EVENT "event"

#define EXTRAS "extras"

#define PLAYER_ID "PlayerId"

#define PACKAGE_NAME "PackageName"

#define MEDIA_INFO "MediaInfo"

#define CALLBACK_INFO "CallbackInfo"

#define VOLUME_INFO "VolumeInfo"

#define IS_SUPPORT_SINGLE_FRAME_MEDIA_PLAY "mIsSupportSingleFrameMediaPlay"

#define METADATA_MASK_ALL "11111111111111111"
#define METADATA_MASK_NULL "00000000000000000"
#define PLAYBACK_MASK_ALL "111111111"
#define PLAYBACK_MASK_NULL "000000000"
constexpr int32_t VOLUMN_INFO = 15;

#define CONFIG_SOFTBUS_SESSION_TAG "Media_Session_RemoteCtrl"

#define AUDIO_VOLUME "AudioVolume"
#define AUDIO_DEVICE_CATEGORY "AudioDeviceCategory"
#define AUDIO_DEVICE_TYPE "AudioDeviceType"
#define AUDIO_DEVICE_ROLE "AudioDeviceRole"
#define AUDIO_NETWORK_ID "AudioNetworkId"
#define AUDIO_DEVICE_NAME "AudioDeviceName"
#define AUDIO_MAC_ADDRESS "AudioMacAddress"

#define AUDIO_SET_VOLUME "AUDIO_SET_VOLUME"
#define AUDIO_SELECT_OUTPUT_DEVICE "AUDIO_SELECT_OUTPUT_DEVICE"
#define SESSION_COLD_START_FROM_PROXY "COLD_START"
#define SESSION_SET_MEDIACONTROL_NEED_STATE "MEDIACONTROL_NEED_STATE"
#define MEDIACONTROL_NEED_STATE "NEED_STATE"

#define AUDIO_GET_VOLUME "AUDIO_GET_VOLUME"
#define AUDIO_GET_AVAILABLE_DEVICES "AUDIO_GET_AVAILABLE_DEVICES"
#define AUDIO_GET_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO \
    "AUDIO_GET_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO"

#define AUDIO_CALLBACK_VOLUME "AUDIO_CALLBACK_VOLUME"
#define AUDIO_CALLBACK_AVAILABLE_DEVICES \
    "AUDIO_CALLBACK_AVAILABLE_DEVICES"
#define AUDIO_CALLBACK_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO \
    "AUDIO_CALLBACK_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO"
} // namespace OHOS::AVSession

#endif // MIGRATE_AVSESSION_CONSTANT_H