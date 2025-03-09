/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "avcall_meta_data.h"
#include "avcall_state.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avcast_player_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avsession_descriptor.h"
#include "key_event.h"
#include "want_params.h"
#include "av_shared_memory.h"

/**
 * @brief Listening events for the creation and destruction of sessions
 *     and the latest session changes.
 * @since 9
 */
namespace OHOS::AVSession {
using DeathCallback = std::function<void()>;

class SessionListener {
public:
    /**
     * @brief Listen for session creation events.
     *
     * @param descriptor Session related description callback.
     * @since 9
    */
    virtual void OnSessionCreate(const AVSessionDescriptor& descriptor) = 0;

    /**
     * @brief Listen for session release events.
     *
     * @param descriptor Session related description callback.
     * @since 9
    */
    virtual void OnSessionRelease(const AVSessionDescriptor& descriptor) = 0;

    /**
     * @brief Listen for changes in the latest session.
     *
     * @param descriptor Session related description callback.
     * @since 9
    */
    virtual void OnTopSessionChange(const AVSessionDescriptor& descriptor) = 0;

    /**
     * @brief Listen for AudioSession verification.
     *
     * @param uid Session related uid.
     * @since 9
    */
    virtual void OnAudioSessionChecked(const int32_t uid) {};

    /**
     * @brief Listen for the event of device discovery.
     *
     * @param { OutputDeviceInfo } castOutputDeviceInfo - Discovered device info.
     * @since 10
    */
    virtual void OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) {};

    /**
     * @brief Listen for the event of device logging.
     *
     * @param { DeviceLogEventCode } eventId - Event ID.
     * @param { int64_t } int64_t - Param.
     * @since 13
    */
    virtual void OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) {};

    /**
     * @brief Listen for the event of device offline.
     *
     * @param { std::string& } deviceId - Offlined device ID.
     * @since 10
    */
    virtual void OnDeviceOffline(const std::string& deviceId) {};

    /**
     * @brief Listen for the distributed session changed.
     *
     * @param { std::vector<sptr<IRemoteObject>>& } sessionControllers - changed distributed session.
     * @since 16
    */
    virtual void OnRemoteDistributedSessionChange(
        const std::vector<sptr<IRemoteObject>>& sessionControllers) {};

    /**
     * @brief Deconstruct SessionListener.
     * @since 9
    */
    virtual ~SessionListener() = default;
};

class IAVCastControllerProxyListener {
public:
    virtual void OnCastPlaybackStateChange(const AVPlaybackState& state) = 0;

    virtual void OnMediaItemChange(const AVQueueItem& avQueueItem) = 0;

    virtual void OnPlayNext() = 0;

    virtual void OnPlayPrevious() = 0;

    virtual void OnSeekDone(const int32_t seekNumber) = 0;

    virtual void OnVideoSizeChange(const int32_t width, const int32_t height) = 0;

    virtual void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) = 0;

    virtual void OnEndOfStream(const int32_t isLooping) = 0;

    virtual void OnPlayRequest(const AVQueueItem& avQueueItem) = 0;

    virtual void OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData) = 0;

    virtual void OnValidCommandChange(const std::vector<int32_t> &cmds) = 0;

    virtual int32_t onDataSrcRead(std::shared_ptr<AVSharedMemory>mem, uint32_t length, int64_t pos) {return 0;};

    /**
     * @brief Deconstruct SessionListener.
     * @since 9
    */
    virtual ~IAVCastControllerProxyListener() = default;
};

class AVSessionCallback {
public:
    /**
     * @brief playback.
     * @since 9
    */
    virtual void OnPlay() = 0;

    /**
     * @brief Pause playback.
     * @since 9
    */
    virtual void OnPause() = 0;

    /**
     * @brief Stop playback.
     * @since 9
    */
    virtual void OnStop() = 0;

    /**
     * @brief play next.
     * @since 9
    */
    virtual void OnPlayNext() = 0;

    /**
     * @brief Play the previous song.
     * @since 9
    */
    virtual void OnPlayPrevious() = 0;

    /**
     * @brief Fast forward.
     *
     * @param time fastforward skip intervals
     * @since 11
    */
    virtual void OnFastForward(int64_t time) = 0;

    /**
     * @brief Fast rewind.
     *
     * @param time rewind skip intervals
     * @since 11
    */
    virtual void OnRewind(int64_t time) = 0;

    /**
     * @brief Seek to the specified time.
     *
     * @param time Seek to the specified time
     * @since 9
    */
    virtual void OnSeek(int64_t time) = 0;

    /**
     * @brief Set playback speed.
     *
     * @param speed The playback speed to be set
     * @return Whether the playback speed is set successfully
     * @since 9
    */
    virtual void OnSetSpeed(double speed) = 0;

    /**
     * @brief Set cycle mode.
     *
     * @param mode Cycle mode to be set {@link LoopMode}
     * @return Whether the cycle mode is set successfully.
     * @since 9
    */
    virtual void OnSetLoopMode(int32_t loopMode) = 0;

    /**
     * @brief Set target cycle mode.
     *
     * @param mode Cycle mode to be set {@link LoopMode}
     * @return Whether the cycle mode is set successfully.
     * @since 9
    */
    virtual void OnSetTargetLoopMode(int32_t targetLoopMode) {}

    /**
     * @brief Whether to collect the current song.
     *
     * @param mediaId current song id.
     * @since 9
    */
    virtual void OnToggleFavorite(const std::string& mediaId) = 0;

    /**
     * @brief Listening for Media key events.
     *
     * @param keyEvent event callbacks.
     * @since 9
    */
    virtual void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) = 0;

    /**
     * @brief Monitor and play device change events.
     *
     * @param connectionState Event callback of device state.
     * @param outputDeviceInfo Event callback of device information.
     * @since 9
    */
    virtual void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) = 0;

    /**
     * @brief Listen for command events.
     *
     * @param commonCommand The name of the command to be sent.
    * @param commandArgs Command packets to be sent
     * @since 10
     */
    virtual void OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) = 0;

    /**
     * @brief Listen to the change of item in the playlist to be played.
     *
     * @param itemId The serial number of the item to be played.
     * @since 10
     */
    virtual void OnSkipToQueueItem(int32_t itemId) = 0;

    /**
     * Register answer command callback.
     * @since 11
     */
    virtual void OnAVCallAnswer() = 0;

    /**
     * Register hangUp command callback.
     * @since 11
     */
    virtual void OnAVCallHangUp() = 0;

    /**
     * Register toggleCallMute command callback.
     * @since 11
     */
    virtual void OnAVCallToggleCallMute() = 0;

    /**
     * @brief Play from assetId.
     *
     * @param assetId Id for asset
     * @since 11
    */
    virtual void OnPlayFromAssetId(int64_t assetId) = 0;

    /**
     * @brief cast display change.
     *
     * @param castDisplayInfo for castDisplay
     * @since 11
     */
    virtual void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) = 0;

    /**
     * @brief Deconstruct AVSessionCallback.
     * @since 9
    */
    virtual ~AVSessionCallback() = default;
};

class AVControllerCallback {
public:

    /**
     * @brief Listen for avcall metadata change events.
     *
     * @param avCallMetaData is the changed avcall metadata.
     * @since 11
    */
    virtual void OnAVCallMetaDataChange(const AVCallMetaData& avCallMetaData) = 0;

    /**
     * @brief Listening session avcall status change event.
     *
     * @param avCallState Session related avcall state.
     * @since 11
    */
    virtual void OnAVCallStateChange(const AVCallState& avCallState) = 0;
    /**
     * @brief Session Destroy.
     * @since 9
    */
    virtual void OnSessionDestroy() = 0;

    /**
     * @brief Listening session destruction playback status change event.
     *
     * @param state Session related description callback.
     * @since 9
    */
    virtual void OnPlaybackStateChange(const AVPlaybackState& state) = 0;

    /**
     * @brief Listen for metadata change events.
     *
     * @param data Data is the changed metadata.
     * @since 9
    */
    virtual void OnMetaDataChange(const AVMetaData& data) = 0;

    /**
     * @brief Listen to the activation status event of the session.
     *
     * @param isActive Whether the session is activated.
     * @since 9
    */
    virtual void OnActiveStateChange(bool isActive) = 0;

    /**
     * @brief Listen for valid command change events supported by the session.
     *
     * @param cmds Collection callback of valid commands.
     * @since 9
    */
    virtual void OnValidCommandChange(const std::vector<int32_t>& cmds) = 0;

    /**
     * @brief Monitor and play device change events.
     *
     * @param connectionState Event callback of device state.
     * @param outputDeviceInfo Device related information callback.
     * @since 9
    */
    virtual void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) = 0;

    /**
     * @brief Listen for changes in custom events of the session.
     *
     * @param event Changed session event name.
     * @param args Parameters of parts.
     * @since 9
    */
    virtual void OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args) = 0;

    /**
     * @brief Session playlist change callback.
     *
     * @param items The changed queue items.
     * @since 10
     */
    virtual void OnQueueItemsChange(const std::vector<AVQueueItem>& items) = 0;

    /**
     * @brief Session title change callback.
     *
     * @param title The changed title.
     * @since 10
     */
    virtual void OnQueueTitleChange(const std::string& title) = 0;

    /**
     * @brief Session custom media packet change callback.
     *
     * @param extras The changed custom media packet.
     * @since 10
     */
    virtual void OnExtrasChange(const AAFwk::WantParams& extras) = 0;

    /**
     * @brief Deconstruct AVControllerCallback.
     * @since 9
    */
    virtual ~AVControllerCallback() = default;
};

class AVCastControllerCallback {
public:
    virtual void OnCastPlaybackStateChange(const AVPlaybackState& state) = 0;

    virtual void OnMediaItemChange(const AVQueueItem& avQueueItem) = 0;

    virtual void OnPlayNext() = 0;

    virtual void OnPlayPrevious() = 0;

    virtual void OnSeekDone(const int32_t seekNumber) = 0;

    virtual void OnVideoSizeChange(const int32_t width, const int32_t height) = 0;

    virtual void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) = 0;

    virtual void OnEndOfStream(const int32_t isLooping) = 0;

    virtual void OnPlayRequest(const AVQueueItem& avQueueItem) = 0;

    virtual void OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData) = 0;

    virtual void OnCastValidCommandChanged(const std::vector<int32_t> &cmds) = 0;

    virtual int32_t onDataSrcRead(std::shared_ptr<AVSharedMemory>mem, uint32_t length, int64_t pos) {return 0;};

    /**
     * @brief Deconstruct AVControllerCallback.
     * @since 9
    */
    virtual ~AVCastControllerCallback() = default;
};

class IAVCastSessionStateListener {
public:
    /**
     * @brief Listen to the change of cast state change.
     *
     * @param castState The cast state of device info.
     * @param deviceInfo The device info.
     * @since 9
    */
    virtual void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo) = 0;

    /**
     * @brief Listen to the change of cast event.
     *
     * @param errorCode The error code of cast event.
     * @param errorMsg The error message of cast event.
     * @since 9
    */
    virtual void OnCastEventRecv(int32_t errorCode, std::string& errorMsg) = 0;

    /**
     * @brief Deconstruct IAVCastSessionStateListener.
     * @since 10
    */
    virtual ~IAVCastSessionStateListener() = default;
};

class IAVRouterListener {
public:
    /**
     * @brief Listen to the change of cast state change.
     *
     * @param castState The cast state of device info.
     * @param deviceInfo The device info.
     * @param isNeedRemove is need remove cast device
     * @since 13
    */
    virtual void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove) = 0;

    /**
     * @brief Listen to the change of cast event.
     *
     * @param errorCode The error code of cast event.
     * @param errorMsg The error message of cast event.
     * @since 13
    */
    virtual void OnCastEventRecv(int32_t errorCode, std::string& errorMsg) = 0;

    /**
     * @brief Deconstruct IAVRouterListener.
     * @since 13
    */
    virtual ~IAVRouterListener() = default;
};

struct SessionToken {
    std::string sessionId;
    pid_t pid;
    pid_t uid;
};

enum SessionDataCategory {
    SESSION_DATA_CATEGORY_INVALID = -1,
    SESSION_DATA_META = 0,
    SESSION_DATA_PLAYBACK_STATE = 1,
    SESSION_DATA_CONTROL_COMMAND = 2,
    SESSION_DATA_SET_EVENT = 3,
    SESSION_DATA_QUEUE_ITEMS = 4,
    SESSION_DATA_QUEUE_TITLE = 5,
    SESSION_DATA_COMMON_COMMAND = 6,
    SESSION_DATA_EXTRAS = 7,
    SESSION_DATA_CATEGORY_MAX = 8,
};

enum AVCastCategory {
    /**
     * The default cast type "local", media can be routed on the same device,
     * including internal speakers or audio jacks on the device itself, A2DP devices.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @since 10
     */
    CATEGORY_LOCAL = 0,

    /**
     * The remote category indicating the media is presenting on a remote device,
     * the application needs to get an AVCastController to control remote playback.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @since 10
     */
    CATEGORY_REMOTE = 1,
};

enum ProtocolType {
    /**
     * The default cast type "local", media can be routed on the same device,
     * including internal speakers or audio jacks on the device itself, A2DP devices.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @since 10
     */
    TYPE_LOCAL = 0,

    /**
     * Cast+ mirror capability
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @systemapi
     * @since 10
     */
    TYPE_CAST_PLUS_MIRROR  = 1,

    /**
     * The Cast+ Stream indicating the media is presenting on a different device
     * the application need get an AVCastController to control remote playback.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @since 10
     */
    TYPE_CAST_PLUS_STREAM  = 2,

    /**
     * The DLNA type indicates the device supports DLNA protocol,
     * the application needs to get an AVCastController to control remote playback.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @since 12
     */
    TYPE_DLNA = 4,
};

/**
 * Define different distributed session type
 * @enum { number }
 * @syscap SystemCapability.Multimedia.AVSession.Manager
 * @systemapi
 * @since 16
 */
enum DistributedSessionType {
    /**
     * Remote session sensed from remote device.
     * @syscap SystemCapability.Multimedia.AVSession.Manager
     * @systemapi
     * @since 16
     */
    TYPE_SESSION_REMOTE = 0,

    /**
     * Migrate from remote device to this device.
     * @syscap SystemCapability.Multimedia.AVSession.Manager
     * @systemapi
     * @since 16
     */
    TYPE_SESSION_MIGRATE_IN = 1,

    /**
     * Migrate from this device to remote device.
     * @syscap SystemCapability.Multimedia.AVSession.Manager
     * @systemapi
     * @since 16
     */
    TYPE_SESSION_MIGRATE_OUT = 2,

    /**
     * Migrate session max flag.
     * @syscap SystemCapability.Multimedia.AVSession.Manager
     * @systemapi
     * @since 16
     */
    TYPE_SESSION_MAX = 1,
};

/**
 * Define the device connection state.
 * @syscap SystemCapability.Multimedia.AVSession.Core
 * @since 10
 */
enum ConnectionState {
    /**
     * A connection state indicating the device is in the process of connecting.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    STATE_CONNECTING = 0,
    /**
     * A connection state indicating the device is connected.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    STATE_CONNECTED = 1,
    /**
     * The default connection state indicating the device is disconnected.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    STATE_DISCONNECTED = 6,
};

enum DeviceType {
    /**
     * A device type indicating the route is on internal speakers or audio jacks on the device itself.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    DEVICE_TYPE_LOCAL = 0,
    /**
     * A device type indicating the route is on a TV.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     */
    DEVICE_TYPE_TV = 2,
    /**
     * A device type indicating the route is on a smart speaker.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     */
    DEVICE_TYPE_SPEAKER = 3,
    /**
     * A device type indicating the route is on a bluetooth device.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    DEVICE_TYPE_BLUETOOTH = 10,
};

/**
 * The defination of suggested resolution.
 * @enum { number }
 * @syscap SystemCapability.Multimedia.AVSession.AVCast
 * @atomicservice
 * @since 18
 */
enum ResolutionLevel {
    /**
     * Defination of 480P which typically resolution is 640*480.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 18
     */
    RESOLUTION_480P = 0,

    /**
     * Defination of 720P which typically resolution is 1280*720.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 18
     */
    RESOLUTION_720P = 1,

    /**
     * Defination of 1080P which typically resolution is 1920*1080.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 18
     */
    RESOLUTION_1080P = 2,

    /**
     * Defination of 2K which typically resolution is 2560*1440.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 18
     */
    RESOLUTION_2K = 3,

    /**
     * Defination of 4K which typically resolution is 4096*3840.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 18
     */
    RESOLUTION_4K = 4,
};

/**
 * Enumerates the HDR Format
 *
 * @enum { number }
 * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
 * @since 11
 */
/**
 * Enumerates the HDR Format
 *
 * @enum { number }
 * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
 * @atomicservice
 * @since 12
 */
enum HDRFormat {
    /**
     * Not support HDR.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @since 11
     */
    /**
     * Not support HDR.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @atomicservice
     * @since 12
     */
    NONE = 0,
    /**
     * HLG format supported by video.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @since 11
     */
    /**
     * HLG format supported by video.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @atomicservice
     * @since 12
     */
    VIDEO_HLG = 1,
    /**
     * HDR10 format supported by video.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @since 11
     */
    /**
     * HDR10 format supported by video.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @atomicservice
     * @since 12
     */
    VIDEO_HDR10 = 2,
    /**
     * HDR Vivid format supported by video.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @since 11
     */
    /**
     * HDR Vivid format supported by video.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @atomicservice
     * @since 12
     */
    VIDEO_HDR_VIVID = 3,
    /**
     * HDR Vivid format supported by image, stored in dual JPEG format.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @since 11
     */
    /**
     * HDR Vivid format supported by image, stored in dual JPEG format.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @atomicservice
     * @since 12
     */
    IMAGE_HDR_VIVID_DUAL = 4,
    /**
     * HDR Vivid format supported by image, stored in single HEIF format.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @since 11
     */
    /**
     * HDR Vivid format supported by image, stored in single HEIF format.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @atomicservice
     * @since 12
     */
    IMAGE_HDR_VIVID_SINGLE = 5,
    /**
     * ISO HDR format supported by image, stored in dual JPEG format.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @since 11
     */
    /**
     * ISO HDR format supported by image, stored in dual JPEG format.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @atomicservice
     * @since 12
     */
    IMAGE_HDR_ISO_DUAL = 6,
    /**
     * ISO HDR format supported by image, stored in single HEIF format.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @since 11
     */
    /**
     * ISO HDR format supported by image, stored in single HEIF format.
     *
     * @syscap SystemCapability.Graphic.Graphic2D.ColorManager.Core
     * @atomicservice
     * @since 12
     */
    IMAGE_HDR_ISO_SINGLE = 7,
};

enum CastEngineConnectState {
    CONNECTING = 0,
    CONNECTED = 1,
    PAUSED = 2,
    PLAYING = 3,
    DISCONNECTING = 4,
    DISCONNECTED = 5,
    STREAM = 6,
    MIRROR_TO_UI = 7,
    UI_TO_MIRROR = 8,
    UICAST = 9,
    DEVICE_STATE_MAX = 10,
};

/**
 * Enumerates ErrorCode types, returns in BusinessError.code.
 * @enum { number }
 * @syscap SystemCapability.Multimedia.AVSession.Core
 * @since 10
 */
enum AVSessionErrorCode {
    /**
     * Session service exception.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_SERVICE_EXCEPTION = 6600101,

    /**
     * The session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_SESSION_NOT_EXIST = 6600102,

    /**
     * The session controller does not exist.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_CONTROLLER_NOT_EXIST = 6600103,

    /**
     * The remote session connection failed.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_REMOTE_CONNECTION_ERR = 6600104,

    /**
     * Invalid session command.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_COMMAND_INVALID = 6600105,

    /**
     * The session is not activated.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_SESSION_INACTIVE = 6600106,

    /**
     * Too many commands or events.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_MESSAGE_OVERLOAD = 6600107,

    /**
     * Device connecting failed.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_DEVICE_CONNECTION_FAILED = 6600108,

    /**
     * The remote connection is not established.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    ERR_CODE_REMOTE_CONNECTION_NOT_EXIST = 6600109,

    /**
     * The error code for cast control is unspecified.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_UNSPECIFIED = 6611000,

    /**
     * An unspecified error occurs in the remote player.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_REMOTE_ERROR = 6611001,

    /**
     * The playback position falls behind the live window.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_BEHIND_LIVE_WINDOW = 6611002,

    /**
     * The process of cast control times out.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_TIMEOUT = 6611003,

    /**
     * The runtime check failed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_RUNTIME_CHECK_FAILED = 6611004,

    /**
     * Cross-device data transmission is locked.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_PLAYER_NOT_WORKING = 6611100,

    /**
     * The specified seek mode is not supported.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_SEEK_MODE_UNSUPPORTED = 6611101,

    /**
     * The position to seek to is out of the range of the media asset or the specified seek mode is not supported.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_ILLEGAL_SEEK_TARGET = 6611102,

    /**
     * The specified playback mode is not supported.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_PLAY_MODE_UNSUPPORTED = 6611103,

    /**
     * The specified playback speed is not supported.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_PLAY_SPEED_UNSUPPORTED = 6611104,

    /**
     * The action failed because either the media source device or the media sink device has been revoked.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DEVICE_MISSING = 6611105,

    /**
     * The parameter is invalid, for example, the url is illegal to play.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_INVALID_PARAM = 6611106,

    /**
     * Allocation of memory failed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_NO_MEMORY = 6611107,

    /**
     * Operation is not allowed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_OPERATION_NOT_ALLOWED = 6611108,

    /**
     * An unspecified input/output error occurs.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_UNSPECIFIED = 6612000,

    /**
     * Network connection failure.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_NETWORK_CONNECTION_FAILED = 6612001,

    /**
     * Network timeout.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_NETWORK_CONNECTION_TIMEOUT = 6612002,

    /**
     * Invalid "Content-Type" HTTP header.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_INVALID_HTTP_CONTENT_TYPE = 6612003,

    /**
     * The HTTP server returns an unexpected HTTP response status code.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_BAD_HTTP_STATUS = 6612004,

    /**
     * The file does not exist.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_FILE_NOT_FOUND = 6612005,

    /**
     * No permission is granted to perform the IO operation.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_NO_PERMISSION = 6612006,

    /**
     * Access to cleartext HTTP traffic is not allowed by the app's network security configuration.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_CLEARTEXT_NOT_PERMITTED = 6612007,

    /**
     * Reading data out of the data bound.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_READ_POSITION_OUT_OF_RANGE = 6612008,

    /**
     * The media does not contain any contents that can be played.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_NO_CONTENTS = 6612100,

    /**
     * The media cannot be read, for example, because of dust or scratches.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_READ_ERROR = 6612101,

    /**
     * This resource is already in use.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_CONTENT_BUSY = 6612102,

    /**
     * The content using the validity interval has expired.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_CONTENT_EXPIRED = 6612103,

    /**
     * Using the requested content to play is not allowed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_USE_FORBIDDEN = 6612104,

    /**
     * The use of the allowed content cannot be verified.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_NOT_VERIFIED = 6612105,

    /**
     * The number of times this content has been used as requested has reached the maximum allowed number of uses.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_EXHAUSTED_ALLOWED_USES = 6612106,

    /**
     * An error occurs when sending packet from source device to sink device.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_IO_NETWORK_PACKET_SENDING_FAILED = 6612107,

    /**
     * Unspecified error related to content parsing.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_PARSING_UNSPECIFIED = 6613000,

    /**
     * Parsing error associated with media container format bit streams.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_PARSING_CONTAINER_MALFORMED = 6613001,

    /**
     * Parsing error associated with the media manifest.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_PARSING_MANIFEST_MALFORMED = 6613002,

    /**
     * An error occurs when attempting to extract a file with an unsupported media container format
     * or an unsupported media container feature.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_PARSING_CONTAINER_UNSUPPORTED = 6613003,

    /**
     * Unsupported feature in the media manifest.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_PARSING_MANIFEST_UNSUPPORTED = 6613004,

    /**
     * Unspecified decoding error.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DECODING_UNSPECIFIED = 6614000,

    /**
     * Decoder initialization failed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DECODING_INIT_FAILED = 6614001,

    /**
     * Decoder query failed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DECODING_QUERY_FAILED = 6614002,

    /**
     * Decoding the media samples failed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DECODING_FAILED = 6614003,

    /**
     * The format of the content to decode exceeds the capabilities of the device.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DECODING_FORMAT_EXCEEDS_CAPABILITIES = 6614004,

    /**
     * The format of the content to decode is not supported.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DECODING_FORMAT_UNSUPPORTED = 6614005,

    /**
     * Unspecified errors related to the audio renderer.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_UNSPECIFIED = 6615000,

    /**
     * Initializing the audio renderer failed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_INIT_FAILED = 6615001,

    /**
     * The audio renderer fails to write data.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_WRITE_FAILED = 6615002,

    /**
     * Unspecified error related to DRM.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_UNSPECIFIED = 6616000,

    /**
     * The chosen DRM protection scheme is not supported by the device.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_SCHEME_UNSUPPORTED = 6616001,

    /**
     * Device provisioning failed.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_PROVISIONING_FAILED = 6616002,

    /**
     * The DRM-protected content to play is incompatible.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_CONTENT_ERROR = 6616003,

    /**
     * Failed to obtain a license.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_LICENSE_ACQUISITION_FAILED = 6616004,

    /**
     * The operation is disallowed by the license policy.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_DISALLOWED_OPERATION = 6616005,

    /**
     * An error occurs in the DRM system.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_SYSTEM_ERROR = 6616006,

    /**
     * The device has revoked DRM privileges.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_DEVICE_REVOKED = 6616007,

    /**
     * The DRM license being loaded into the open DRM session has expired.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_LICENSE_EXPIRED = 6616008,

    /**
     * An error occurs when the DRM processes the key response.
     * @syscap SystemCapability.Multimedia.AVSession.AVCast
     * @atomicservice
     * @since 13
     */
    ERR_CODE_CAST_CONTROL_DRM_PROVIDE_KEY_RESPONSE_ERROR = 6616100,
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_INFO_H
