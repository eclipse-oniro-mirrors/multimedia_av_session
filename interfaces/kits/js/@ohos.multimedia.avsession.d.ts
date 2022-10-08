/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import { AsyncCallback } from './basic';
import { WantAgent } from '@ohos.wantAgent';
import KeyEvent from './@ohos.multimodalInput.keyEvent';
import { ElementName } from './bundle/elementName';
import image from './@ohos.multimedia.image';
import audio from './@ohos.multimedia.audio';

/**
 * @name avSession
 * @syscap SystemCapability.Multimedia.AVSession.Core
 * @import import avsession from '@ohos.multimedia.avsession';
 * @since 9
 */
declare namespace avSession {
  /**
   * Create an AVSession instance. An ability can only create one AVSession
   * @param context The context of application
   * @param tag A user-defined name for this session
   * @param type The type of session {@link AVSessionType}
   * @param {AsyncCallback<AVSession>} [callback] - callback.
   * @return @returns {void | Promise<AVSession>} no callback return Promise otherwise return void
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  function createAVSession(context: Context, tag: string, type: AVSessionType, callback: AsyncCallback<AVSession>): void;
  function createAVSession(context: Context, tag: string, type: AVSessionType): Promise<AVSession>;

  /**
   * Get all avsession descriptors of the system
   * @param -
   * @return The array of {@link AVSessionDescriptor}
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
   * @systemapi Hide this for inner system use
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   * @since 9
   */
  function getAllSessionDescriptors(callback: AsyncCallback<Array<Readonly<AVSessionDescriptor>>>): void;
  function getAllSessionDescriptors(): Promise<Array<Readonly<AVSessionDescriptor>>>;

  /**
   * Create an avsession controller
   * @param sessionId Specifies the sessionId to create the controller.
   * If provided 'default', the system will create a default controller, Used to control the system default session
   * @return An instance of {@link AVSessionController}
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
   * @systemapi Hide this for inner system use
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   */
  function createController(sessionId: string, callback: AsyncCallback<AVSessionController>): void;
  function createController(sessionId: string): Promise<AVSessionController>;

  /**
   * Cast Audio to the remote devices or cast back local device
   * @param audioDevices Specifies the audio devices to cast.
   * @param sessionId Specifies the sessionId which to send to remote.
   * 'all' means cast all the media audio of this device to remote.
   * @return -
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
   * @systemapi Hide this for inner system use
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   */
  function castAudio(session: SessionToken | 'all', audioDevices: Array<audio.AudioDeviceDescriptor>, callback: AsyncCallback<void>): void;
  function castAudio(session: SessionToken | 'all', audioDevices: Array<audio.AudioDeviceDescriptor>): Promise<void>;

  /**
   * Session token. Used to judge the legitimacy of the session.
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi Hide this for inner system use
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   */
  interface SessionToken {
    /**
     * session id
     * @since 9
     */
    sessionId: string;
    /**
     * process id
     * @since 9
     */
    pid: number;
    /**
     * user id
     * @since 9
     */
    uid: number;
  }
  /**
   * Register or unregister system session changed callback
   * @param type Registration Type, session creation, deletion or top priority session changed
   * @param callback Used to return the descriptor of created or delete session
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi Hide this for inner system use
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   */
  function on(type: 'sessionCreate' | 'sessionDestroy' | 'topSessionChange', callback: (session: AVSessionDescriptor) => void): void;
  function off(type: 'sessionCreate' | 'sessionDestroy' | 'topSessionChange', callback?: (session: AVSessionDescriptor) => void): void;

  /**
   * Register or unregister Session service death callback, notifying the application to clean up resources.
   * @param type Registration Type
   * @param callback Used to handle the session service death event.
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  function on(type: 'sessionServiceDie', callback: () => void): void;
  function off(type: 'sessionServiceDie', callback?: () => void): void;

  /**
   * Send system media key event.The system automatically selects the recipient.
   * @param event The key event to be send
   * @return -
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
   * @systemapi Hide this for inner system use
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   */
  function sendSystemAVKeyEvent(event: KeyEvent, callback: AsyncCallback<void>): void;
  function sendSystemAVKeyEvent(event: KeyEvent): Promise<void>;

  /**
   * Send system control command.The system automatically selects the recipient.
   * @param command The command to be send. See {@link AVControlCommand}
   * @return -
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
   * If all the sessions do not support the command, it will throw AVSessionErrCode.ERR_CODE_COMMAND_INVALID
   * @systemapi Hide this for inner system use
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   */
  function sendSystemControlCommand(command: AVControlCommand, callback: AsyncCallback<void>): void;
  function sendSystemControlCommand(command: AVControlCommand): Promise<void>;

  /**
   * session type.
   */
  type AVSessionType = 'audio' | 'video';
  /**
   * AVSession object.
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  interface AVSession {
    /**
     * unique session Id
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    readonly sessionId: string;

    /**
     * Set the metadata of this session.
     * In addition to the required properties, users can fill in partially supported properties
     * @param data {@link AVMetadata}
     * @return -
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
     */
    setAVMetadata(data: AVMetadata, callback: AsyncCallback<void>): void;
    setAVMetadata(data: AVMetadata): Promise<void>;

    /**
     * Set the playback state of this session.
     * @param state {@link AVPlaybackState}
     * @return -
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
     */
    setAVPlaybackState(state: AVPlaybackState, callback: AsyncCallback<void>): void;
    setAVPlaybackState(state: AVPlaybackState): Promise<void>;

    /**
     * Set the ability to start the session corresponding to
     * @param ability The WantAgent for launch the ability
     * @return -
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
     */
    setLaunchAbility(ability: WantAgent, callback: AsyncCallback<void>): void;
    setLaunchAbility(ability: WantAgent): Promise<void>;

    /**
     * Set audio stream id. Identifies the audio streams controlled by this session.
     * If multiple streams are set, these streams will be simultaneously cast to the remote during the casting operation.
     * @param streamId The audio streams
     * @return -
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
     */
    setAudioStreamId(streamIds: Array<number>, callback: AsyncCallback<void>): void;
    setAudioStreamId(streamIds: Array<number>): Promise<void>;

    /**
     * Get the current session's own controller
     * @param -
     * @return The instance of {@link AVSessionController}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
     */
    getController(callback: AsyncCallback<AVSessionController>): void;
    getController(): Promise<AVSessionController>;

    /**
     * Get output device information
     * @param -
     * @return The instance of {@link OutputDeviceInfo}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
     */
    getOutputDevice(callback: AsyncCallback<OutputDeviceInfo>): void;
    getOutputDevice(): Promise<OutputDeviceInfo>;

    /**
     * Register or unregister playback command callback.
     * As long as it is registered, it means that the ability supports this command.
     * If you cancel the callback, you need to call off {@link off}
     * When canceling the callback, need to update the supported commands list.
     * Each playback command only supports registering one callback,
     * and the new callback will replace the previous one.
     * @param type Command to register.
     * @param callback Used to handle callback commands
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' | 'fastForward' | 'rewind', callback: () => void): void;
    off(type: 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' | 'fastForward' | 'rewind', callback?: () => void): void;

    /**
     * Register or unregister seek command callback
     * @param type Registration Type 'seek'
     * @param callback Used to handle seek command.The callback provide the seek time(ms)
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'seek', callback: (time: number) => void): void;
    off(type: 'seek', callback?: (time: number) => void): void;

    /**
     * Register or unregister setSpeed command callback
     * @param type Registration Type 'setSpeed'
     * @param callback Used to handle setSpeed command.The callback provide the speed value
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'setSpeed', callback: (speed: number) => void): void;
    off(type: 'setSpeed', callback?: (speed: number) => void): void;

    /**
     * Register or unregister setLoopMode command callback
     * @param type Registration Type 'setLoopMode'
     * @param callback Used to handle setLoopMode command.The callback provide the {@link LoopMode}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'setLoopMode', callback: (mode: LoopMode) => void): void;
    off(type: 'setLoopMode', callback?: (mode: LoopMode) => void): void;

    /**
     * Register or unregister toggle favorite command callback
     * @param type Registration Type 'toggleFavorite'
     * @param callback Used to handle toggleFavorite command.The callback provide
     * the assetId for which the favorite status needs to be switched.
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'toggleFavorite', callback: (assetId: string) => void): void;
    off(type: 'toggleFavorite', callback?: (assetId: string) => void): void;

    /**
     * Register or unregister media key handling callback
     * @param type Registration Type
     * @param callback Used to handle key events.The callback provide the KeyEvent
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'handleKeyEvent', callback: (event: KeyEvent) => void): void;
    off(type: 'handleKeyEvent', callback?: (event: KeyEvent) => void): void;

    /**
     * Register or unregister session output device change callback
     * @param type Registration Type
     * @param callback Used to handle output device changed.
     * The callback provide the new device info {@link OutputDeviceInfo}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'outputDeviceChange', callback: (device: OutputDeviceInfo) => void): void;
    off(type: 'outputDeviceChange', callback?: (device: OutputDeviceInfo) => void): void;

    /**
     * Activate the session, indicating that the session can accept control commands
     * @param -
     * @return -
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
     */
    activate(callback: AsyncCallback<void>): void;
    activate(): Promise<void>;

    /**
     * Deactivate the session, indicating that the session not ready to accept control commands
     * @param -
     * @return -
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    deactivate(callback: AsyncCallback<void>): void;
    deactivate(): Promise<void>;

    /**
     * Destroy this session, the server will clean up the session resources
     * @param -
     * @return -
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    destroy(callback: AsyncCallback<void>): void;
    destroy(): Promise<void>;
  }

  /**
   * The metadata of the current media.Used to set the properties of the current media file
   * @since 9
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  interface AVMetadata {
    /**
     * Unique ID used to represent this media.
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    assetId: string;
    /**
     * The title of this media, for display in media center.
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    title?: string;
    /**
     * The artist of this media
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    artist?: string;
    /**
     * The author of this media
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    author?: string;
    /**
     * The album of this media
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    album?: string;
    /**
     * The writer of this media
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    writer?: string;
    /**
     * The composer of this media
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    composer?: string;
    /**
     * The duration of this media, used to automatically calculate playback position
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    duration?: number;
    /**
     * The image of the media as a {@link PixelMap} or an uri formatted String,
     * used to display in media center.
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    mediaImage?: image.PixelMap | string;
    /**
     * The publishDate of the media
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    publishDate?: Date;
    /**
     * The subtitle of the media, used for display
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    subtitle?: string;
    /**
     * The discription of the media, used for display
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    description?: string;
    /**
     * The lyric of the media, it should be in standard lyric format
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    lyric?: string;
    /**
     * The previous playable media id.
     * Used to tell the controller if there is a previous playable media
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    previousAssetId?: string;
    /**
     * The next playable media id.
     * Used to tell the controller if there is a next playable media
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    nextAssetId?: string;
  }

  /**
   * Used to indicate the playback state of the current media.
   * If the playback state of the media changes, it needs to be updated synchronously
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  interface AVPlaybackState {
    /**
     * Current playback state. See {@link PlaybackState}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    state?: PlaybackState;
    /**
     * Current playback speed
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    speed?: number;
    /**
     * Current playback position of this media. See {@link PlaybackPosition}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    position?: PlaybackPosition;
    /**
     * The current buffered time, the maximum playable position
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    bufferedTime?: number;
    /**
     * Current playback loop mode. See {@link LoopMode}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    loopMode?: LoopMode;
    /**
     * Current Favorite Status
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    isFavorite?: boolean;
  }

  /**
   * Playback position defination
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  interface PlaybackPosition {
    /**
     * Elapsed time(position) of this media set by the app.
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    elapsedTime: number;
    /**
     * Record the system time when elapsedTime is set.
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    updateTime: number;
  }
  /**
   * Target Device Information Definition
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  interface OutputDeviceInfo {
    /**
     * Whether the remote device
     * @since 9
     */
    isRemote: boolean;
    /**
     * Audio device id.The length of the audioDeviceId array is greater than 1
     * if output to multiple devices at the same time.
     * @since 9
     */
    audioDeviceId: Array<number>;
    /**
     * Device name. The length of the deviceName array is greater than 1
     * if output to multiple devices at the same time.
     * @since 9
     */
    deviceName: Array<string>;
  }
  /**
   * Loop Play Mode Definition
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  enum LoopMode {
    /**
     * The default mode is sequential playback
     * @since 9
     */
    LOOP_MODE_SEQUENCE = 0,

    /**
     * Single loop mode
     * @since 9
     */
    LOOP_MODE_SINGLE = 1,

    /**
     * List loop mode
     * @since 9
     */
    LOOP_MODE_LIST = 2,

    /**
     * Shuffle playback mode
     * @since 9
     */
    LOOP_MODE_SHUFFLE = 3,
  }

  /**
   * Definition of current playback state
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  enum PlaybackState {
    /**
     * Initial state. The initial state of media file
     * @since 9
     */
    PLAYBACK_STATE_INITIAL = 0,

    /**
     * Preparing state. Indicates that the media file is not ready to play,
     * the media is loading or buffering
     * @since 9
     */
    PLAYBACK_STATE_PREPARE = 1,

    /**
     * Playing state.
     * @since 9
     */
    PLAYBACK_STATE_PLAY = 2,

    /**
     * Paused state.
     * @since 9
     */
    PLAYBACK_STATE_PAUSE = 3,

    /**
     * Fast forwarding state.
     * @since 9
     */
    PLAYBACK_STATE_FAST_FORWARD = 4,

    /**
     * Rewinding state.
     * @since 9
     */
    PLAYBACK_STATE_REWIND = 5,

    /**
     * Stopped state.The server will clear the media playback position and other information.
     * @since 9
     */
    PLAYBACK_STATE_STOP = 6,
  }

  /**
   * The description of the session
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi Hide this for inner system use
   */
  interface AVSessionDescriptor {
    /**
     * Unique ID of the session
     * @since 9
     */
    sessionId: string;
    /**
     * Session type, currently supports audio or video
     * @since 9
     */
    type: AVSessionType;
    /**
     * The session tag set by the application
     * @since 9
     */
    sessionTag: string;
    /**
     * The elementName of the ability that created this session. See {@link ElementName} in bundle/elementName.d.ts
     * @since 9
     */
    elementName: ElementName;
    /**
     * Session active state
     * @since 9
     */
    isActive: boolean;
    /**
     * Is it the top priority session
     * @since 9
     */
    isTopSession: boolean;
    /**
     * The current output device information.
     * It will be undefined if this is a local session.
     * @since 9
     */
    outputDevice: OutputDeviceInfo;
  }

  /**
   * Session controller,used to control media playback and get media information
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  interface AVSessionController {
    /**
     * Unique session Id
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    readonly sessionId: string;
    /**
     * Get the playback status of the current session
     * @param -
     * @return AVPlaybackState {@link AVPlaybackState}
     * @since 9
     */
    getAVPlaybackState(callback: AsyncCallback<AVPlaybackState>): void;
    getAVPlaybackState(): Promise<AVPlaybackState>;

    /**
     * Get the metadata of the current session
     * @param -
     * @return AVMetadata {@link AVMetadata}
     * @since 9
     */
    getAVMetadata(callback: AsyncCallback<AVMetadata>): void;
    getAVMetadata(): Promise<AVMetadata>;

    /**
     * Get output device information
     * @param -
     * @return The instance of {@link OutputDeviceInfo}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws Throws this exception if any of the following errors occurs:{@link AVSessionErrCode}.
     */
    getOutputDevice(callback: AsyncCallback<OutputDeviceInfo>): void;
    getOutputDevice(): Promise<OutputDeviceInfo>;

    /**
     * Send media key event to this session
     * @param event The KeyEvent
     * @return -
     * @since 9
     */
    sendAVKeyEvent(event: KeyEvent, callback: AsyncCallback<void>): void;
    sendAVKeyEvent(event: KeyEvent): Promise<void>;

    /**
     * Get the {@link WantAgent} of this session that can launch the session ability
     * @param -
     * @return WantAgent {@link WantAgent}
     * @since 9
     */
    getLaunchAbility(callback: AsyncCallback<WantAgent>): void;
    getLaunchAbility(): Promise<WantAgent>;

    /**
     * Get the adjusted playback position. The time automatically calculated by the system
     * taking into account factors such as playback status, playback speed, and application update time.
     * @param -
     * @return current playback position in ms.Note that the return value of each call will be different.
     * @since 9
     */
    getRealPlaybackPositionSync(): number;

    /**
     * Check if the current session is active
     * @param -
     * @return the active state
     * @since 9
     */
    isActive(callback: AsyncCallback<boolean>): void;
    isActive(): Promise<boolean>;

    /**
     * Destroy the server controller
     * @param -
     * @return -
     * @since 9
     */
    destroy(callback: AsyncCallback<void>): void;
    destroy(): Promise<void>;

    /**
     * Get commands supported by the current session
     * @param -
     * @return An array of AVControlCommandType {@link AVControlCommandType}
     * @since 9
     */
    getValidCommands(callback: AsyncCallback<Array<AVControlCommandType>>): void;
    getValidCommands(): Promise<Array<AVControlCommandType>>;

    /**
     * Send control commands to this session
     * @param command The command to be send. See {@link AVControlCommand}
     * @return -
     * @since 9
     */
    sendControlCommand(command: AVControlCommand, callback: AsyncCallback<void>): void;
    sendControlCommand(command: AVControlCommand): Promise<void>;

    /**
     * Register or unregister metadata changed callback
     * @param type 'metadataChange'
     * @param filter The properties of {@link AVMetadata} that you cared about
     * @param callback The callback used to handle metadata changed event.
     * The callback function provides the {@link AVMetadata} parameter.
     * It only contains the properties set in the filter.
     * @return -
     * @since 9
     */
    on(type: 'metadataChange', filter: Array<keyof AVMetadata> | 'all', callback: (data: AVMetadata) => void);
    off(type: 'metadataChange', callback?: (data: AVMetadata) => void);

    /**
     * Register or unregister playback state changed callback
     * @param type 'playbackStateChange'
     * @param filter The properties of {@link AVPlaybackState} that you cared about
     * @param callback The callback used to handle playback state changed event.
     * The callback function provides the {@link AVPlaybackState} parameter.
     * @return -
     * @since 9
     */
    on(type: 'playbackStateChange', filter: Array<keyof AVPlaybackState> | 'all', callback: (state: AVPlaybackState) => void);
    off(type: 'playbackStateChange', callback?: (state: AVPlaybackState) => void);

    /**
     * Register or unregister current session destroyed callback
     * @param type 'sessionDestroy'
     * @param callback The callback used to handle current session destroyed event.
     * @return -
     * @since 9
     */
    on(type: 'sessionDestroy', callback: () => void);
    off(type: 'sessionDestroy', callback?: () => void);

    /**
     * Register or unregister the active state of this session changed callback
     * @param type 'activeStateChange'
     * @param callback The callback used to handle the active state of this session changed event.
     * The callback function provides the changed session state.
     * @return -
     * @since 9
     */
    on(type: 'activeStateChange', callback: (isActive: boolean) => void);
    off(type: 'activeStateChange', callback?: (isActive: boolean) => void);

    /**
     * Register or unregister the valid commands of the session changed callback
     * @param type 'validCommandChange'
     * @param callback The callback used to handle the changes.
     * The callback function provides an array of AVControlCommandType.
     * @return -
     * @since 9
     */
    on(type: 'validCommandChange', callback: (commands: Array<AVControlCommandType>) => void);
    off(type: 'validCommandChange', callback?: (commands: Array<AVControlCommandType>) => void);

    /**
     * Register or unregister session output device change callback
     * @param type Registration Type
     * @param callback Used to handle output device changed.
     * The callback provide the new device info {@link OutputDeviceInfo}
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'outputDeviceChange', callback: (device: OutputDeviceInfo) => void): void;
    off(type: 'outputDeviceChange', callback?: (device: OutputDeviceInfo) => void): void;
  }

  /**
   * The type of control command
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  type AVControlCommandType = 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' | 'fastForward' | 'rewind' |
                              'seek' | 'setSpeed' | 'setLoopMode' | 'toggleFavorite';

  /**
   * The defination of command to be send to the session
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  interface AVControlCommand {
    /**
     * The command value {@link AVControlCommandType}
     * @since 9
     */
    command: AVControlCommandType;
    /**
     * parameter of the command. Whether this command requires parameters, see {@link AVSessionCommand}
     * seek command requires a number parameter
     * setSpeed command requires a number parameter
     * setLoopMode command requires a {@link LoopMode} parameter.
     * toggleFavorite command requires assetId {@link AVMetadata.assetId} parameter
     * other commands need no parameter
     * @since 9
     */
    parameter?: LoopMode | string | number;
  }

  /**
   * Enumerates ErrorCode types, return in BusinessError.code.
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  enum AVSessionErrorCode {
    /**
     * Server exception
     * @since 9
     */
    ERR_CODE_SERVICE_EXCEPTION = 6600101,

    /**
     * The session does not exist
     * @since 9
     */
    ERR_CODE_SESSION_NOT_EXIST = 6600102,

    /**
     * The controller does not exist
     * @since 9
     */
    ERR_CODE_CONTROLLER_NOT_EXIST = 6600103,

    /**
     * Remote connection error
     * @since 9
     */
    ERR_CODE_REMOTE_CONNECTION_ERR = 6600104,

    /**
     * Command not supported
     * @since 9
     */
    ERR_CODE_COMMAND_INVALID = 6600105,

    /**
     * Session inactive
     * @since 9
     */
    ERR_CODE_SESSION_INACTIVE = 6600106,

    /**
     * Command or event overload
     * @since 9
     */
    ERR_CODE_MESSAGE_OVERLOAD = 6600107,
  }
}

export default avSession;
