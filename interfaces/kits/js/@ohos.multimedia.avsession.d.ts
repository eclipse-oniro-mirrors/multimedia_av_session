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
   * @returns {void | Promise<AVSession>} no callback returns Promise otherwise returns void
   * @throws {BusinessError} 401 - parameter check failed
   * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  function createAVSession(context: Context, tag: string, type: AVSessionType, callback: AsyncCallback<AVSession>): void;
  function createAVSession(context: Context, tag: string, type: AVSessionType): Promise<AVSession>;

  /**
   * Get all avsession descriptors of the system
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   * @returns The array of {@link AVSessionDescriptor}
   * @throws {BusinessError} 201 - permission denied
   * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi
   * @since 9
   */
  function getAllSessionDescriptors(callback: AsyncCallback<Array<Readonly<AVSessionDescriptor>>>): void;
  function getAllSessionDescriptors(): Promise<Array<Readonly<AVSessionDescriptor>>>;

  /**
   * Create an avsession controller
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   * @param sessionId Specifies the sessionId to create the controller.
   * If provided 'default', the system will create a default controller, Used to control the system default session
   * @returns An instance of {@link AVSessionController}
   * @throws {BusinessError} 201 - permission denied
   * @throws {BusinessError} 401 - parameter check failed
   * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
   * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi
   * @since 9
   */
  function createController(sessionId: string, callback: AsyncCallback<AVSessionController>): void;
  function createController(sessionId: string): Promise<AVSessionController>;

  /**
   * Cast Audio to the remote devices or cast back local device
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   * @param audioDevices Specifies the audio devices to cast.
   * @param sessionId Specifies the sessionId which to send to remote.
   * 'all' means cast all the media audio of this device to remote.
   * @throws {BusinessError} 201 - permission denied
   * @throws {BusinessError} 401 - parameter check failed
   * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
   * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
   * @throws {BusinessError} {@link #ERR_CODE_REMOTE_CONNECTION_ERR} - remote connection error
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi
   * @since 9
   */
  function castAudio(session: SessionToken | 'all', audioDevices: Array<audio.AudioDeviceDescriptor>, callback: AsyncCallback<void>): void;
  function castAudio(session: SessionToken | 'all', audioDevices: Array<audio.AudioDeviceDescriptor>): Promise<void>;

  /**
   * Session token. Used to judge the legitimacy of the session.
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi
   * @since 9
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
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   * @param type Registration Type, session creation, deletion or top priority session changed
   * @param callback Used to returns the descriptor of created or delete session
   * @throws {BusinessError} 201 - permission denied
   * @throws {BusinessError} 401 - parameter check failed
   * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi
   * @since 9
   */
  function on(type: 'sessionCreate' | 'sessionDestroy' | 'topSessionChange', callback: (session: AVSessionDescriptor) => void): void;
  function off(type: 'sessionCreate' | 'sessionDestroy' | 'topSessionChange', callback?: (session: AVSessionDescriptor) => void): void;

  /**
   * Register or unregister Session service death callback, notifying the application to clean up resources.
   * @param type Registration Type
   * @param callback Used to handle the session service death event.
   * @throws {BusinessError} 201 - permission denied
   * @throws {BusinessError} 401 - packagearameter check failed
   * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  function on(type: 'sessionServiceDie', callback: () => void): void;
  function off(type: 'sessionServiceDie', callback?: () => void): void;

  /**
   * Send system media key event.The system automatically selects the recipient.
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   * @param event The key event to be send
   * @throws {BusinessError} 201 - permission denied
   * @throws {BusinessError} 401 - parameter check failed
   * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
   * @throws {BusinessError} {@link #ERR_CODE_COMMAND_INVALID} - command not supported
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi
   * @since 9
   */
  function sendSystemAVKeyEvent(event: KeyEvent, callback: AsyncCallback<void>): void;
  function sendSystemAVKeyEvent(event: KeyEvent): Promise<void>;

  /**
   * Send system control command.The system automatically selects the recipient.
   * @permission ohos.permission.MANAGE_MEDIA_RESOURCES
   * @param command The command to be send. See {@link AVControlCommand}
   * @throws {BusinessError} 201 - permission denied
   * @throws {BusinessError} 401 - parameter check failed
   * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
   * @throws {BusinessError} {@link #ERR_CODE_COMMAND_INVALID} - command not supported
   * @throws {BusinessError} {@link #ERR_CODE_MESSAGE_OVERLOAD} - command or event overload
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi
   * @since 9
   */
  function sendSystemControlCommand(command: AVControlCommand, callback: AsyncCallback<void>): void;
  function sendSystemControlCommand(command: AVControlCommand): Promise<void>;

  /**
   * session type.
   */
  type AVSessionType = 'audio' | 'video';
  /**
   * AVSession object.
   * @interface AVSession
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  interface AVSession {
    /**
     * unique session Id
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    readonly sessionId: string;

    /**
     * Set the metadata of this session.
     * In addition to the required properties, users can fill in partially supported properties
     * @param data {@link AVMetadata}
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    setAVMetadata(data: AVMetadata, callback: AsyncCallback<void>): void;
    setAVMetadata(data: AVMetadata): Promise<void>;

    /**
     * Set the playback state of this session.
     * @param state {@link AVPlaybackState}
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    setAVPlaybackState(state: AVPlaybackState, callback: AsyncCallback<void>): void;
    setAVPlaybackState(state: AVPlaybackState): Promise<void>;

    /**
     * Set the ability to start the session corresponding to
     * @param ability The WantAgent for launch the ability
     * @since 9
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     */
    setLaunchAbility(ability: WantAgent, callback: AsyncCallback<void>): void;
    setLaunchAbility(ability: WantAgent): Promise<void>;

    /**
     * Set audio stream id. Identifies the audio streams controlled by this session.
     * If multiple streams are set, these streams will be simultaneously cast to the remote during the casting operation.
     * @param streamId The audio streams
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 10
     */
    setAudioStreamId(streamIds: Array<number>, callback: AsyncCallback<void>): void;
    setAudioStreamId(streamIds: Array<number>): Promise<void>;

    /**
     * Get the current session's own controller
     * @returns The instance of {@link AVSessionController}
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    getController(callback: AsyncCallback<AVSessionController>): void;
    getController(): Promise<AVSessionController>;

    /**
     * Get output device information
     * @returns The instance of {@link OutputDeviceInfo}
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
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
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    on(type: 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' | 'fastForward' | 'rewind', callback: () => void): void;
    off(type: 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' | 'fastForward' | 'rewind', callback?: () => void): void;

    /**
     * Register or unregister seek command callback
     * @param type Registration Type 'seek'
     * @param callback Used to handle seek command.The callback provide the seek time(ms)
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    on(type: 'seek', callback: (time: number) => void): void;
    off(type: 'seek', callback?: (time: number) => void): void;

    /**
     * Register or unregister setSpeed command callback
     * @param type Registration Type 'setSpeed'
     * @param callback Used to handle setSpeed command.The callback provide the speed value
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    on(type: 'setSpeed', callback: (speed: number) => void): void;
    off(type: 'setSpeed', callback?: (speed: number) => void): void;

    /**
     * Register or unregister setLoopMode command callback
     * @param type Registration Type 'setLoopMode'
     * @param callback Used to handle setLoopMode command.The callback provide the {@link LoopMode}
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    on(type: 'setLoopMode', callback: (mode: LoopMode) => void): void;
    off(type: 'setLoopMode', callback?: (mode: LoopMode) => void): void;

    /**
     * Register or unregister toggle favorite command callback
     * @param type Registration Type 'toggleFavorite'
     * @param callback Used to handle toggleFavorite command.The callback provide
     * the assetId for which the favorite status needs to be switched.
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    on(type: 'toggleFavorite', callback: (assetId: string) => void): void;
    off(type: 'toggleFavorite', callback?: (assetId: string) => void): void;

    /**
     * Register or unregister media key handling callback
     * @param type Registration Type
     * @param callback Used to handle key events.The callback provide the KeyEvent
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    on(type: 'handleKeyEvent', callback: (event: KeyEvent) => void): void;
    off(type: 'handleKeyEvent', callback?: (event: KeyEvent) => void): void;

    /**
     * Register or unregister session output device change callback
     * @param type Registration Type
     * @param callback Used to handle output device changed.
     * The callback provide the new device info {@link OutputDeviceInfo}
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    on(type: 'outputDeviceChange', callback: (device: OutputDeviceInfo) => void): void;
    off(type: 'outputDeviceChange', callback?: (device: OutputDeviceInfo) => void): void;

    /**
     * Activate the session, indicating that the session can accept control commands
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    activate(callback: AsyncCallback<void>): void;
    activate(): Promise<void>;

    /**
     * Deactivate the session, indicating that the session not ready to accept control commands
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    deactivate(callback: AsyncCallback<void>): void;
    deactivate(): Promise<void>;

    /**
     * Destroy this session, the server will clean up the session resources
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    destroy(callback: AsyncCallback<void>): void;
    destroy(): Promise<void>;
  }

  /**
   * The metadata of the current media.Used to set the properties of the current media file
   * @interface AVMetadata
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  interface AVMetadata {
    /**
     * Unique ID used to represent this media.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    assetId: string;
    /**
     * The title of this media, for display in media center.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    title?: string;
    /**
     * The artist of this media
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    artist?: string;
    /**
     * The author of this media
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    author?: string;
    /**
     * The album of this media
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    album?: string;
    /**
     * The writer of this media
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    writer?: string;
    /**
     * The composer of this media
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    composer?: string;
    /**
     * The duration of this media, used to automatically calculate playback position
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    duration?: number;
    /**
     * The image of the media as a {@link PixelMap} or an uri formatted String,
     * used to display in media center.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    mediaImage?: image.PixelMap | string;
    /**
     * The publishDate of the media
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    publishDate?: Date;
    /**
     * The subtitle of the media, used for display
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    subtitle?: string;
    /**
     * The discription of the media, used for display
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    description?: string;
    /**
     * The lyric of the media, it should be in standard lyric format
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    lyric?: string;
    /**
     * The previous playable media id.
     * Used to tell the controller if there is a previous playable media
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    previousAssetId?: string;
    /**
     * The next playable media id.
     * Used to tell the controller if there is a next playable media
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    nextAssetId?: string;
  }

  /**
   * Used to indicate the playback state of the current media.
   * If the playback state of the media changes, it needs to be updated synchronously
   * @interface AVPlaybackState
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  interface AVPlaybackState {
    /**
     * Current playback state. See {@link PlaybackState}
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    state?: PlaybackState;
    /**
     * Current playback speed
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    speed?: number;
    /**
     * Current playback position of this media. See {@link PlaybackPosition}
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    position?: PlaybackPosition;
    /**
     * The current buffered time, the maximum playable position
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    bufferedTime?: number;
    /**
     * Current playback loop mode. See {@link LoopMode}
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    loopMode?: LoopMode;
    /**
     * Current Favorite Status
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    isFavorite?: boolean;
  }

  /**
   * Playback position defination
   * @interface PlaybackPosition
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  interface PlaybackPosition {
    /**
     * Elapsed time(position) of this media set by the app.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    elapsedTime: number;
    /**
     * Record the system time when elapsedTime is set.
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    updateTime: number;
  }
  /**
   * Target Device Information Definition
   * @interface OutputDeviceInfo
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
   * @enum {number}
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
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
   * @enum {number}
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
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
   * @interface AVSessionDescriptor
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @systemapi
   * @since 9
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
   * @interface AVSessionController
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
   */
  interface AVSessionController {
    /**
     * Unique session Id
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    readonly sessionId: string;
    /**
     * Get the playback status of the current session
     * @returns AVPlaybackState {@link AVPlaybackState}
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    getAVPlaybackState(callback: AsyncCallback<AVPlaybackState>): void;
    getAVPlaybackState(): Promise<AVPlaybackState>;

    /**
     * Get the metadata of the current session
     * @returns AVMetadata {@link AVMetadata}
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    getAVMetadata(callback: AsyncCallback<AVMetadata>): void;
    getAVMetadata(): Promise<AVMetadata>;

    /**
     * Get output device information
     * @returns The instance of {@link OutputDeviceInfo}
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
     */
    getOutputDevice(callback: AsyncCallback<OutputDeviceInfo>): void;
    getOutputDevice(): Promise<OutputDeviceInfo>;

    /**
     * Send media key event to this session
     * @param event The KeyEvent
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @throws {BusinessError} {@link #ERR_CODE_COMMAND_INVALID} - command not supported
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_INACTIVE} - session inactive
     * @since 9
     */
    sendAVKeyEvent(event: KeyEvent, callback: AsyncCallback<void>): void;
    sendAVKeyEvent(event: KeyEvent): Promise<void>;

    /**
     * Get the {@link WantAgent} of this session that can launch the session ability
     * @returns WantAgent {@link WantAgent}
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    getLaunchAbility(callback: AsyncCallback<WantAgent>): void;
    getLaunchAbility(): Promise<WantAgent>;

    /**
     * Get the adjusted playback position. The time automatically calculated by the system
     * taking into account factors such as playback status, playback speed, and application update time.
     * @returns current playback position in ms.Note that the returns value of each call will be different.
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    getRealPlaybackPositionSync(): number;

    /**
     * Check if the current session is active
     * @returns the active state
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    isActive(callback: AsyncCallback<boolean>): void;
    isActive(): Promise<boolean>;

    /**
     * Destroy the server controller
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    destroy(callback: AsyncCallback<void>): void;
    destroy(): Promise<void>;

    /**
     * Get commands supported by the current session
     * @returns An array of AVControlCommandType {@link AVControlCommandType}
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    getValidCommands(callback: AsyncCallback<Array<AVControlCommandType>>): void;
    getValidCommands(): Promise<Array<AVControlCommandType>>;

    /**
     * Send control commands to this session
     * @param command The command to be send. See {@link AVControlCommand}
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_NOT_EXIST} - session does not exist
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @throws {BusinessError} {@link #ERR_CODE_COMMAND_INVALID} - command not supported
     * @throws {BusinessError} {@link #ERR_CODE_SESSION_INACTIVE} - session inactive
     * @throws {BusinessError} {@link #ERR_CODE_MESSAGE_OVERLOAD} - command or event overload
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
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
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
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    on(type: 'playbackStateChange', filter: Array<keyof AVPlaybackState> | 'all', callback: (state: AVPlaybackState) => void);
    off(type: 'playbackStateChange', callback?: (state: AVPlaybackState) => void);

    /**
     * Register or unregister current session destroyed callback
     * @param type 'sessionDestroy'
     * @param callback The callback used to handle current session destroyed event.
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    on(type: 'sessionDestroy', callback: () => void);
    off(type: 'sessionDestroy', callback?: () => void);

    /**
     * Register or unregister the active state of this session changed callback
     * @param type 'activeStateChange'
     * @param callback The callback used to handle the active state of this session changed event.
     * The callback function provides the changed session state.
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    on(type: 'activeStateChange', callback: (isActive: boolean) => void);
    off(type: 'activeStateChange', callback?: (isActive: boolean) => void);

    /**
     * Register or unregister the valid commands of the session changed callback
     * @param type 'validCommandChange'
     * @param callback The callback used to handle the changes.
     * The callback function provides an array of AVControlCommandType.
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @since 9
     */
    on(type: 'validCommandChange', callback: (commands: Array<AVControlCommandType>) => void);
    off(type: 'validCommandChange', callback?: (commands: Array<AVControlCommandType>) => void);

    /**
     * Register or unregister session output device change callback
     * @param type Registration Type
     * @param callback Used to handle output device changed.
     * The callback provide the new device info {@link OutputDeviceInfo}
     * @throws {BusinessError} 401 - parameter check failed
     * @throws {BusinessError} {@link #ERR_CODE_SERVICE_EXCEPTION} - server exception
     * @throws {BusinessError} {@link #ERR_CODE_CONTROLLER_NOT_EXIST} - controller does not exist
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @since 9
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
   * @interface AVControlCommand
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
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
   * Enumerates ErrorCode types, returns in BusinessError.code.
   * @enum {number}
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @since 9
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
