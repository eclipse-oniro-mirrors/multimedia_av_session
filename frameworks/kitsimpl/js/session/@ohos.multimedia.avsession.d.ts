// noinspection SpellCheckingInspection

/*
* Copyright (C) 2022 Huawei Device Co., Ltd.
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
import { WantAgent } from './@ohos.wantAgent';
import ime from './@ohos.inputmethodengine';
import image from './@ohos.multimedia.image';

/**
 * @name avsession
 * @syscap SystemCapability.Multimedia.AVSession.Core
 * @import import avsession from '@ohos.multimedia.avsession';
 * @since 10
 */
declare namespace avsession {
  /**
   * Create an avsession instance. An ability can only create one AVSession
   *
   * @param tag A user-defined name for this session
   * @param type The type of session, currently supports audio and video
   * @return The instance of {@link AVSession}
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  function createAVSession(tag: string, type: 'audio'|'video', callback: AsyncCallback<AVSession>): void;
  function createAVSession(tag: string, type: 'audio'|'video'): Promise<AVSession>;

  /**
   * Get the AVSession created by the current ability, or return null if not created
   *
   * @return The created {@link AVSession} instance or null
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Core
   * @param callback
   */
  function getAVSession(callback: AsyncCallback<AVSession>): void;
  function getAVSession(): Promise<AVSession>;

  /**
   * Get all avsession descriptors of the system
   *
   * @return The array of {@link AVSessionDescriptor}
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @param callback
   */
  function getAllSessionDescriptors(callback: AsyncCallback<Array<AVSessionDescriptor>>): void;
  function getAllSessionDescriptors(): Promise<Array<AVSessionDescriptor>>

  /**
   * Create an avsession controller
   *
   * @param sessionId Specifies the sessionId to create the controller
   * @return An instance of {@link AVSessionController}
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  function createController(sessionId: number, callback: AsyncCallback<AVSessionController>): void;
  function createController(sessionId: number): Promise<AVSessionController>;

  /**
   * Get the controller of the specified session, or return null if not created
   *
   * @param sessionId Specifies the sessionId to get the controller
   * @return The {@link AVSessionController} of the session
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  function getController(sessionId: number, callback: AsyncCallback<AVSessionController>): void;
  function getController(sessionId: number): Promise<AVSessionController>;

  /**
   * Get all controllers created by the current ability
   *
   * @return The array of the created {@link AVSessionController}
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   * @param callback
   */
  function getAllControllers(callback: AsyncCallback<Array<AVSessionController>>): void;
  function getAllControllers(): Promise<Array<AVSessionController>>;

  /**
   * Register system session creation or deletion callback
   *
   * @param type Registration Type, session creation or deletion
   * @param callback Used to return the descriptor of created or delete session
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  function on(type: 'sessionCreated' | 'sessionReleased',  callback: (descriptor: AVSessionDescriptor) => void): void;

  /**
   * Register the top priority session change callback
   *
   * @param type Registration Type
   * @param callback Used to return the descriptor of the top priority session
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  function on(type: 'topSessionChanged', callback: (descriptor: AVSessionDescriptor) => void): void;

  /**
   * Register AvSession service death callback
   *
   * @param type Registration Type
   * @param deathCallback Used to notify service has dead
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  function on(type: 'serviceDeath', deathCallback: () => void): void;

  /**
   * Send system media key event
   *
   * @param event The key event to be send
   * @return -
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  function sendSysetemMediaKeyEvent(event: ime.KeyEvent, callback: AsyncCallback<void>): void;
  function sendSysetemMediaKeyEvent(event: ime.KeyEvent): Promise<void>;

  /**
   * Set system media volume
   *
   * @param volume The volume value
   * @return -
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  function setSystemMediaVolume(volume: number, callback: AsyncCallback<void>): void;
  function setSystemMediaVolume(volume: number): Promise<void>

  /**
   *  AVSession object.
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  interface AVSession {
    /**
     * Get unique session Id
     *
     * @return Session Id
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    getSessionId(): number;

    /**
     * Get the metadata of this session
     *
     * @return An instance of {@link AVMetadata}
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    getAVMetadata(): Promise<AVMetadata>;
    getAVMetadata(callback: AsyncCallback<AVMetadata>): void;

    /**
     * Set the metadata of this session.
     *
     * In addition to the required properties, users can fill in partially supported properties
     * @param data {@link AVMetadata}
     * @return -
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    setAVMetadata(data: AVMetadata, callback: AsyncCallback<void>): void;
    setAVMetadata(data: AVMetadata): Promise<void>;

    /**
     * Get the playback state of this session
     *
     * @return {@link AVPlaybackState}
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @param callback
     */
    getAVPlaybackState(callback: AsyncCallback<AVPlaybackState>): void;
    getAVPlaybackState(): Promise<AVPlaybackState>;

    /**
     * Set the playback state of this session.
     *
     * @param state {@link AVPlaybackState}
     * @return -
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    setAVPlaybackState(state: AVPlaybackState, callback: AsyncCallback<void>): void;
    setAVPlaybackState(state: AVPlaybackState): Promise<void>;

    /**
     * Set the ability to start the session corresponding to
     *
     * @param ability The WantAgent for launch the ability
     * @return -
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    setLaunchAbility(ability: WantAgent, callback: AsyncCallback<void>): void;
    setLaunchAbility(ability: WantAgent): Promise<void>;

    /**
     * Get the current session's own controller
     * @param -
     * @return The instance of {@link AVSessionController}
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    getController(callback: AsyncCallback<AVSessionController>): void;
    getController(): Promise<AVSessionController>

    /**
     * register playback command callback.
     * As long as it is registered, it means that the ability supports this command.
     * If it is not registered, the callback will not be triggered.
     * When canceling the callback, the callback passes null.
     * Each playback command only supports registering one callback,
     * and the new callback will replace the previous one.
     * @param type Command to register, now supported 'play'|'pause'|'stop'|'playNext'|'playPrevious'|'fastForward'|'rewind'
     * @param callback Used to handle callback commands
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'play'|'pause'|'stop'|'playNext'|'playPrevious'|'fastForward'|'rewind',  callback: () => void): void;

    /**
     * Register media key handling callback
     *
     * @param type Registration Type
     * @param callback Used to handle key events.The callback provide the KeyEvent
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'mediaKeyEvent', callback: (keyEvent: ime.KeyEvent) => void): void;

    /**
     * Register seek command callback
     *
     * @param type Registration Type 'seek'
     * @param callback Used to handle seek command.The callback provide the seek time(ms)
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'seek', callback: (time: number) => void): void;

    /**
     * Register setSpeed command callback
     * @param type Registration Type 'setSpeed'
     * @param callback Used to handle setSpeed command.The callback provide the speed value
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'setSpeed', callback: (speed: number) => void): void;

    /**
     * Register setLoopMode command callback
     * @param type Registration Type 'setLoopMode'
     * @param callback Used to handle setLoopMode command.The callback provide the {@link LoopMode}
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'setLoopMode', callback: (mode: LoopMode) => void): void;

    /**
     * Register toggle favorite command callback
     * @param type Registration Type 'toggleFavorite'
     * @param callback Used to handle toggleFavorite command.The callback provide
     * the mediaId for which the favorite status needs to be switched.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'toggleFavorite', callback: (mediaId: string) => void): void;

    /**
     * Register volume changed event callback
     *
     * @param type Registration Type 'volumeChanged'
     * @param callback Used to handle volumeChanged command.The callback provide
     * the {@link AVVolumeInfo}
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    on(type: 'volumeChanged', callback: (info: AVVolumeInfo) => void): void;

     /**
     * Activate the session, indicating that the session can accept control commands
     *
     * @return -
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @param callback
     */
    active(callback: AsyncCallback<void>): void;
    active(): Promise<void>;

    /**
     * disactivate the session, indicating that the session not ready to accept control commands
     * @param -
     * @return -
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    disactive(callback: AsyncCallback<void>): void;
    disactive(): Promise<void>;

    /**
     * Check whether the session is active
     * @return -
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @param callback
     */
    isActive(callback: AsyncCallback<boolean>): void;
    isActive(): Promise<boolean>;

    /**
     * release this session, the server will clean up the session resources
     * @return -
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     * @param callback
     */
    release(callback: AsyncCallback<void>): void;
    release(): Promise<void>;
  }

  /**
   * Volume related information
   *
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  interface AVVolumeInfo {
    /**
     * current volume value
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    currentVolume: number
    /**
     * maximum volume value
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    maxVolume: number
    /**
     * volume control type. Including absolute volume, relative volume and fixed volume
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    volumeType: 'absolute' | 'relative' | 'fixed'
  }

  /**
   * The metadata of the current media.Used to set the properties of the current media file
   * @since 10
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  interface AVMetadata {
    /**
     * Unique ID used to represent this media.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    mediaId: string
    /**
     * The title of this media, for display in media center.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    title?: string
    /**
     * The artist of this media
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    artist?: string
    /**
     * The author of this media
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    author?: string
    /**
     * The album of this media
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    album?: string
    /**
     * The writer of this media
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    writer?: string
    /**
     * The composer of this media
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    composer?: string
    /**
     * The duration of this media, used to automatically calculate playback position
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    duration?: number
    /**
     * The image of the media as a {@link PixelMap} or an uri formatted String,
     * used to display in media center.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    mediaImage?: image.PixelMap | string
    /**
     * The icon of the application as a {@link PixelMap} or an uri formatted String,
     * used to display in media center. It should be smaller than homescreen icon and
     * it may be scaled down by the system.
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    appIcon?: image.PixelMap | string
    /**
     * The publishDate of the media
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    publishDate?: Date //日期格式？
    //mediaType: string //什么类型？
    //format: string //什么类型？
    //mediaUri: string //参考媒体播放器
    //rating: number
    /**
     * The subtitle of the media, used for display
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    subtile?: string
    /**
     * The discription of the media, used for display
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    description?: string
    /**
     * The lyric of the media, it should be in standard lyric format
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    lyric?: string
  }

  /**
   * Used to indicate the playback state of the current media.
   * If the playback state of the media changes, it needs to be updated synchronously
   */
  interface AVPlaybackState {
    /**
     * Current playback state. See {@link PlaybackState}
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    state: PlaybackState;
    /**
     * Current playback speed
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    speed: number;
    /**
     * Current elapsed time(position) of this media
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    elapsedTime: number;
    /**
     * The current buffered time, the maximum playable position
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    bufferdTime?: number;
    /**
     * Current playback loop mode. See {@link LoopMode}
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    loopMode?: LoopMode;
    /**
     * Current Favorite Status
     * @since 10
     * @syscap SystemCapability.Multimedia.AVSession.Core
     */
    isFavorite?: boolean;
  }


  /**
   * Loop Play Mode Definition
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  enum LoopMode {
    /**
     * The default mode is sequential playback
     * @since 10
     */
    LOOP_MODE_SEQUENCE = 0,
    /**
     * Single loop mode
     * @since 10
     */
    LOOP_MODE_SINGLE,
    /**
     * List loop mode
     * @since 10
     */
    LOOP_MODE_LIST,
    /**
     * Shuffle playback mode
     * @since 10
     */
    LOOP_MODE_SHUFFLE
  }

  /**
   * Definition of current playback state
   * @syscap SystemCapability.Multimedia.AVSession.Core
   */
  enum PlaybackState {
    /**
     * Invalid state. The initial state of media file
     * @since 10
     */
    PLAYBACK_STATE_INVALID = -1,
    /**
     * Preparing state.Indicates that the media file is not ready to paly,
     * the media is loading or buffering
     * @since 10
     */
    PLAYBACK_STATE_PREPARING,
    /**
     * Playing state.
     * @since 10
     */
    PLAYBACK_STATE_PLAYING,
    /**
     * Paused state.
     * @since 10
     */
    PLAYBACK_STATE_PAUSED,
    /**
     * Stopped state.
     * @since 10
     */
    PLAYBACK_STATE_STOPPED
  }


  /**
   * The description of the session
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  interface AVSessionDescriptor {
    /**
     * Unique ID of the session
     * @since 10
     */
    readonly sessionId: number
    /**
     * Session type, currently supports audio or video
     * @since 10
     */
    readonly type: 'audio'|'video'
    /**
     * The session tag set by the application
     * @since 10
     */
    readonly sessionTag: string
    /**
     * The bundleName of the app that created this session
     * @since 10
     */
    readonly bundleName: string
    /**
     * The abilityName of the app that created this session
     * @since 10
     */
    readonly abilityName: string
    /**
     * Session active state
     * @since 10
     */
    readonly isActive: boolean
    /**
     * Is it the top priority session
     * @since 10
     */
    readonly isTopSession: boolean
    /**
     *
     * @since 10
     */
    readonly isRemote: boolean

    readonly remoteDevice?: string
  }

  /**
   * Session controller，used to control media playback and get media information
   * @syscap SystemCapability.Multimedia.AVSession.Manager
   */
  interface AVSessionController {
    /**
     * Get the playback status of the current session
     * @param -
     * @return AVPlaybackState {@link AVPlaybackState}
     * @since 10
     */
    getAVPlaybackState(callback: AsyncCallback<AVPlaybackState>): void;
    getAVPlaybackState():Promise<AVPlaybackState>;
    /**
     * Get the metadata of the current session
     * @param -
     * @return AVMetadata {@link AVMetadata}
     * @since 10
     */
    getAVMetadata(callback: AsyncCallback<AVMetadata>): void;
    getAVMetadata() :Promise<AVMetadata>;

    getAVVolumeInfo(callback: AsyncCallback<AVVolumeInfo>): void;
    getAVVolumeInfo(): Promise<AVVolumeInfo>;

    sendMediaButtonEvent(event: ime.KeyEvent, callback: AsyncCallback<void>): void
    sendMediaButtonEvent(event: ime.KeyEvent): Promise<void>;

    getLaunchAbility(callback: AsyncCallback<WantAgent>): void;
    getLaunchAbility():Promise<WantAgent>;

    isActive(callback: AsyncCallback<boolean>): void;
    isActive(): Promise<boolean>

    release(callback: AsyncCallback<void>): void;
    release(): void;

    getSupportedCommand(): Promise<AVSessionCommand>;
    getSupportedCommand(callback: AsyncCallback<AVSessionCommand>): void;

    sendControlCommand(command: AVControlCommand, callback: AsyncCallback<void>): void;
    sendControlCommand(command: AVControlCommand): Promise<void>;

    on(type: 'volumeInfoChanged', callback: (info: AVVolumeInfo) => void)
    on(type: 'metaDataChanged', filter: Array<keyof AVMetadata>, callback: (data: AVMetadata) => void) //支持设置关心的metadata
    on(type: 'playbackStateChanged', callback: (state: AVPlaybackState) => void) //支持设置关心的状态
    on(type: 'sessionReleased', callback: ()=> void)
    on(type: 'activeStateChanged', callback: (isActive: boolean) => void)
  }

  interface AVSessionCommand{
    play: boolean
    pause: boolean
    stop: boolean
    playNext: boolean
    playPrevious: boolean
    fastForward: boolean
    rewind: boolean
    seek: boolean
    setSpeed: boolean
    setLoopMode: boolean
    toggleFavorite: boolean
  }

  /**
   *
   */
  interface AVControlCommand {
    command: keyof AVSessionCommand;
    param?: LoopMode | string | number;
  }
}

export default avsession;