
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
import KeyEvent from './@ohos.multimodalInput.KeyEvent';
import { ElementName } from './bundle/elementName';
import image from './@ohos.multimedia.image';
import audio from './@ohos.multimedia.audio';

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

  function createAVSession(tag: string, type: AVSessionType, callback: AsyncCallback<AVSession>): void;
  function createAVSession(tag: string, type: AVSessionType): Promise<AVSession>;

  function getAllSessionDescriptors(callback: AsyncCallback<Array<Readonly<AVSessionDescriptor>>>): void;
  function getAllSessionDescriptors(): Promise<Array<Readonly<AVSessionDescriptor>>>;

  function createController(sessionId: number, callback: AsyncCallback<AVSessionController>): void;
  function createController(sessionId: number): Promise<AVSessionController>;

  function castAudio(session: SessionToken | 'all', audioDevices: Array<audio.AudioDeviceDescriptor>, callback: AsyncCallback<void>): void;
  function castAudio(session: SessionToken | 'all', audioDevices: Array<audio.AudioDeviceDescriptor>): Promise<void>;

  interface SessionToken {
    sessionId: number;
    pid: number;
    uid: number;
  }

  function on(type: 'sessionCreated' | 'sessionDestroyed', callback: (session: AVSessionDescriptor) => void): void;
  function on(type: 'topSessionChanged', callback: (session: AVSessionDescriptor) => void): void;
  function on(type: 'sessionServiceDied', callback: () => void): void;

  function off(type: 'sessionServiceDied'): void;
  function off(type: 'sessionCreated' | 'sessionDestroyed' | 'topSessionChanged'): void;

  function sendSystemAVKeyEvent(event: KeyEvent, callback: AsyncCallback<void>): void;
  function sendSystemAVKeyEvent(event: KeyEvent): Promise<void>;

  function sendSystemControlCommand(command: AVControlCommand, callback: AsyncCallback<void>): void;
  function sendSystemControlCommand(command: AVControlCommand): Promise<void>;

  type AVSessionType = 'audio' | 'video';

  interface AVSession {
    readonly sessionId: number;

    setAVMetadata(data: AVMetadata, callback: AsyncCallback<void>): void;
    setAVMetadata(data: AVMetadata): Promise<void>;

    setAVPlaybackState(state: AVPlaybackState, callback: AsyncCallback<void>): void;
    setAVPlaybackState(state: AVPlaybackState): Promise<void>;

    setLaunchAbility(ability: WantAgent, callback: AsyncCallback<void>): void;
    setLaunchAbility(ability: WantAgent): Promise<void>;

    setAudioStreamId(streamIds: Array<number>, callback: AsyncCallback<void>): void;
    setAudioStreamId(streamIds: Array<number>): Promise<void>;

    getController(callback: AsyncCallback<AVSessionController>): void;
    getController(): Promise<AVSessionController>;

    getOutputDevice(callback: AsyncCallback<OutputDeviceInfo>): void;
    getOutputDevice(): Promise<OutputDeviceInfo>;

    on(type: 'play'|'pause'|'stop'|'playNext'|'playPrevious'|'fastForward'|'rewind', callback: () => void):void;

    on(type: 'seek', callback: (time: number) => void): void;

    on(type: 'setSpeed', callback: (speed: number) => void): void;

    on(type: 'setLoopMode', callback: (mode: LoopMode) => void): void;

    on(type: 'toggleFavorite', callback: (assetId: string) => void): void;

    on(type: 'handleKeyEvent', callback: (event: KeyEvent) => void): void;

    on(type: 'outputDeviceChanged', callback: (device: OutputDeviceInfo) => void): void;

    off(type: 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' | 'fastForward' | 'rewind' | 'seek'
            | 'setSpeed' | 'setLoopMode' | 'toggleFavorite' | 'handleKeyEvent' | 'outputDeviceChanged'): void;

    activate(callback: AsyncCallback<void>): void;
    activate(): Promise<void>;

    deactivate(callback: AsyncCallback<void>): void;
    deactivate(): Promise<void>;

    destroy(callback: AsyncCallback<void>): void;
    destroy(): Promise<void>;
  }

  interface AVMetadata {
    assetId: string;
    title?: string;
    artist?: string;
    author?: string;
    album?: string;
    writer?: string;
    composer?: string;
    duration?: number;
    mediaImage?: image.PixelMap | string;
    publishDate?: Date;
    subtitle?: string;
    description?: string;
    lyric?: string;
    previousAssetId?: string;
    nextAssetId?: string;
  }

  interface AVPlaybackState {
    state?: PlaybackState;
    speed?: number;
    position?: PlaybackPosition;
    bufferedTime?: number;
    loopMode?: LoopMode;
    isFavorite?: boolean;
  }

  interface PlaybackPosition {
    elapsedTime: number;
    updateTime: number;
  }

  interface OutputDeviceInfo {
    isRemote: boolean;
    deviceId: Array<string>;
    deviceName: Array<string>;
  }

  enum LoopMode {
    LOOP_MODE_SEQUENCE = 0,
    LOOP_MODE_SINGLE,
    LOOP_MODE_LIST,
    LOOP_MODE_SHUFFLE,
  }

  enum PlaybackState {
    PLAYBACK_STATE_INITIAL = 0,
    PLAYBACK_STATE_PREPARE,
    PLAYBACK_STATE_PLAY,
    PLAYBACK_STATE_PAUSE,
    PLAYBACK_STATE_FAST_FORWARD,
    PLAYBACK_STATE_REWIND,
    PLAYBACK_STATE_STOP,
  }

  interface AVSessionDescriptor {
    sessionId: number;
    type: AVSessionType;
    sessionTag: string;
    elementName: ElementName;
    isActive: boolean;
    isTopSession: boolean;
    outputDevice: OutputDeviceInfo;
  }

  interface AVSessionController {
    readonly sessionId: number;
    getAVPlaybackState(callback: AsyncCallback<AVPlaybackState>): void;
    getAVPlaybackState(): Promise<AVPlaybackState>;

    getAVMetadata(callback: AsyncCallback<AVMetadata>): void;
    getAVMetadata(): Promise<AVMetadata>;

    getOutputDevice(callback: AsyncCallback<OutputDeviceInfo>): void;
    getOutputDevice(): Promise<OutputDeviceInfo>;

    sendAVKeyEvent(event: KeyEvent, callback: AsyncCallback<void>): void;
    sendAVKeyEvent(event: KeyEvent): Promise<void>;

    getLaunchAbility(callback: AsyncCallback<WantAgent>): void;
    getLaunchAbility(): Promise<WantAgent>;

    getRealPlaybackPositionSync(): number;

    isActive(callback: AsyncCallback<boolean>): void;
    isActive(): Promise<boolean>;

    destroy(callback: AsyncCallback<void>): void;
    destroy(): Promise<void>;

    getValidCommands(callback: AsyncCallback<Set<AVControlCommandType>>): void;
    getValidCommands(): Promise<Set<AVControlCommandType>>;

    sendControlCommand(command: AVControlCommand, callback: AsyncCallback<void>): void;
    sendControlCommand(command: AVControlCommand): Promise<void>;

    on(type: 'metadataChanged', filter: Set<keyof AVMetadata> | 'all', callback: (data: AVMetadata) => void);
    on(type: 'playbackStateChanged', filter: Set<keyof AVPlaybackState> | 'all', callback: (state: AVPlaybackState) => void);
    on(type: 'sessionDestroyed', callback: () => void);
    on(type: 'activeStateChanged', callback: (isActive: boolean) => void);
    on(type: 'validCommandChanged', callback: (commands: Set<AVControlCommandType>) => void);
    on(type: 'outputDeviceChanged', callback: (device: OutputDeviceInfo) => void): void;

    off(type: 'metadataChanged'|'playbackStateChanged'|'sessionDestroyed'|'activeStateChanged'|'validCommandChanged'|'outputDeviceChanged'): void;
  }

  type AVControlCommandType = 'play'|'pause'|'stop'|'playNext'|'playPrevious'|'fastForward'|'rewind'|'seek'|'setSpeed'|'setLoopMode'|'toggleFavorite';

  interface AVControlCommand {
    command: AVControlCommandType;
    parameter?: LoopMode | string | number;
  }

  enum AVSessionErrorCode {
    ERR_CODE_UNKNOWN = 6600100,
    ERR_CODE_SERVICE_EXCEPTION,
    ERR_CODE_SESSION_NOT_EXIST,
    ERR_CODE_CONTROLLER_NOT_EXIST,
    ERR_CODE_REMOTE_CONNECTION_ERR,
    ERR_CODE_COMMAND_INVALID,
  }
}

export default avsession;
