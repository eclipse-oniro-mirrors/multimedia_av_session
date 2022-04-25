/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

import {ErrorCallback, AsyncCallback, Callback} from './basic';
import Context from './@ohos.ability';
import image from './@ohos.multimedia.image';


declare namespace session {
    function getAVSessionManager(context: Context): AVSessionManager;

    interface AVSessionManager {
        createSession(context: Context, tag: string, callback: AsyncCallback<Session>): void;
        createSession(context: Context, tag: string): Promise<Session>;

        listAllSessionDescriptors(callback: AsyncCallback<Array<SessionDescriptor>>): void;
        listAllSessionDescriptors(): Promise<Array<SessionDescriptor>>;

        findSessionDescriptiorByTag(tag: string, callback: AsyncCallback<SessionDescriptor>): void;
        findSessionDescriptiorByTag(tag: string): Promise<SessionDescriptor>;

        createSessionController(sessionId: number, context: Context, callback: AsyncCallback<SessionController>): void;
        createSessionController(sessionId: number, context: Context): Promise<SessionController>;
    }

    interface SessionDescriptor {
        readonly sessionId: number;
        readonly tag: string;
        readonly bundleName: string;
        readonly active: boolean;
    }

    interface Session {
        setActiveState(isActive: boolean, callback: AsyncCallback<void>): void;
        setActiveState(isActive: boolean): Promise<void>;

        setAVMetadata(meta: AVMetadata, callback: AsyncCallback<void>): void;
        setAVMetadata(meta: AVMetadata): Promise<void>;

        setAVPlaybackState(state: AVPlaybackState, callback: AsyncCallback<void>): void;
        setAVPlaybackState(state: AVPlaybackState): Promise<void>;

        on(type: 'permissionCheck', callback: (pid: number, uid: number, bundleName: string) => {}): void;
        on(type: 'play', callback: () => {}): void;
        on(type: 'pause', callback: () => {}): void;
        on(type: 'stop', callback: () => {}): void;
        on(type: 'playNext', callback: () => {}): void;
        on(type: 'playPrevious', callback: () => {}): void;
        on(type: 'seek', callback: Callback<number>): void;
        on(type: 'setSpeed', callback: Callback<number>): void;

        release(callback: AsyncCallback<void>): void;
        release(): Promise<void>;
    }

    interface SessionController {
        getAVPlaybackState(callback: AsyncCallback<AVPlaybackState>): void;
        getAVPlaybackState(): Promise<AVPlaybackState>;

        getAVMetaData(callback: AsyncCallback<AVMetadata>): void;
        getAVMetaData(): Promise<AVMetadata>;

        sendCommand(cmd: SessionCommand, callback: AsyncCallback<void>): void;
        sendCommand(cmd: SessionCommand): Promise<void>;

        on(type: 'sessionRelease', callback: () => {}): void;
        on(type: 'playbackStateUpdate', callback: (state: AVPlaybackState) => {}): void;
        on(type: 'metadataUpdate', callback: (meta: AVMetadata) => {}): void;

        release(callback: AsyncCallback<void>): void;
        release(): Promise<void>;
    }

    interface SessionCommand {
        readonly cmd: AVCommand;
        readonly para: number;
    }

    enum AVCommand {
        AV_CMD_STOP = 0,
        AV_CMD_PLAY,
        AV_CMD_PAUSE,
        AV_CMD_PLAY_NEXT,
        AV_CMD_PLAY_PREVIOUS,
        AV_CMD_SEEK,
        AV_CMD_SET_SPEED
    }

    interface AVPlaybackState {
        readonly state: PlaybackState;
        readonly currentTime: number;
    }

    enum PlaybackState {
        PLAYBACK_STATE_INVALID = -1,
        PLAYBACK_STATE_NEW,
        PLAYBACK_STATE_PREPARED,
        PLAYBACK_STATE_PLAYING,
        PLAYBACK_STATE_PAUSED,
        PLAYBACK_STATE_STOPPED,
        PLAYBACK_STATE_RELEASED
    }

    enum AVMetadataKey {
        METADATA_KEY_TITLE = "title",
        METADATA_KEY_SUBTITLE = "subtitle",
        METADATA_KEY_ARTIST = "artist",
        METADATA_KEY_DURATION = "duration",
        METADATA_KEY_DATE = "date",
        METADATA_KEY_DISPLAY_ICON = "display_icon"
    }

    interface AVMetadata {
        setNumberValue(key: AVMetadataKey, value: number, callback: AsyncCallback<void>): void;
        setNumberValue(key: AVMetadataKey, value: number): Promise<void>;

        setStringValue(key: AVMetadataKey, value: string, callback: AsyncCallback<void>): void;
        setStringValue(key: AVMetadataKey, value: string): Promise<void>;

        setPixelMapValue(key: AVMetadataKey, value: image.PixelMap, callback: AsyncCallback<void>): void;
        setPixelMapValue(key: AVMetadataKey, value: image.PixelMap): Promise<void>;
    }
}

export default session;