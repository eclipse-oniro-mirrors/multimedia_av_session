
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { AsyncCallback, Callback, BusinessError } from '@ohos.base';
import type Context from 'application.BaseContext';

type RejectString = (e: BusinessError<string>) => void;

function businessError<T = void>(c: number, d?: string): BusinessError<T> {
  let err: BusinessError<T> = new BusinessError<T>();
  err.code = c;
  err.message = d ? d : "";
  return err;
}

function isNullish(d: NullishType): boolean {
  return (d === null || d === undefined) ? true : false;
}

class AvSessionAniError extends BusinessError {
  constructor(code: number, message: string) {
    super();
    this.code = code;
    this.message = message;
  }
}

export namespace avSession {
  loadLibrary("avsession_ani");

  export function createAVSession(context: Context, tag: string, type: AVSessionType,
    callback: AsyncCallback<AVSession | undefined>): void {
    let queueSize: int = 2;
    let blockQueue: containers.BlockingQueue<AVSession | AvSessionAniError> =
      new containers.ArrayBlockingQueue<AVSession | AvSessionAniError>(queueSize);
    let cb = (): AVSession | AvSessionAniError => {
      let result: AVSession | AvSessionAniError;
      try {
        result = avSession.createAVSessionInner(context, tag, type);
      } catch(e) {
        result = e as AvSessionAniError;
      }
      blockQueue.push(result);
      return result;
    };
    taskpool.execute(cb).then((ret: NullishType): void => {
      if (ret instanceof AvSessionAniError) {
        let err = ret as AvSessionAniError;
        callback(businessError(err.code, err.message), undefined);
      } else {
        if (isNullish(ret)) {
          callback(businessError(-1), undefined);
        } else {
          callback(businessError(0), ret as AVSession);
        }
      }
    });
    blockQueue.pop();
  }

  export function createAVSession(context: Context, tag: string, type: AVSessionType): Promise<AVSession> {
    return new Promise<AVSession>((resolve: (v: AVSession) => void, reject: RejectString) => {
      let queueSize: int = 2;
      let blockQueue: containers.BlockingQueue<AVSession | AvSessionAniError> =
        new containers.ArrayBlockingQueue<AVSession | AvSessionAniError>(queueSize);
      let cb = (): AVSession | AvSessionAniError => {
        let result: AVSession | AvSessionAniError;
        try {
          result = avSession.createAVSessionInner(context, tag, type);
        } catch(e) {
          result = e as AvSessionAniError;
        }
        blockQueue.push(result);
        return result;
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof AvSessionAniError) {
          let err = ret as AvSessionAniError;
          reject(businessError<string>(err.code, err.message));
        } else {
          if (isNullish(ret)) {
            reject(businessError<string>(-1, "Operation failed"));
          } else {
            resolve(ret as AVSession);
          }
        }
      });
      blockQueue.pop();
    });
  }

  export native function createAVSessionInner(context: Context, tag: string, type: AVSessionType): AVSession;

  export type AVSessionType = 'audio' | 'video' | 'voice_call' | 'video_call';

  export interface AVSession {
    readonly sessionId: string;
    readonly sessionType: AVSessionType;
    getAllCastDisplays(): Promise<Array<CastDisplayInfo>>;
    on(type: 'castDisplayChange', callback: Callback<CastDisplayInfo>): void;
    activate(callback: AsyncCallback<void>): void;
    activate(): Promise<void>;
    destroy(callback: AsyncCallback<void>): void;
    destroy(): Promise<void>;
  }

  class AVSessionHandle implements AVSession {
    readonly sessionId: string = "";
    readonly sessionType: AVSessionType;
    private nativeAVSession: long = 0;

    constructor(nativePtr: long) {
      if (this.nativeAVSession == 0) {
        this.nativeAVSession = nativePtr;
      }
    }

    getAllCastDisplays(): Promise<Array<CastDisplayInfo>> {
      return new Promise<Array<CastDisplayInfo>>((resolve: (v: Array<CastDisplayInfo>) => void,
        reject: RejectString) => {
        let queueSize: int = 2;
        let blockQueue: containers.BlockingQueue<Array<CastDisplayInfo> | AvSessionAniError> =
          new containers.ArrayBlockingQueue<Array<CastDisplayInfo> | AvSessionAniError>(queueSize);
        let cb = (): Array<CastDisplayInfo> | AvSessionAniError => {
          let result: Array<CastDisplayInfo> | AvSessionAniError;
          try {
            result = this.getAllCastDisplaysInner();
          } catch(e) {
            result = e as AvSessionAniError;
          }
          blockQueue.push(result);
          return result;
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof AvSessionAniError) {
            let err = ret as AvSessionAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as Array<CastDisplayInfo>);
            }
          }
        });
        blockQueue.pop();
      });
    }

    activate(callback: AsyncCallback<void>): void {
      let cb = (): AvSessionAniError | undefined => {
        try {
          this.activateInner();
          return undefined;
        } catch(e) {
          return e as AvSessionAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as AvSessionAniError;
          callback(businessError(err.code, err.message), undefined);
        }
      });
    }

    activate(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): AvSessionAniError | undefined => {
          try {
            this.activateInner();
            return undefined;
          } catch(e) {
            return e as AvSessionAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as AvSessionAniError;
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    destroy(callback: AsyncCallback<void>): void {
      let cb = (): AvSessionAniError | undefined => {
        try {
          this.destroyInner();
          return undefined;
        } catch(e) {
          return e as AvSessionAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as AvSessionAniError;
          callback(businessError(err.code, err.message), undefined);
        }
      });
    }

    destroy(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): AvSessionAniError | undefined => {
          try {
            this.destroyInner();
            return undefined;
          } catch(e) {
            return e as AvSessionAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as AvSessionAniError;
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    native getAllCastDisplaysInner(): Array<CastDisplayInfo>;
    native on(type: 'castDisplayChange', callback: Callback<CastDisplayInfo>): void;
    native activateInner(): void;
    native destroyInner(): void;
  }

  export type AVCastControlCommandType = 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' | 'fastForward' |
  'rewind' | 'seek' | 'setVolume' | 'setSpeed' | 'setLoopMode' | 'toggleFavorite' | 'toggleMute';

  export type KeyRequestCallback = (assetId: string, requestData: Uint8Array) => void;

  export enum CastDisplayState {
    STATE_OFF = 1,
    STATE_ON = 2,
  }

  export interface CastDisplayInfo {
    id: number;
    name: string;
    state: CastDisplayState;
    width: number;
    height: number;
  }

  class CastDisplayInfoHandle implements CastDisplayInfo {
    constructor() {}
    id: number = 0;
    name: string = "";
    state: CastDisplayState;
    width: number = 0;
    height: number = 0;
  }

  export enum CallState {
    CALL_STATE_IDLE = 0,
    CALL_STATE_INCOMING = 1,
    CALL_STATE_ACTIVE = 2,
    CALL_STATE_DIALING = 3,
    CALL_STATE_WAITING = 4,
    CALL_STATE_HOLDING = 5,
    CALL_STATE_DISCONNECTING = 6,
  }

  export enum AVCastCategory {
    CATEGORY_LOCAL = 0,
    CATEGORY_REMOTE = 1,
  }

  export enum DeviceType {
    DEVICE_TYPE_LOCAL = 0,
    DEVICE_TYPE_TV = 2,
    DEVICE_TYPE_SMART_SPEAKER = 3,
    DEVICE_TYPE_BLUETOOTH = 10,
  }

  export enum LoopMode {
    LOOP_MODE_SEQUENCE = 0,
    LOOP_MODE_SINGLE = 1,
    LOOP_MODE_LIST = 2,
    LOOP_MODE_SHUFFLE = 3,
    LOOP_MODE_CUSTOM = 4,
  }

  export enum SkipIntervals {
    SECONDS_10 = 10,
    SECONDS_15 = 15,
    SECONDS_30 = 30,
  }

  export enum PlaybackState {
    PLAYBACK_STATE_INITIAL = 0,
    PLAYBACK_STATE_PREPARE = 1,
    PLAYBACK_STATE_PLAY = 2,
    PLAYBACK_STATE_PAUSE = 3,
    PLAYBACK_STATE_FAST_FORWARD = 4,
    PLAYBACK_STATE_REWIND = 5,
    PLAYBACK_STATE_STOP = 6,
    PLAYBACK_STATE_COMPLETED = 7,
    PLAYBACK_STATE_RELEASED = 8,
    PLAYBACK_STATE_ERROR = 9,
    PLAYBACK_STATE_IDLE = 10,
    PLAYBACK_STATE_BUFFERING = 11,
  }

  export type AVControlCommandType = 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' |
  'fastForward' | 'rewind' | 'seek' | 'setSpeed' | 'setLoopMode' | 'toggleFavorite' | 'playFromAssetId' |
  'answer' | 'hangUp' | 'toggleCallMute';
}
