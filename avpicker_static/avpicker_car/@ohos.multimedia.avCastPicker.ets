/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import {
  Component, Color, UIExtensionComponent, UIExtensionProxy, ReceiveCallback, BuilderParam, Column, Builder, SymbolGlyph,
  $r, Image, Text, TextOverflow, WordBreak, Direction, Row, ForEach, Flex, FlexOptions, FlexDirection, FlexAlign,
  ItemAlign,VerticalAlign, TouchType, Divider, Button, ButtonOptions, Placement, Stack, Alignment, LoadingProgress,
  HorizontalAlign, TextAttribute, FontWeight, Margin, Resource, SymbolRenderingStrategy, Padding, ButtonType,
  ClickEvent, TouchEvent, CustomBuilder, TerminationInfo, MenuOptions
} from '@ohos.arkui.component';
import { State, Watch, PropRef } from '@ohos.arkui.stateManagement'
import { Callback, ErrorCallback, BusinessError, RecordData } from '@ohos.base';
import { AVCastPickerState, AVCastPickerStyle, AVCastPickerColorMode } from '@ohos.multimedia.avCastPickerParam';
import Want from '@ohos.app.ability.Want'

const TAG = 'avcastpicker_component ';

@Component
export struct AVCastPicker {
  /**
   * Assigns the color of picker component at normal state.
   */
  @PropRef normalColor: Color | int | string = '';

  /**
   * Assigns the color of picker component at active state.
   */
  @PropRef activeColor: Color | int | string = '';

  /**
   * Definition of color mode of picker.
   */
  @PropRef colorMode: AVCastPickerColorMode = AVCastPickerColorMode.AUTO;

  /**
   * Session type transferred by the application.
   */
  @PropRef sessionType?: string = 'audio';

  /**
   * Picker state change callback.
   */
  private onStateChange?: (state: AVCastPickerState) => void;

  /**
   * UIExtensionProxy.
   */
  private extensionProxy: UIExtensionProxy | null = null;

  /**
   * Custom builder from application.
   */
  @BuilderParam customPicker?: () => void = () => {};

  /**
   * Accessibility Strings
   */
  @State accessibilityAudioControlStr: string = '音视频投播';

  @State restartUECMessage: number = 1;
  private needToRestart: boolean = false;
  private pickerCountOnCreation: number = 0;

  private static currentPickerCount: number = 0;

  aboutToAppear(): void {
    AVCastPicker.currentPickerCount += 1;
    this.pickerCountOnCreation = AVCastPicker.currentPickerCount;
  }

  aboutToDisappear(): void {
    AVCastPicker.currentPickerCount -= 1;
  }

  build(): void {
    Column() {
      if (this.customPicker === undefined) {
        this.buildDefaultPicker(false);
      } else {
        this.buildCustomPicker();
      }
    }.size({width: '100%', height: '100%'})
  }

  @Builder
  private buildDefaultPicker(isCustomPicker: boolean) {
    Button({ type: ButtonType.Normal } as ButtonOptions) {
      Column() {
        UIExtensionComponent(
          {
            abilityName: 'MultiScreenIconButton',
            bundleName: 'com.hmos.hwcomic',
            parameters: {
              'normalColor': this.normalColor,
              'activeColor': this.activeColor,
              'pickerColorMode': this.colorMode,
              'ability.want.params.uiExtensionType': 'sysPicker/mediaControl',
              'isCustomPicker': isCustomPicker,
              'message': this.restartUECMessage,
            } as Record<string, RecordData>
          } as Want)
          .onRemoteReady((proxy: UIExtensionProxy) => {
            console.info(TAG, 'onRemoteReady');
            this.extensionProxy = proxy;
          })
          .onReceive((data: Record<string, RecordData>) => {
            if (JSON.stringify(data['state']) !== undefined) {
              console.info(TAG, `picker state change : ${JSON.stringify(data['state'])}`);
              if (this.onStateChange != null) {
                if (parseInt(JSON.stringify(data['state'])) === AVCastPickerState.STATE_APPEARING) {
                  this.onStateChange?.(AVCastPickerState.STATE_APPEARING);
                } else {
                  this.onStateChange?.(AVCastPickerState.STATE_DISAPPEARING);
                }
              }
            }

            if (JSON.stringify(data['accessAudioControl']) !== undefined) {
              console.info(TAG, `accessAudioControl : ${JSON.stringify(data['accessAudioControl'])}`);
              this.accessibilityAudioControlStr = data['accessAudioControl'] as string;
            }
          })
          .size({ width: '100%', height: '100%' })
          .onTerminated((releaseCode: TerminationInfo) => {
            console.error(TAG, `onRelease code ${releaseCode.code}`);
            if (releaseCode.code === 1) {
              this.needToRestart = true;
            }
          } as Callback<TerminationInfo>)
          .onError(() => {
            console.error(TAG, 'onError ready to restart');
            this.needToRestart = true;
          } as ErrorCallback<BusinessError>)
      }
      .accessibilityLevel('no-hide-descendants')
      .size({ width: '100%', height: '100%' })
    }
    .backgroundColor('#00000000')
    .stateEffect(false)
    .size({ width: '100%', height: '100%' })
    .accessibilityLevel('yes')
    .accessibilityText(this.accessibilityAudioControlStr)
    .onClick((e: ClickEvent) => {
      if (this.needToRestart) {
        this.needToRestart = false;
        this.restartUECMessage += 1;
        return;
      }
    })
  }

  @Builder
  private buildCustomPicker() {
    Stack({ alignContent: Alignment.Center}) {
      Column() {
        this.customPicker?.();
      }
      .alignItems(HorizontalAlign.Center)
      .justifyContent(FlexAlign.Center)
      .size({ width: '100%', height: '100%' })
      .zIndex(0)

      Column() {
        this.buildDefaultPicker(true);
      }
      .alignItems(HorizontalAlign.Center)
      .justifyContent(FlexAlign.Center)
      .size({ width: '100%', height: '100%' })
      .zIndex(1)
    }
    .size({ width: '100%', height: '100%' })
  }
}