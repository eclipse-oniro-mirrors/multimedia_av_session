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
const castPlusAudioType: number = 8;

enum DeviceSource {
  /**
   * local device
   */
  LOCAL,

  /**
   * cast device
   */
  CAST
}

enum ConfigurationColorMode {
  /**
   * the color mode is not set.
   */
  COLOR_MODE_NOT_SET = -1,

  /**
   * Dark mode.
   */
  COLOR_MODE_DARK = 0,

  /**
   * Light mode.
   */
  COLOR_MODE_LIGHT = 1
}

interface HighQualityParams {
  iconLeft: string,
  iconRight: string,
}

/**
 * menuItem device info
 */
export interface AVCastPickerDeviceInfo {
  deviceId: number | String,
  deviceType: number,
  deviceName: string,
  deviceIconName: string,
  isConnected: boolean,
  selectedIconName: string,
  deviceSource: DeviceSource,
  networkId: string,
  supportedProtocols?: number,
  highQualityParams?: HighQualityParams,
}

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
   * The device that is displayed in the menu.
   */
  @State deviceList: Array<AVCastPickerDeviceInfo> = [] as Array<AVCastPickerDeviceInfo>;

  /**
   * The scale of font size.
   */
  @State fontSizeScale: number = 1;

  /**
   * Session type transferred by the application.
   */
  @PropRef sessionType?: string = 'audio';

  /**
   * Display form of application transfer.
   */
  @PropRef pickerStyle: AVCastPickerStyle = AVCastPickerStyle.STYLE_PANEL;

  /**
   * Display form mediaController.
   */
  @State pickerStyleFromMediaController: AVCastPickerStyle = AVCastPickerStyle.STYLE_PANEL;

  /**
   * Whether to display the menu.
   */
  @State@Watch('MenuStateChange') isMenuShow: boolean = false;

  /**
   * Touch item index.
   */
  @State touchMenuItemIndex: number = -1;

  /**
   * Picker state change callback.
   */
  private onStateChange?: (state: AVCastPickerState) => void;

  /**
   * UIExtensionProxy.
   */
  private extensionProxy: UIExtensionProxy | null = null;

  private pickerClickTime: number = -1;

  /**
   * Custom builder from application.
   */
  @BuilderParam customPicker?: () => void = () => {};

  /**
   * Configuration color mode.
   */
  @State configurationColorMode: number = ConfigurationColorMode.COLOR_MODE_NOT_SET;

  @State deviceInfoType: string = '';

  /**
   * Max Font and graphic magnification.
   */
  @State maxFontSizeScale: number = 1;

  /**
   * Accessibility Strings
   */
  @State accessibilityConnectedStr: string = '已连接';
  @State accessibilityAudioControlStr: string = '音视频投播';

  @State isPc: boolean = false;
  @State isRTL: boolean = false;
  @State restartUECMessage: number = 1;
  private needToRestart: boolean = false;
  @State isShowLoadingProgress: boolean = false;
  private pickerCountOnCreation: number = 0;

  private static currentPickerCount: number = 0;

  aboutToAppear(): void {
    AVCastPicker.currentPickerCount += 1;
    this.pickerCountOnCreation = AVCastPicker.currentPickerCount;
  }

  aboutToDisappear(): void {
    AVCastPicker.currentPickerCount -= 1;
  }

  MenuStateChange(MenuStateChange: string){
    if (this.extensionProxy != null) {
      this.extensionProxy!.send({ 'isMenuShow': this.isMenuShow });
    }
  }

  private showHighQuality(item: AVCastPickerDeviceInfo): boolean {
    if (item.supportedProtocols === undefined) {
      return false;
    }
    const protocols = item.supportedProtocols as number;
    return (protocols & castPlusAudioType) !== 0;
  }

  build() {
    Column() {
      if (this.customPicker === undefined) {
        this.buildDefaultPicker(false);
      } else {
        this.buildCustomPicker();
      }
    }.size({width: '100%', height: '100%'})
  }

  @Builder
  iconBuilder(item: AVCastPickerDeviceInfo, isSelected: boolean): void {
    if (this.deviceInfoType === 'true') {
      SymbolGlyph(!isSelected ? $r(item.deviceIconName) : $r(item.selectedIconName))
        .fontSize('24vp')
        .fontColor((isSelected && this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
          [$r('sys.color.comp_background_emphasize')] as Array<Color|int|String|Resource> :
          [$r('sys.color.icon_primary')] as Array<Color|int|String|Resource>)
        .renderingStrategy(SymbolRenderingStrategy.MULTIPLE_OPACITY)
    } else {
      Image(!isSelected ? $r(item.deviceIconName) : $r(item.selectedIconName))
        .width(24)
        .height(24)
        .fillColor((isSelected && this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
        $r('sys.color.comp_background_emphasize') : $r('sys.color.icon_primary'))
    }
  }


  @Builder
  textBuilder(item: AVCastPickerDeviceInfo) {
    Text(item.deviceName)
      .fontSize($r('sys.float.ohos_id_text_size_body2'))
      .fontColor(item.isConnected ?
        (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ?
        $r('sys.color.font_emphasize') : $r('sys.color.font_primary')) :
        (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ?
        $r('sys.color.font_primary') : $r('sys.color.font_secondary')))
      .width(this.isPc ? 254 : 144)
      .textOverflow({ overflow: TextOverflow.Ellipsis })
      .maxLines(2)
      .wordBreak(WordBreak.BREAK_ALL)
      .maxFontScale(this.maxFontSizeScale)
      .direction(this.isRTL ? Direction.Rtl : Direction.Ltr)
  }

  @Builder
  highQualityIconBuilder(params: HighQualityParams) {
    Row() {
      Text(params.iconLeft)
        .highQualityStyles(this.maxFontSizeScale)
      Text(params.iconRight)
        .highQualityStyles(this.maxFontSizeScale)
        .margin({ left: 2 * (Math.min(this.maxFontSizeScale, this.fontSizeScale)) } as Margin)
    }
    .direction(Direction.Ltr)
  }

  @Builder
  deviceMenu() {
    Column() {
      ForEach(this.deviceList, (item: AVCastPickerDeviceInfo, index: int) => {
        Flex({
          direction: FlexDirection.Column,
          justifyContent: FlexAlign.SpaceBetween,
          alignItems: ItemAlign.End
        } as FlexOptions) {
          Flex({
            direction: FlexDirection.Row,
            justifyContent: FlexAlign.SpaceBetween,
            alignItems: ItemAlign.Center
          } as FlexOptions) {
            Row() {
              this.iconBuilder(item, false)

              Flex({direction: FlexDirection.Row, justifyContent: FlexAlign.Center}) {
                this.textBuilder(item)
                if (this.showHighQuality(item)) {
                  Flex() {
                    this.highQualityIconBuilder(item.highQualityParams as HighQualityParams)
                  }
                  .borderRadius(3.0)
                  .border({
                    width: 0.5 * (Math.min(this.maxFontSizeScale, this.fontSizeScale)),color: $r('sys.color.font_secondary')})
                  .padding({top: 1.5, right: 4, bottom: 1.5, left: 4} as Padding)
                  .margin({ top: 2 } as Margin)
                  .width('auto')
                }
              }
              .padding({
                left: 8,
                top: this.isPc ? 11 : (this.showHighQuality(item as AVCastPickerDeviceInfo) ? 7 : 17),
                right: 8,
                bottom: this.isPc ? 11 : (this.showHighQuality(item as AVCastPickerDeviceInfo) ? 7 : 17),
              } as Padding)
            }
            .alignItems(VerticalAlign.Center)

            if (item.isConnected && item.selectedIconName !== null && item.selectedIconName !== undefined) {
              Row() {
                this.iconBuilder(item, true)
              }
              .alignItems(VerticalAlign.Center)
              .accessibilityLevel('yes')
              .accessibilityText(this.accessibilityConnectedStr)
            }
          }
          .constraintSize({ minHeight: this.isPc ? 40 : 48 })
          .padding({ left: 12, right: 12 } as Padding)
          .onTouch((event: TouchEvent) => {
            if (event.type === TouchType.Down) {
              this.touchMenuItemIndex = index;
            } else if (event.type === TouchType.Up) {
              this.touchMenuItemIndex = -1;
            }
          })
          .backgroundColor(this.touchMenuItemIndex === index ?
          $r('sys.color.interactive_click') : '#00FFFFFF')
          .borderRadius(this.touchMenuItemIndex === index ?
            (this.isPc ? $r('sys.float.corner_radius_level2') : $r('sys.float.corner_radius_level8')) : 0.0)

          if (!this.isPc && (index != this.deviceList!.length - 1)) {
            Divider()
              .height(1)
              .color($r('sys.color.comp_divider'))
              .padding({ right: (this.isRTL ? 44 : 12), left: (this.isRTL ? 12 : 44) } as Padding)
          } else if (this.isPc && (index != this.deviceList!.length - 1)) {
            Row()
              .width('100%')
              .height(2)
          }
        }
        .width('100%')
        .onClick((e: ClickEvent) => {
          if (this.extensionProxy != null && !item.isConnected) {
            this.extensionProxy!.send({ 'selectedDeviceInfo': item })
          }
        })
      })
    }
    .width(this.isPc ? 326 : 216)
    .borderRadius(this.isPc ? 8.0 : 20.0)
  }

  @Builder
  private buildDefaultPicker(isCustomPicker: boolean) {
    Button({ type: ButtonType.Normal } as ButtonOptions) {
      Column() {
        UIExtensionComponent(
          {
            abilityName: 'UIExtAbility',
            bundleName: 'com.hmos.mediacontroller',
            parameters: {
              'normalColor': this.normalColor,
              'activeColor': this.activeColor,
              'pickerColorMode': this.colorMode,
              'avCastPickerStyle': this.pickerStyle,
              'ability.want.params.uiExtensionType': 'sysPicker/mediaControl',
              'isCustomPicker': isCustomPicker,
              'message': this.restartUECMessage,
              'currentPickerCount': this.pickerCountOnCreation,
            } as Record<string, RecordData>
          } as Want)
          .onRemoteReady((proxy: UIExtensionProxy) => {
            console.info(TAG, 'onRemoteReady');
            this.extensionProxy = proxy;
          })
          .onReceive((data) => {
            if (JSON.stringify(data['deviceInfoType']) !== undefined) {
              console.info(TAG, `deviceInfoType : ${JSON.stringify(data['deviceInfoType'])}`);
              this.deviceInfoType = data['deviceInfoType'] as string;
            }

            if (JSON.stringify(data['pickerStyle']) !== undefined) {
              console.info(TAG, `picker style : ${JSON.stringify(data['pickerStyle'])}`);
              this.pickerStyleFromMediaController = data['pickerStyle'] as AVCastPickerStyle;
            }

            if (JSON.stringify(data['deviceList']) !== undefined) {
              console.info(TAG, `picker device list : ${JSON.stringify(data['deviceList'])}`);
              this.deviceList =
                JSON.parse(JSON.stringify(data!['deviceList'] as string), Type.from<string>())! as Array<AVCastPickerDeviceInfo>;
              let hasOnlySpeakerAndEarpiece: boolean = this.deviceList!.length === 2 &&
                !this.hasExtDevice(this.deviceList!);
              let hasNoDevices: boolean = this.deviceList === null || this.deviceList!.length === 0;
              let isCalling: boolean = this.sessionType === 'voice_call' || this.sessionType === 'video_call';
              let isExtMenuScene = isCalling && (hasNoDevices || hasOnlySpeakerAndEarpiece);
              let isPanelForMedia: boolean = !isCalling &&
                (this.pickerStyle === AVCastPickerStyle.STYLE_PANEL &&
                  this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_PANEL);
              if (isExtMenuScene || isPanelForMedia) {
                this.isMenuShow = false;
                this.touchMenuItemIndex = -1;
              }
            }

            if (JSON.stringify(data['fontSizeScale']) !== undefined) {
              console.info(TAG, `font size scale : ${JSON.stringify(data['fontSizeScale'])}`);
              this.fontSizeScale = data['fontSizeScale'] as number;
            }

            if (JSON.stringify(data['state']) !== undefined) {
              console.info(TAG, `picker state change : ${JSON.stringify(data['state'])}`);
              let isCalling: boolean = (this.sessionType === 'voice_call' || this.sessionType === 'video_call');
              let isPanelForMedia: boolean = !isCalling &&
                (this.pickerStyle === AVCastPickerStyle.STYLE_PANEL &&
                  this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_PANEL);
              if (this.onStateChange != null && isPanelForMedia) {
                if (parseInt(JSON.stringify(data['state'])) === AVCastPickerState.STATE_APPEARING) {
                  this.onStateChange?.(AVCastPickerState.STATE_APPEARING);
                } else {
                  this.onStateChange?.(AVCastPickerState.STATE_DISAPPEARING);
                }
              }
            }

            if (JSON.stringify(data['sessionType']) !== undefined) {
              console.info(TAG, `session type : ${JSON.stringify(data['sessionType'])}`);
              this.sessionType = data['sessionType'] as string;
            }

            if (JSON.stringify(data['isShowMenu']) !== undefined) {
              console.info(TAG, `isShowMenu : ${JSON.stringify(data['isShowMenu'])}`);
              this.isMenuShow = data['isShowMenu'] as boolean;
              if (!this.isMenuShow) {
                this.touchMenuItemIndex = -1;
              }
            }

            if (JSON.stringify(data['configurationColorMode']) !== undefined) {
              console.info(TAG, `configurationColorMode : ${JSON.stringify(data['configurationColorMode'])}`);
              this.configurationColorMode = data['configurationColorMode'] as number;
            }

            if (JSON.stringify(data['accessConnected']) !== undefined) {
              console.info(TAG, `accessConnected : ${JSON.stringify(data['accessConnected'])}`);
              this.accessibilityConnectedStr = data['accessConnected'] as string;
            }

            if (JSON.stringify(data['accessAudioControl']) !== undefined) {
              console.info(TAG, `accessAudioControl : ${JSON.stringify(data['accessAudioControl'])}`);
              this.accessibilityAudioControlStr = data['accessAudioControl'] as string;
            }

            if (JSON.stringify(data['isPc']) !== undefined) {
              console.info(TAG, `isPc : ${JSON.stringify(data['isPc'])}`);
              this.isPc = data['isPc'] as boolean;
            }

            if (JSON.stringify(data['isRTL']) !== undefined) {
              console.info(TAG, `isRTL : ${JSON.stringify(data['isRTL'])}`);
              this.isRTL = data['isRTL'] as boolean;
            }

            if (JSON.stringify(data['maxFontSizeScale']) !== undefined) {
              console.info(TAG, `maxFontSizeScale : ${JSON.stringify(data['maxFontSizeScale'])}`);
              this.maxFontSizeScale = data['maxFontSizeScale'] as number;
            }

            if (JSON.stringify(data['isShowLoadingProgress']) !== undefined) {
              console.info(TAG, `isShowLoadingProgress : ${JSON.stringify(data['isShowLoadingProgress'])}`);
              this.isShowLoadingProgress = data['isShowLoadingProgress'] as boolean;
            }
          })
          .size({ width: '100%', height: '100%' })
          .bindMenu(this.isMenuShow, (()=>this.deviceMenu()) as CustomBuilder, {
            placement: Placement.BottomRight,
            onDisappear: () => {
              this.isMenuShow = false;
              this.touchMenuItemIndex = -1;
              this.menuShowStateCallback(this.isMenuShow);
            },
            onAppear: () => {
              if (this.extensionProxy != null && this.pickerClickTime !== -1) {
                this.extensionProxy?.send({ 'timeCost': new Date().getTime() - this.pickerClickTime });
                this.pickerClickTime = -1;
              }
              this.menuShowStateCallback(this.isMenuShow);
            }
          } as MenuOptions)
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
      let hasOnlySpeakerAndEarpiece: boolean = this.deviceList!.length === 2 && !this.hasExtDevice(this.deviceList!);
      let hasNoDevices: boolean = this.deviceList === null || this.deviceList!.length === 0;
      let isCalling: boolean = this.sessionType === 'voice_call' || this.sessionType === 'video_call';
      let isExtMenuScene: boolean = isCalling && (hasNoDevices || hasOnlySpeakerAndEarpiece);
      let isPanelForMedia: boolean = !isCalling &&
        (this.pickerStyle === AVCastPickerStyle.STYLE_PANEL &&
          this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_PANEL);
      if (isExtMenuScene || isPanelForMedia) {
        this.isMenuShow = false;
        this.touchMenuItemIndex = -1;
        if (this.extensionProxy != null) {
          this.extensionProxy?.send({ 'clickEvent': true });
        }
      } else {
        this.isMenuShow = !this.isMenuShow;
        if (this.isMenuShow) {
          this.pickerClickTime = new Date().getTime();
        } else {
          this.touchMenuItemIndex = -1;
        }
      }
    })
  }

  private hasExtDevice(allDevice: Array<AVCastPickerDeviceInfo>): boolean {
    for (let i: number = 0; i < allDevice.length; i++) {
      let isEarpieceOrSpeaker: boolean =
        (allDevice[Double.toInt(i)].deviceType === 1 || allDevice[Double.toInt(i)].deviceType === 2) &&
          allDevice[Double.toInt(i)].networkId === 'LocalDevice';
      if (!isEarpieceOrSpeaker) {
        return true;
      }
    }
    return false;
  }

  private menuShowStateCallback(isMenuShow: boolean): void {
    if (this.onStateChange as (state: AVCastPickerState) => void != null &&
      (this.pickerStyle === AVCastPickerStyle.STYLE_MENU ||
        this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_MENU)) {
      let menuShowState: AVCastPickerState = isMenuShow ?
      AVCastPickerState.STATE_APPEARING : AVCastPickerState.STATE_DISAPPEARING;
      this.onStateChange?.(menuShowState);
    }
  }

  @Builder
  private buildCustomPicker() {
    Stack({ alignContent: Alignment.Center}) {
      Column() {
        if (this.isShowLoadingProgress) {
          LoadingProgress()
            .color($r('sys.color.icon_secondary'))
            .width('20vp')
            .height('20vp')
        } else {
          this.customPicker?.();
        }
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

function highQualityStyles(this: TextAttribute, maxScale: number): this {
  this.fontSize(7);
  this.fontWeight(FontWeight.Medium);
  this.fontColor($r('sys.color.font_secondary'));
  this.maxFontScale(maxScale);
  return this;
}
