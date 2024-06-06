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

const TAG = 'avcastpicker_component ';

/**
 * Definition of av cast picker state.
 */
export enum AVCastPickerState {
  /**
   * The picker starts showing.
   */
  STATE_APPEARING,

  /**
   * The picker finishes presenting.
   */
  STATE_DISAPPEARING
}

/**
 * Definition of av cast picker state.
 */
export enum AVCastPickerStyle {
  /**
   * The picker shows in a panel style.
   */
  STYLE_PANEL,

  /**
   * The picker shows in a menu style.
   */
  STYLE_MENU
}

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
  deviceSource: DeviceSource
}

@Component
export struct AVCastPicker {
  /**
   * Assigns the color of picker component at normal state.
   */
  @State normalColor: Color | number | string = '#000000';

  /**
   * Assigns the color of picker component at active state.
   */
  @State activeColor: Color | number | string = '#000000';

  /**
   * The device that is displayed in the menu.
   */
  @State deviceList: Array<AVCastPickerDeviceInfo> = [];

  /**
   * Session type transferred by the application.
   */
  @State sessionType: string = 'audio';

  /**
   * Display form of application transfer.
   */
  @State pickerStyle: AVCastPickerStyle = AVCastPickerStyle.STYLE_PANEL;

  /**
   * Whether to display the menu.
   */
  @State isMenuShow: boolean = false;

  /**
   * Touch item index.
   */
  @State touchMenuItemIndex: number = -1;

  /**
   * Picker state change callback.
   */
  private onStateChange?: (state: AVCastPickerState) => void;

  /**
   * UIExtensionProxy
   */
  private extensionProxy: UIExtensionProxy | null = null;

  private pickerClickTime: number = -1;

  /**
   * Custom builder from application
   */
  @BuilderParam customPicker: (() => void)

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
  deviceMenu() {
    Column() {
      ForEach(this.deviceList, (item: AVCastPickerDeviceInfo, index) => {
        Flex({
          direction: FlexDirection.Column,
          justifyContent: FlexAlign.SpaceBetween,
          alignItems: ItemAlign.End
        }) {
          Flex({
            direction: FlexDirection.Row,
            justifyContent: FlexAlign.SpaceBetween,
            alignItems: ItemAlign.Center
          }) {
            Row() {
              Image($r(item.deviceIconName))
                .width(24)
                .height(24)
                .fillColor($r('sys.color.ohos_id_color_primary'))
              Text(item.deviceName)
                .fontSize($r('sys.float.ohos_id_text_size_body2'))
                .fontColor(item.isConnected ? $r('sys.color.ohos_id_color_text_primary_activated')
                  : $r('sys.color.ohos_id_color_text_primary'))
                .width(item.isConnected ? 144 : 168)
                .padding({
                  left: 8,
                  top: 12,
                  right: 8,
                  bottom: 12
                })
            }
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            if (item.isConnected && item.selectedIconName !== null && item.selectedIconName !== undefined) {
              Row() {
                Image($r(item.selectedIconName))
                  .width(24)
                  .height(24)
                  .fillColor($r('sys.color.ohos_id_color_activated'))
              }
              .justifyContent(FlexAlign.Start)
              .alignItems(VerticalAlign.Center)
            }
          }
          .constraintSize({ minHeight: 48 })
          .padding({ left: 12, right: 12 })
          .onTouch((event) => {
            if (event.type === TouchType.Down) {
              this.touchMenuItemIndex = index;
            } else if (event.type === TouchType.Up) {
              this.touchMenuItemIndex = -1;
            }
          })
          .backgroundColor(this.touchMenuItemIndex === index
            ? $r('sys.color.ohos_id_color_click_effect') : '#00FFFFFF')
          .borderRadius(this.touchMenuItemIndex === index
            ? $r('sys.float.ohos_id_corner_radius_default_m') : 0)

          if (index != this.deviceList.length - 1) {
            Divider()
              .height(1)
              .width(172)
              .color($r('sys.color.ohos_id_color_list_separator'))
              .padding({ right: 12 })
          }
        }
        .width('100%')
        .onClick(() => {
          if (this.extensionProxy != null && !item.isConnected) {
            this.extensionProxy.send({ 'selectedDeviceInfo': item })
          }
        })
      })
    }
    .width(216)
  }

  @Builder
  private buildDefaultPicker(isCustomPicker: boolean) {
    UIExtensionComponent(
      {
        abilityName: 'UIExtAbility',
        bundleName: 'com.hmos.mediacontroller',
        parameters: {
          'normalColor': this.normalColor,
          'avCastPickerStyle': this.pickerStyle,
          'ability.want.params.uiExtensionType': 'sys/commonUI',
          'isCustomPicker': isCustomPicker,
        }
      })
      .onRemoteReady((proxy: UIExtensionProxy) => {
          console.info(TAG, 'onRemoteReady');
          this.extensionProxy = proxy;
      })
      .onReceive((data) => {
        if (JSON.stringify(data['state']) !== undefined) {
          console.info(TAG, `picker state change : ${JSON.stringify(data['state'])}`);
          if (this.onStateChange != null) {
            if (parseInt(JSON.stringify(data['state'])) === AVCastPickerState.STATE_APPEARING) {
              this.onStateChange(AVCastPickerState.STATE_APPEARING);
            } else {
              this.onStateChange(AVCastPickerState.STATE_DISAPPEARING);
            }
          }
        }

        if (JSON.stringify(data['deviceList']) !== undefined) {
          console.info(TAG, `picker device list : ${JSON.stringify(data['deviceList'])}`);
          this.deviceList = JSON.parse(JSON.stringify(data['deviceList']));
          if ((this.pickerStyle === AVCastPickerStyle.STYLE_MENU && this.deviceList?.length === 2 &&
            !this.hasExtDevice(this.deviceList) && (this.sessionType === 'voice_call' ||
            this.sessionType === 'video_call')) || this.pickerStyle === AVCastPickerStyle.STYLE_PANEL) {
            this.isMenuShow = false;
          }
        }

        if (JSON.stringify(data['pickerStyle']) !== undefined) {
          console.info(TAG, `picker style : ${JSON.stringify(data['pickerStyle'])}`);
          this.pickerStyle = data['pickerStyle'] as AVCastPickerStyle;
        }

        if (JSON.stringify(data['sessionType']) !== undefined) {
          console.info(TAG, `session type : ${JSON.stringify(data['sessionType'])}`);
          this.sessionType = data['sessionType'] as string;
        }

        if (JSON.stringify(data['isShowMenu']) !== undefined) {
          console.info(TAG, `isShowMenu : ${JSON.stringify(data['isShowMenu'])}`);
          this.isMenuShow = data['isShowMenu'] as boolean;
        }
      })
      .size({ width: '100%', height: '100%' })
      .bindMenu(this.isMenuShow, this.deviceMenu(), {
        placement: Placement.TopRight,
        onDisappear: () => {
          this.isMenuShow = false;
        },
        onAppear: () => {
          if (this.extensionProxy != null && this.pickerClickTime !== -1) {
              this.extensionProxy.send({ 'timeCost': new Date().getTime() - this.pickerClickTime});
              this.pickerClickTime = -1;
          }
        }
      })
      .onClick(() => {
        if ((this.pickerStyle === AVCastPickerStyle.STYLE_MENU && this.deviceList?.length === 2 &&
          !this.hasExtDevice(this.deviceList) && (this.sessionType === 'voice_call' ||
          this.sessionType === 'video_call')) || this.pickerStyle === AVCastPickerStyle.STYLE_PANEL) {
          this.isMenuShow = false;
        } else {
          this.isMenuShow = !this.isMenuShow;
          if (this.isMenuShow) {
              this.pickerClickTime = new Date().getTime();
          }
        }
      })
  }

  private hasExtDevice(allDevice: Array<AVCastPickerDeviceInfo>): boolean {
    for (let i = 0; i < allDevice.length; i++) {
      if (allDevice[i].deviceType !== 1 && // 1 is audio.DeviceType.EARPIECE
        allDevice[i].deviceType !== 2) { // 2 is audio.DeviceType.SPEAKER
        return true;
      }
    }
    return false;
  }

  @Builder
  private buildCustomPicker() {
    Stack({ alignContent: Alignment.Center}) {
      Column() {
        this.customPicker();
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
