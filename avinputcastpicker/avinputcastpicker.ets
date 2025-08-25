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
 
const TAG = 'AVInputCastPicker_component';

/**
 * menuItem device info
 */
interface AVInputCastPickerDeviceInfo {
  deviceId: number | String,
  deviceType: number,
  deviceName: string,
  deviceIconName: string,
  isConnected: boolean,
  selectedIconName: string,
}

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

@Component
export struct AVInputCastPicker {
  /**
   * Custom builder from application.
   */
  @BuilderParam customPicker: (() => void);
  /**
   * Device list data.
   */
  @State deviceInfoList: Array<AVInputCastPickerDeviceInfo> = [];
  /**
   * Touch item index.
   */
  @State touchMenuItemIndex: number = -1;
  /**
   * Configuration color mode.
   */
  @State isDarkMode: boolean = false;
  /**
   * Mirrored or not.
   */
  @State isRTL: boolean = false;
  /**
   * Picker state change callback.
   */
  private onStateChange?: (state: AVCastPickerState) => void;
  /**
   * UIExtensionProxy.
   */
  private extensionProxy: UIExtensionProxy | null = null;
  /**
   * show menu start time.
   */
  private pickerClickTime: number = -1;
  /**
   * picker count on creation.
   */
  private pickerCountOnCreation: number = 0;
  /**
   * current picker count.
   */
  private static currentPickerCount: number = 0;

  aboutToAppear(): void {
    AVInputCastPicker.currentPickerCount += 1;
    this.pickerCountOnCreation = AVInputCastPicker.currentPickerCount;
  }

  aboutToDisappear(): void {
    AVInputCastPicker.currentPickerCount -= 1;
  }

  @Builder
  iconBuilder(item: AVInputCastPickerDeviceInfo, isSelected: boolean): void {
    SymbolGlyph(!isSelected ? $r(item.deviceIconName) : $r(item.selectedIconName))
      .fontSize('24vp')
      .fontColor((isSelected && !this.isDarkMode) ?
        [$r('sys.color.comp_background_emphasize')] : [$r('sys.color.icon_primary')])
      .renderingStrategy(SymbolRenderingStrategy.SINGLE)
  }

  @Builder
  textBuilder(item: AVInputCastPickerDeviceInfo) {
    Text(item.deviceName)
      .fontSize($r('sys.float.ohos_id_text_size_body2'))
      .fontColor(item.isConnected ? (!this.isDarkMode ? $r('sys.color.font_emphasize') : $r('sys.color.font_primary')) :
        (!this.isDarkMode ? $r('sys.color.font_primary') : $r('sys.color.font_secondary')))
      .width(254)
      .padding({
        left: 8,
        top: 11,
        right: 8,
        bottom: 11
      })
      .textOverflow({ overflow: TextOverflow.Ellipsis })
      .maxLines(2)
      .wordBreak(WordBreak.BREAK_WORD)
      .direction(this.isRTL ? Direction.Rtl : Direction.Ltr)
  }

  @Builder
  deviceMenu() {
    Column() {
      ForEach(this.deviceInfoList, (item: AVInputCastPickerDeviceInfo, index) => {
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
              this.iconBuilder(item, false)

              this.textBuilder(item)
            }
            .alignItems(VerticalAlign.Center)

            if (item.isConnected && item.selectedIconName !== null && item.selectedIconName !== undefined) {
              Row() {
                this.iconBuilder(item, true)
              }
              .alignItems(VerticalAlign.Center)
            }
          }
          .constraintSize({ minHeight: 40 })
          .padding({ left: 12, right: 12 })
          .onTouch((event) => {
            if (event.type === TouchType.Down) {
              this.touchMenuItemIndex = index;
            } else if (event.type === TouchType.Up) {
              this.touchMenuItemIndex = -1;
            }
          })
          .backgroundColor(this.touchMenuItemIndex === index ? $r('sys.color.interactive_click') : '#00FFFFFF')
          .borderRadius(this.touchMenuItemIndex === index ? $r('sys.float.corner_radius_level2') : 0)

          if (index !== this.deviceInfoList.length - 1) {
            Row()
              .width('100%')
              .height(2)
          }
        }
        .width('100%')
        .onClick(() => {
          console.info(TAG, ` item click ${item.isConnected}`)
          if (this.extensionProxy !== null && !item.isConnected) {
            this.extensionProxy.send({ 'selectedDeviceInfo': item })
          }
        })
      })
    }
    .width(326)
    .borderRadius(8)
  }

  @Builder
  private buildDefaultPicker(isCustomPicker: boolean) {
    UIExtensionComponent({
      abilityName: 'AVInputCastPickerAbility',
      bundleName: 'com.hmos.mediacontroller',
      parameters: {
        'ability.want.params.uiExtensionType': 'sysPicker/mediaControl',
        'isCustomPicker': isCustomPicker,
        'currentPickerCount': this.pickerCountOnCreation,
      }
    })
      .size({ width: '100%', height: '100%' })
      .bindMenu(this.deviceMenu(), {
        onDisappear: () => {
          this.touchMenuItemIndex = -1;
          if (this.onStateChange !== null && this.onStateChange !== undefined) {
            this.onStateChange(AVCastPickerState.STATE_DISAPPEARING);
          }
        },
        onAppear: () => {
          if (this.onStateChange !== null && this.onStateChange !== undefined) {
            this.onStateChange(AVCastPickerState.STATE_APPEARING);
          }
          if (this.extensionProxy !== null && this.pickerClickTime !== -1) {
            this.extensionProxy.send({ 'timeCost': new Date().getTime() - this.pickerClickTime });
            this.pickerClickTime = -1;
          }
        }
      })
      .onClick(() => {
        this.pickerClickTime = new Date().getTime();
      })
      .onRemoteReady((proxy: UIExtensionProxy) => {
        console.info(TAG, 'onRemoteReady');
        this.extensionProxy = proxy;
      })
      .onReceive((data) => {
        if (JSON.stringify(data['deviceInfoList']) !== undefined) {
          this.deviceInfoList = JSON.parse(JSON.stringify(data['deviceInfoList']));
        }

        if (JSON.stringify(data['isDarkMode']) !== undefined) {
          console.info(TAG, `isDarkMode : ${JSON.stringify(data['isDarkMode'])}`);
          this.isDarkMode = data['isDarkMode'] as boolean;
        }

        if (JSON.stringify(data['isRTL']) !== undefined) {
          console.info(TAG, `isRTL : ${JSON.stringify(data['isRTL'])}`);
          this.isRTL = data['isRTL'] as boolean;
        }
      })
      .onTerminated((info) => {
        console.info(TAG, ` onTerminated code: ${info?.code}`);
      })
      .onError((error) => {
        console.info(TAG, ` onError code: ${error?.code} message: ${error?.message}`);
      })
  }

  @Builder
  private buildCustomPicker() {
    Stack({ alignContent: Alignment.Center }) {
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

  build() {
    Column() {
      if (this.customPicker === undefined) {
        this.buildDefaultPicker(false);
      } else {
        this.buildCustomPicker();
      }
    }
    .size({ width: '100%', height: '100%' })
  }
}