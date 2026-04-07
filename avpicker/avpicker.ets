/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
import image from '@ohos.multimedia.image';

const TAG = 'avcastpicker_component ';
const castPlusAudioType = 8;
const MAX_PICKER_LIMIT = 20;
const HIGH_QUALITY_MAX_SCALE = 1.5;

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

enum AVCastPickerColorMode {
  /**
   * the color mode of picker is not set.
   */
  AUTO = 0,

  /**
   * Dark mode of picker.
   */
  DARK = 1,

  /**
   * Light mode of picker.
   */
  LIGHT = 2
}

enum HiPlayCastMode {
  DEVICE_LEVEL = 1,
  APP_LEVEL = 2
}

enum KeyInputCode {
  KEYCODE_VOLUME_UP = 16,
  KEYCODE_VOLUME_DOWN = 17
}

interface HighQualityParams {
  iconLeft: string,
  iconRight: string,
}

export interface ShowingBundleTS {
  pixelData?: image.PixelMap | undefined;
  appName?: string | undefined;
  isShowBadge: boolean | undefined;
}

interface TextParams {
  currentApp?: string,
  allMediaAudio?: string,
  playingNow?: string,
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
  fromCall?: boolean,
  deviceSubName?: string,
  supportCastMode?: number,
  castMode?: number,
  castUid?: number,
  bundleInfo?: ShowingBundleTS,
}

/**
 * 全屋音乐分区信息
 */
export interface HomeMusicServicesData {
  bassWeight: number;
  playTask: string;
  acousticsMode: number;
  volumePercentage: number;
  description: number;
  supportMusicLed: boolean;
  label: string;
  type: number;
  roomId: string;
  limitedVolume: number;
  volume: number;
  faultCode: number;
  supportStereo: number;
  playState: number;
  speakerList: string;
  enable: number;
  name: string;
  zoneId: string;
};
 
export interface HomeMusicServices {
  st: string;
  ts: string;
  sid: string;
  data: HomeMusicServicesData;
}
 
export type AnyType = string | boolean | number | bigint | null | object | undefined;
export interface HomeMusic {
  devId: string;
  devName: string;
  homeId: string;
  homeName: string;
  roomId: string;
  roomName: string;
  status: string;
  devInfo: Record<string, AnyType>;
  services: HomeMusicServices[];
}

@Component
export struct AVCastPicker {
  /**
   * Assigns the color of picker component at normal state.
   */
  @State normalColor: Color | number | string | undefined = undefined;

  /**
   * Assigns the color of picker component at active state.
   */
  @State activeColor: Color | number | string | undefined = undefined;

  /**
   * Definition of color mode of picker.
   */
  @State colorMode: AVCastPickerColorMode = AVCastPickerColorMode.AUTO;

  /**
   * The device that is displayed in the menu.
   */
  @State deviceList: Array<AVCastPickerDeviceInfo> = [];

  /**
   * The scale of font size.
   */
  @State fontSizeScale: number = 1;

  /**
   * Session type transferred by the application.
   */
  @State sessionType: string = 'audio';

  /**
   * Display form of application transfer.
   */
  @State pickerStyle: AVCastPickerStyle = AVCastPickerStyle.STYLE_PANEL;

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
   * Text params.
   */
  @State textParams: TextParams = {};

  /**
   * whether it is an ANCO session
   */
  @State isAncoSession: boolean = false;

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
  @BuilderParam customPicker: (() => void)

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
  @State accessibilityAudioControlStr: string = '音视频投播';

  // 标题和全屋播放按钮
  @State houseMusicTitle: string = '';
  @State houseMusicPlay: string = '';
  @State houseMusicPlayCancel: string = '';
  // 房间信息
  @State @Watch('roomListChange') roomListService: HomeMusicServices[] = [];
  // 是否全选
  @State isAllSelecting: boolean = false;
  // 房间勾选
  @State timeoutIds: number[] = [];
  @State @Watch('homeMusicPlayTaskIdChange') playTaskIdStr: string = '';
  @State roomIsSelect: boolean[] = [];
  @State isSelectRoomListService: HomeMusicServices[] = [];
  @State roomSelectStatusPending: boolean[] = [];
  @State @Watch('selectHomeMusicSys') houseMusicIsSelect: boolean = false;
  @State @Watch('homeMusicScanStatusChange') scanStatus: number = -1;
  // 房间音量
  @State roomVolumeVisible: Visibility[] = [];
  @State roomCurrVolume: number[] = [];
  @State roomMaxVolume: number = 0;
  // 房间信息组件高度
  @State roomItemHeight: number = 0;

  scroller: Scroller = new Scroller();

  @State isPc: boolean = false;
  @State isRTL: boolean = false;
  @State restartUECMessage: number = 1;
  private needToRestart: boolean = false;
  @State isShowLoadingProgress: boolean = false;
  private pickerCountOnCreation: number = 0;
  @State isDisabledByPickerLimit: boolean = false;
  @State isDeviceLevel: boolean = true;
  @State isSubMenuExpanded: boolean = false;
  @State isSwitch: boolean = false;

  private static currentPickerCount: number = 0;

  aboutToAppear(): void {
    AVCastPicker.currentPickerCount += 1;
    this.pickerCountOnCreation = AVCastPicker.currentPickerCount;
    if (this.pickerCountOnCreation > MAX_PICKER_LIMIT) {
      console.info(TAG, 'disable picker');
      this.isDisabledByPickerLimit = true;
    }
  }

  aboutToDisappear(): void {
    AVCastPicker.currentPickerCount -= 1;
    this.timeoutIds.forEach((id) => {
      clearTimeout(id);
    });
    this.timeoutIds = [];
  }

  MenuStateChange() {
    if (this.extensionProxy != null) {
      this.extensionProxy.send({ 'isMenuShow': this.isMenuShow });
      let needListenKeyInput = (this.isMenuShow && this.houseMusicIsSelect);
      this.extensionProxy.send({ 'isSelectHomeMusicSys': needListenKeyInput });
    }
  }

  private showHighQuality(item: AVCastPickerDeviceInfo): boolean {
    if (item.supportedProtocols === undefined) {
      return false;
    }
    return (item.supportedProtocols & castPlusAudioType) !== 0;
  }

  private createNullRoomService(): HomeMusicServices[] {
    return [{'st':'','ts':'','sid':'','data':{'bassWeight':0,'playTask':'','acousticsMode':0,'volumePercentage':0,'description':0,
      'supportMusicLed':false,'label':'','type':0,'roomId':'','limitedVolume':0,'volume':0,'faultCode':0,'supportStereo':0,
      'playState':0,'speakerList':'','enable':0,'name':'','zoneId':''}}];
  }

  refreshRoomList() {
    this.timeoutIds.forEach((id) => {
      clearTimeout(id);
    });
    this.timeoutIds = [];
    let roomListTemp: HomeMusicServices[] = this.roomListService;
    let isAllRoomSelect: boolean = true;
    let hasRoomIsSelect: boolean = false;
    let maxVolumeNum: number = 0;
    for (let i = 0; i < roomListTemp.length; i++) {
      this.roomSelectStatusPending[i] = false;
      this.roomIsSelect[i] = ((roomListTemp[i].data.playTask === this.playTaskIdStr) &&
        (this.playTaskIdStr !== '')) ? true : false;
      this.roomCurrVolume[i] = roomListTemp[i].data.volume;
      this.roomVolumeVisible[i] = this.roomIsSelect[i] ? Visibility.Visible : Visibility.None;
      if (!this.roomIsSelect[i]) {
        isAllRoomSelect = false;
      } else {
        hasRoomIsSelect = true;
        if (maxVolumeNum < roomListTemp[i].data.volume) {
          maxVolumeNum = roomListTemp[i].data.volume;
        }
      }
    }
    if (isAllRoomSelect && roomListTemp.length > 0) {
      this.isAllSelecting = true;
    } else {
      this.isAllSelecting = false;
    }
    this.houseMusicIsSelect = hasRoomIsSelect;
    if (hasRoomIsSelect) {
      this.roomMaxVolume = maxVolumeNum;
      this.roomMaxVolumeChange();
    }
  }

  homeMusicPlayTaskIdChange() {
    this.refreshRoomList();
  }

  roomListChange() {
    this.refreshRoomList();
  }

  selectHomeMusicSys() {
    if (this.extensionProxy != null) {
      let needListenKeyInput = (this.isMenuShow && this.houseMusicIsSelect);
      this.extensionProxy.send({ 'isSelectHomeMusicSys': needListenKeyInput });
    }
  }

  homeMusicScanStatusChange() {
    if (this.scanStatus === 0) {
      // 全屋播控扫描中，现有房间显示全部需要pending，等待房间扫描刷新即可
      this.setAllRoomSelectStatusPending();
    } else {
      this.roomSelectStatusPendingInit();
    }
  }

  roomMaxVolumeChange() {
    if (this.extensionProxy != null) {
      this.extensionProxy.send({ 'homeMusicMaxVolumeSync': this.roomMaxVolume });
    }
  }

  findRoomMaxVolume() : number {
    let maxVolumeNum: number = 0;
    for (let i = 0; i < this.roomListService.length; i++) {
      if ((maxVolumeNum < this.roomListService[i].data.volume) && this.checkRoomIsSelect(i)) {
        maxVolumeNum = this.roomListService[i].data.volume;
      }
    }
    return maxVolumeNum;
  }

  checkRoomIsSelect(index: number): boolean {
    if((this.roomListService[index].data.playTask === this.playTaskIdStr) &&
      (this.playTaskIdStr !== '')){
      return true;
    }
    return false;
  }

  getCurrIsAllSelectStatus() {
    let isAllSelect: boolean = true;
    for(let i = 0; i < this.roomListService.length; i++) {
      if (!this.checkRoomIsSelect(i)) {
        isAllSelect = false;
        break;
      }
    }
    if (isAllSelect && (this.roomListService.length > 0)) {
      return true;
    }
    return false;
  }

  roomSelectStatusPendingInit() {
    for (let i = 0; i < this.roomListService.length; i++) {
      this.roomSelectStatusPending[i] =  false;
    }
  }

  setAllRoomSelectStatusPending() {
    for (let i = 0; i < this.roomListService.length; i++) {
    //全选时处理所有勾选状态转为pending，等待播控中心返回结果
      this.roomSelectStatusPending[i] = true;
    }
  }

  getCurrSelectRoom(index: number, selectStatus: boolean) {
    // 先清除勾选的房间信息，再处理每个房间的勾选情况
    this.isSelectRoomListService.length = 0;
    for(let i = 0; i < this.roomListService.length; i++) {
      if (i === index) {
        if (selectStatus) {
          this.isSelectRoomListService.push(this.roomListService[index]);
        }
        continue;
      }
      if (this.checkRoomIsSelect(i)) {
        this.isSelectRoomListService.push(this.roomListService[i]);
      }
    }
  }

  onSliderValueChange(index: number, value: number, mode: SliderChangeMode) {
    switch(mode) {
      case SliderChangeMode.Begin:
      case SliderChangeMode.Moving:
        break;
      case SliderChangeMode.End:
        console.info(TAG, `Slider index:${index} Mode.End value:${value}`);
        if (index < this.roomListService.length && this.extensionProxy != null) {
          this.roomListService[index].data.description = index + 1;
          this.extensionProxy.send({ 'roomVolumeChange': this.roomListService[index] });
          this.roomMaxVolume = this.findRoomMaxVolume();
          this.roomMaxVolumeChange();
        }
        break;
      default:
        break;
    }
  }

  syncToRoomVolume(input: number) {
    let volumeMin = 0;
    let volumeStep = 10;
    let volumeMax = 15;
    for (let i = 0; i < this.roomListService.length; i++) {
      if (!this.checkRoomIsSelect(i)) {
        continue;
      }
      let currRoomVolume = Math.round(this.roomListService[i].data.volume * 3 / 2 / volumeStep);
      let settingVolume = (input === KeyInputCode.KEYCODE_VOLUME_UP) ? currRoomVolume + 1 : currRoomVolume - 1;
      if (settingVolume <= volumeMin) {
        settingVolume = volumeMin;
      } else if (settingVolume < volumeMin + 1) {
        settingVolume = volumeMin + 1;
      } else if (settingVolume >= volumeMax) {
        settingVolume = volumeMax;
      } else if (settingVolume > volumeMax - 1) {
        settingVolume = volumeMax - 1;
      } else {
        settingVolume = Math.round(settingVolume);
      }
      this.roomListService[i].data.volume = Math.round(settingVolume * volumeStep * 2 / 3);
      this.roomCurrVolume[i] = this.roomListService[i].data.volume;
    }
  }

  sendAllRoomVolumeToController() {
    if (this.extensionProxy != null) {
      for (let i = 0; i < this.roomListService.length; i++) {
        this.roomListService[i].data.description = i + 1;
        this.extensionProxy.send({ 'roomVolumeChange': this.roomListService[i] });
      }
    }
  }

  allSelectOnClickEven() {
    this.setAllRoomSelectStatusPending();
    const timeId = setTimeout(() => {
      this.roomSelectStatusPendingInit();
    }, 3000);
    if (typeof timeId === 'number') {
      this.timeoutIds.push(timeId);
    }
    if (this.extensionProxy != null) {
      if (!this.getCurrIsAllSelectStatus()) {
          this.extensionProxy.send({ 'roomSelectChange': this.roomListService });
          this.extensionProxy.send({ 'roomIsSelectAll': true });
      } else {
          this.extensionProxy.send({ 'roomSelectChange': this.createNullRoomService() });
          this.extensionProxy.send({ 'roomIsSelectAll': false });
      }
    }
  }

  /**
    * 全屋音乐播放标题 '全屋音乐系统'   '全屋播放' / '取消全屋播放'
    */
  @Builder HomeMusicSystemTitleBuilder() {
    Row() {
      Text(this.houseMusicTitle)
        .fontColor($r('sys.color.font_primary'))
        .fontSize($r('sys.float.Subtitle_M'))
        .fontWeight(FontWeight.Medium)
        .constraintSize({ maxWidth: '65%' })
      Text(this.isAllSelecting ? this.houseMusicPlayCancel : this.houseMusicPlay)
        .fontColor(Color.Blue)
        .fontSize($r('sys.float.Body_M'))
        .fontWeight(FontWeight.Medium)
        .constraintSize({ maxWidth: '35%' })
        .onClick(() => {
          this.allSelectOnClickEven();
        })
    }
    .width('100%')
    .justifyContent(FlexAlign.SpaceBetween)
    .padding({top: '12vp', right: '24vp', bottom: '4vp', left: '24vp'})
    .borderRadius({topLeft: '32vp', topRight: '32vp'})
  }

  /**
   * 适配大字体(1.75倍以上)全屋音乐播放标题 '全屋音乐系统'   '全屋播放' / '取消全屋播放'
   */
  @Builder BigFontHomeMusicSystemTitleBuilder() {
    Column() {
      Text(this.houseMusicTitle)
        .fontColor($r('sys.color.font_primary'))
        .fontSize($r('sys.float.Subtitle_M'))
        .fontWeight(FontWeight.Medium)
      Text(this.isAllSelecting ? this.houseMusicPlayCancel : this.houseMusicPlay)
        .fontColor(Color.Blue)
        .fontSize($r('sys.float.Body_M'))
        .fontWeight(FontWeight.Medium)
        .onClick(() => {
          this.allSelectOnClickEven();
        })
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
    .padding({top: '12vp', right: '24vp', bottom: '4vp', left: '24vp'})
    .borderRadius({topLeft: '32vp', topRight: '32vp'})
  }

  /**
   * 全屋音乐播放列表
   */
  @Builder HomeMusicSystemRoomListBuilder() {
    Scroll(this.scroller) {
      Column() {
        ForEach(this.roomListService, (item: HomeMusicServices, index) => {
          Stack({alignContent: Alignment.Start}) {
            // 构建一行横向排列的全屋音乐 图标，房间名，音量条，勾选按钮
            this.RoomItemBuilder(item, index)
          }
          .constraintSize({ minHeight: 64 })
          .width('100%')
          if (index !== this.roomListService.length - 1) {
            // 构建行间分割线
            this.DividerBuilder()
          }
        })
      }
    }
    .padding({top: '4vp', right: '24vp', bottom: '4vp', left: '24vp'})
    .width('100%')
    .constraintSize({ minHeight: this.roomItemHeight })
    .align(Alignment.Start)
    .borderRadius({bottomLeft: '32vp', bottomRight: '32vp'})
    .scrollBar(BarState.Auto)
  }

  /**
   * 全屋音乐信息 - 横向排列 房间图标，房间名，音量条，勾选按钮
   * @param item
   * @param index
   */
  @Builder RoomItemBuilder(item: HomeMusicServices, index: number) {
    Flex({alignItems: ItemAlign.Center}) {
      this.RoomHouseBuilder();
      this.RoomNameAndVolumeBuilder(item, index);
      this.RoomCheckBuilder(item, index);
    }
  }

  /**
   * 全屋音乐播放列表
   *   - 房间图标构建
   */
  @Builder RoomHouseBuilder() {
    SymbolGlyph($r('sys.symbol.music_house_fill'))
      .fontSize('24vp')
      .fontColor([Color.Black])
      .margin({
        right: $r('sys.float.ohos_id_elements_margin_horizontal_l'),
        left: 0
      })
      .draggable(false)
      .flexGrow(0)
      .flexShrink(0)
      .flexBasis('auto')
      .renderingStrategy(SymbolRenderingStrategy.SINGLE)
  }

  /**
   * 全屋音乐播放列表
   *   - 房间名+音量条
   */
  @Builder RoomNameAndVolumeBuilder(item: HomeMusicServices, index: number) {
    Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Start }) {
      Text(item.data.name)
        .fontWeight('sys.string.ohos_id_text_font_family_medium')
        .fontSize($r('sys.float.ohos_id_text_size_body1'))
        .textOverflow({ overflow: TextOverflow.Ellipsis })
        .wordBreak(WordBreak.BREAK_ALL)
        .width('100%')
        .constraintSize({ minHeight: 16 })
      Slider({
        value: this.roomCurrVolume[index],
        min: 0,
        max: 100,
        step: 1,
        style: SliderStyle.NONE,
        direction: Axis.Horizontal
      })
        .visibility(this.roomVolumeVisible[index])
        .blockColor(Color.Transparent)
        .showSteps(false)
        .showTips(false)
        .blockStyle({
          type: SliderBlockType.SHAPE,
          shape: new Path({ commands: 'M60 60 M30 30 L15 56 L45 56 Z' })
        })
        .height(16)
        .onChange((value: number, mode: SliderChangeMode) => {
          console.info(TAG, `YuBeL room slider onChange: ${value}, mode=${mode}, index=${index}`);
          this.roomListService[index].data.volume = value;
          this.roomCurrVolume[index] = value;
          this.onSliderValueChange(index, value, mode);
        })
    }
  }

  /**
   * 全屋音乐播放列表
   *   - 勾选按钮
   */
  @Builder RoomCheckBuilder(item: HomeMusicServices, index: number) {
    //点击勾选按钮触发状态pending状态，等待播控中心下发勾选控制结果
    if (!this.roomSelectStatusPending[index]) {
      Checkbox()
        .select(this.roomIsSelect[index])
        .shape(CheckBoxShape.CIRCLE)
        .onClick(() => {
          this.roomSelectStatusPending[index] = true;
          const timeId = setTimeout(() => {
            this.roomSelectStatusPendingInit();
          }, 3000);
          if (typeof timeId === 'number') {
            this.timeoutIds.push(timeId);
          }
          this.getCurrSelectRoom(index, !this.roomIsSelect[index]);
          if (this.isSelectRoomListService.length > 0) {
            if (this.extensionProxy != null) {
              this.extensionProxy.send({ 'roomSelectChange': this.isSelectRoomListService });
            }
          } else {
            if (this.extensionProxy != null) {
              this.extensionProxy.send({ 'roomSelectChange': this.createNullRoomService() });
            }
          }
        })
        .width(30)
        .margin({
          left: '16vp'
        })
    } else {
      LoadingProgress()
        .width(36)
        .margin({
          left: '16vp'
        })
    }
  }

  /**
   * 分割线构建
   * - param prefix
   * - param index
   */
  @Builder DividerBuilder() {
    Row() {
      Divider()
        .color($r('sys.color.comp_divider'))
        .opacity(0.5)
        .margin({
          left: $r('sys.float.ohos_id_elements_margin_horizontal_l'),
          right: 0
        })
    }
    .margin({ left: '24vp' })
    .zIndex(1)
  }

  @Builder
  houseMusicSys() {
    if (this.roomListService.length > 0) {
      Column(){
        if (this.fontSizeScale > 1.75) {
          this.BigFontHomeMusicSystemTitleBuilder()
        } else {
          this.HomeMusicSystemTitleBuilder()
        }
        this.HomeMusicSystemRoomListBuilder()
      }
      .backgroundColor((this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
        '#FFFFFFFF' : '#FF3F3F3F')
      .borderRadius({topLeft: '20vp', topRight: '20vp', bottomLeft: '20vp', bottomRight: '20vp'})
    }
  }

  @Builder
  deviceAndHouseMusicSys() {
    Column({ space: 8 }) {
      this.deviceMenu()
      this.houseMusicSys()
    }
    .onTouch((event?: TouchEvent) => {
      event?.stopPropagation();
    })
    .width(this.isPc ? 326 : 216)
    .borderRadius(this.isPc ? 8 : 20)
  }

  build() {
    Column() {
      if (this.isDisabledByPickerLimit) {
        this.buildDisabledPicker();
      } else if (this.customPicker === undefined) {
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
          [$r('sys.color.comp_background_emphasize')] : [$r('sys.color.icon_primary')])
        .renderingStrategy(item.fromCall && item.deviceType === 2 ? 
          SymbolRenderingStrategy.SINGLE : SymbolRenderingStrategy.MULTIPLE_OPACITY)
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
      .fontColor((item.isConnected && !this.houseMusicIsSelect) ?
        (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ?
        $r('sys.color.font_emphasize') : $r('sys.color.font_primary')) :
        (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ?
        $r('sys.color.font_primary') : $r('sys.color.font_secondary')))
      .textOverflow({ overflow: TextOverflow.Ellipsis })
      .maxLines(2)
      .wordBreak(WordBreak.BREAK_WORD)
      .maxFontScale(this.maxFontSizeScale)
      .direction(this.isRTL ? Direction.Rtl : Direction.Ltr)
  }

  @Builder
  subTextBuilder(item: AVCastPickerDeviceInfo) {
    Row() {
      Text(item.deviceSubName || '')
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor((item.isConnected && !this.houseMusicIsSelect) ?
          (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ?
          $r('sys.color.font_emphasize') : $r('sys.color.font_primary')) :
          (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ?
          $r('sys.color.font_primary') : $r('sys.color.font_secondary')))
        .textOverflow({ overflow: TextOverflow.Ellipsis })
        .maxLines(1)
        .maxFontScale(this.maxFontSizeScale)
        .direction(this.isRTL ? Direction.Rtl : Direction.Ltr)
    }
    .width('100%')
  }

  @Builder
  highQualityIconBuilder(params: HighQualityParams) {
    Row() {
      Text(params.iconLeft)
        .highQualityStyles(Math.min(HIGH_QUALITY_MAX_SCALE, this.maxFontSizeScale))
      Text(params.iconRight)
        .highQualityStyles(Math.min(HIGH_QUALITY_MAX_SCALE, this.maxFontSizeScale))
        .margin({left: 2 * (Math.min(HIGH_QUALITY_MAX_SCALE, this.fontSizeScale))})
    }
    .direction(Direction.Ltr)
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
              this.iconBuilder(item, false)
              Flex({direction: FlexDirection.Column, justifyContent: FlexAlign.Start}) {
                this.textBuilder(item)
                if (item.fromCall) {
                  this.subTextBuilder(item)
                } else if (item.highQualityParams !== undefined && this.showHighQuality(item)) {
                  Flex() {
                    this.highQualityIconBuilder(item.highQualityParams)
                  }
                  .borderRadius(4)
                  .border({
                    width: Math.min(HIGH_QUALITY_MAX_SCALE, this.fontSizeScale),
                    color: $r('sys.color.font_secondary')
                  })
                  .padding({top: 2.5, right: 4, bottom: 2.5, left: 4})
                  .margin({top: 4})
                  .width('auto')
                   
                  if ((item.isConnected || item.castUid !== 0) &&
                    item.supportCastMode === HiPlayCastMode.DEVICE_LEVEL) {
                    Flex({direction:FlexDirection.Row, alignItems:ItemAlign.Center}) {
                      Row() {
                        if (item.castMode === HiPlayCastMode.DEVICE_LEVEL) {
                          SymbolGlyph($r('sys.symbol.speaker_wave_2'))
                            .fontSize(`16vp`)
                            .fontColor([$r('sys.color.font_secondary')])
                        } else {
                          this.SmallPicIcon(item.bundleInfo?.pixelData)
                        }
                      }
                      .margin({
                        right: this.isRTL ? 0 : 4,
                        left: this.isRTL ? 4 : 0
                      })
                      .direction(Direction.Ltr)
 
                      Row() {
                        if (item.castMode === HiPlayCastMode.DEVICE_LEVEL) {
                          Text(this.textParams?.allMediaAudio)
                          .fontWeight('sys.string.ohos_id_text_font_family_regular')
                          .fontSize($r('sys.float.ohos_id_text_size_body3'))
                          .textOverflow({ overflow: TextOverflow.Ellipsis })
                          .maxFontScale(this.maxFontSizeScale)
                          .wordBreak(WordBreak.BREAK_ALL)
                          .maxLines(1)
                      } else {
                        Text(this.textParams?.playingNow)
                          .fontWeight('sys.string.ohos_id_text_font_family_regular')
                          .fontSize($r('sys.float.ohos_id_text_size_body3'))
                          .textOverflow({ overflow: TextOverflow.Ellipsis })
                          .maxFontScale(this.maxFontSizeScale)
                          .wordBreak(WordBreak.BREAK_ALL)
                          .maxLines(1)
                      }

                    }
                    .direction(Direction.Ltr)

                    if (item.isConnected && !this.isAncoSession) {
                      if (item.bundleInfo?.isShowBadge) {
                        Row(){
                          Badge({
                            value: '',
                            style: { badgeSize: 6, badgeColor: $r('sys.color.warning') }
                          }) {
                            SymbolGlyph($r('sys.symbol.arrowtriangle_down_fill'))
                              .fontSize('16vp')
                              .fontColor([$r('sys.color.font_secondary')])
                          }
                          .width(18)
                          .height(16)
                        }
                        .onDisAppear(() => {
                          if (item.bundleInfo?.isShowBadge && item?.deviceState === 0){
                            if (this.extensionProxy != null) {
                              this.extensionProxy.send({'isShowBadge': false});
                            }
                          }
                        })
                        .margin({left :8, right: 8})
                        .direction(Direction.Ltr) 
                      } else {
                        Row() {
                          SymbolGlyph($r('sys.symbol.arrowtriangle_down_fill'))
                            .fontSize('16vp')
                            .fontColor([$r('sys.color.font_secondary')])
                        }
                        .margin({left :8, right: 8})
                        .direction(Direction.Ltr)
                      }
                    }
                  }
                  .onClick(() => {
                    if (item.isConnected && !this.isAncoSession) {
                      this.isDeviceLevel = (item.castMode === HiPlayCastMode.DEVICE_LEVEL)
                      if (this.extensionProxy != null) {
                        this.extensionProxy.send({'isShowBadge': false});
                      }
                      if (!this.isSubMenuExpanded) {
                        this.isSwitch = true;
                        this.isMenuShow = false;
                      }
                    }
                  })
                  .padding({top: 2.5, right: 4, bottom: 2.5, left: 4})
                  .margin({top: 4})
                  .width('auto')
                }

                }
              }
              .width(this.isPc ? 254 : 144)
              .padding({
                left: 8,
                top: this.isPc ? 11 : (this.showHighQuality(item) ? 7 : 17),
                right: 8,
                bottom: this.isPc ? 11 : (this.showHighQuality(item) ? 7 : 17),
              })
            }
            .alignItems(VerticalAlign.Center)

            if (item.isConnected && item.selectedIconName !== null && item.selectedIconName !== undefined &&
                !this.houseMusicIsSelect) {
              Row() {
                this.iconBuilder(item, true)
              }
              .alignItems(VerticalAlign.Center)
            }
          }
          .constraintSize({ minHeight: this.isPc ? 40 : 48 })
          .padding({ left: 12, right: 12 })
          .onTouch((event) => {
            if (event.type === TouchType.Down) {
              this.touchMenuItemIndex = index;
            } else if (event.type === TouchType.Up) {
              this.touchMenuItemIndex = -1;
            }
          })
          .backgroundColor(this.touchMenuItemIndex === index ?
            $r('sys.color.interactive_click') : '#00FFFFFF')
          .borderRadius(this.touchMenuItemIndex === index ?
            (this.isPc ? $r('sys.float.corner_radius_level2') : $r('sys.float.corner_radius_level8')) : 0)

          if (!this.isPc && (index != this.deviceList.length - 1)) {
            Divider()
              .opacity(0.5)
              .color($r('sys.color.comp_divider'))
              .padding({ right: (this.isRTL ? 44 : 12), left: (this.isRTL ? 12 : 44) })
          } else if (this.isPc && (index != this.deviceList.length - 1)) {
            Row()
              .width('100%')
              .height(2)
          }
        }
        .width('100%')
        .onClick(() => {
          if (this.extensionProxy !== null && this.houseMusicIsSelect) {
            this.setAllRoomSelectStatusPending();
            const timeId = setTimeout(() => {
              this.roomSelectStatusPendingInit();
            }, 3000);
            if (typeof timeId === 'number') {
              this.timeoutIds.push(timeId);
            }
            this.extensionProxy.send({ 'roomSelectChange': this.createNullRoomService() });
          }
          if (this.extensionProxy != null && !item.isConnected) {
            this.extensionProxy.send({ 'selectedDeviceInfo': item })
          }
        })
        .accessibilityGroup(true)
        .accessibilitySelected(item.isConnected)
      })
    }
    .width(this.isPc ? 326 : 216)
    .borderRadius(this.isPc ? 8 : 20)
    .backgroundColor((this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
      '#FFFFFFFF' : '#FF3F3F3F')
  }

  @Builder
  castModeMenu() {
    Column() {
      Flex() {
        Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
          Flex({ alignItems: ItemAlign.Center}){
            Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.Center}) {
              Text(this.textParams?.allMediaAudio)
                .fontWeight('sys.string.ohos_id_text_font_family_medium')
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .width('100%')
                .textOverflow({ overflow: TextOverflow.Ellipsis })
                .maxFontScale(this.maxFontSizeScale)
                .wordBreak(WordBreak.BREAK_ALL)
                .maxLines(1)
            }
 
            Row() {
              if (this.isDeviceLevel) {
                SymbolGlyph($r('sys.symbol.checkmark'))
                  .fontSize('24vp')
                  .fontColor((this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
                    [$r('sys.color.comp_background_emphasize')] : [$r('sys.color.icon_primary')])
              }
            }
            .width(48)
            .height(48)
            .justifyContent(FlexAlign.End)
          }
          .margin({ left: 12, right: 12 })
        }
        .margin({ left: 4, right: 4 })
      }
      .width(224)
      .height(48)
      .onClick(() => {
        this.isDeviceLevel = true
        if (this.extensionProxy != null) {
          this.extensionProxy.send({'castMode': HiPlayCastMode.DEVICE_LEVEL});
        }
      })

      Divider().width(192)

       Flex() {
        Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems:ItemAlign.Center }) {
          Flex({ alignItems:ItemAlign.Center }) {
            Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.Center}) {
              Text(this.textParams?.currentApp)
                .fontWeight('sys.string.ohos_id_text_font_family_medium')
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .width('100%')
                .textOverflow({ overflow: TextOverflow.Ellipsis })
                .maxFontScale(this.maxFontSizeScale)
                .wordBreak(WordBreak.BREAK_ALL)
                .maxLines(1)
            }

            Row() {
              if (!this.isDeviceLevel) {
                SymbolGlyph($r('sys.symbol.checkmark'))
                  .fontSize('24vp')
                  .fontColor((this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
                    [$r('sys.color.comp_background_emphasize')] : [$r('sys.color.icon_primary')])
              }
            }
            .width(48)
            .height(48)
            .justifyContent(FlexAlign.End)
          }
          .margin({ left: 12, right: 12 })
        }
        .margin({ left: 4, right: 4 })
      }
      .width(224)
      .height(48)
      .onClick(() => {
        this.isDeviceLevel = false
        if (this.extensionProxy != null) {
           this.extensionProxy.send({'castMode': HiPlayCastMode.APP_LEVEL});
        }
      })
    }
    .padding({ top: 4, bottom: 4})
  }

@Builder SmallPicIcon(appIcon : image.PixelMap | undefined) {
  Column() {
    Image(appIcon)
      .size({ width: '100%', height: '100%' })
      .backgroundColor('#00ffffff')
      .draggable(false)
      .interpolation(ImageInterpolation.Medium)
      .autoResize(false);
  }
  .clip(true)
  .size({
    width: '16vp',
    height: '16vp'
  })
  .backgroundColor('#00ffffff')
  .borderRadius($r('sys.float.ohos_id_corner_radius_default_xs'))
}
      
  @Builder
  private buildDisabledPicker() {
    Column();
  }

  @Builder
  private buildDefaultPicker(isCustomPicker: boolean) {
    Button() {
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
            'sessionType': this.sessionType,
          }
        })
        .onRemoteReady((proxy: UIExtensionProxy) => {
          console.info(TAG, 'onRemoteReady');
          this.extensionProxy = proxy;
        })
        .onReceive((data) => {
          if (data['deviceInfoType'] !== undefined) {
            console.info(TAG, `deviceInfoType : ${JSON.stringify(data['deviceInfoType'])}`);
            this.deviceInfoType = data['deviceInfoType'] as string;
          }

          if (data['pickerStyle'] !== undefined) {
            console.info(TAG, `picker style : ${JSON.stringify(data['pickerStyle'])}`);
            this.pickerStyleFromMediaController = data['pickerStyle'] as AVCastPickerStyle;
          }

          if (data['deviceList'] !== undefined) {
            console.info(TAG, `picker device list : ${JSON.stringify(data['deviceList'])}`);
            this.deviceList = JSON.parse(JSON.stringify(data['deviceList']));
            let hasOnlySpeakerAndEarpiece: boolean = this.deviceList.length === 2 &&
              !this.hasExtDevice(this.deviceList);
            let hasNoDevices: boolean = this.deviceList === null || this.deviceList.length === 0;
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

          if (data['fontSizeScale'] !== undefined) {
            console.info(TAG, `font size scale : ${JSON.stringify(data['fontSizeScale'])}`);
            this.fontSizeScale = data['fontSizeScale'] as number;
          }

          if (data['state'] !== undefined) {
            console.info(TAG, `picker state change : ${JSON.stringify(data['state'])}`);
            let isCalling: boolean = (this.sessionType === 'voice_call' || this.sessionType === 'video_call');
            let isPanelForMedia: boolean = !isCalling &&
              (this.pickerStyle === AVCastPickerStyle.STYLE_PANEL &&
              this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_PANEL);
            if (this.onStateChange != null && isPanelForMedia) {
              if (parseInt(JSON.stringify(data['state'])) === AVCastPickerState.STATE_APPEARING) {
                this.onStateChange(AVCastPickerState.STATE_APPEARING);
              } else {
                this.onStateChange(AVCastPickerState.STATE_DISAPPEARING);
              }
            }
          }

          if (data['sessionType'] !== undefined) {
            console.info(TAG, `session type : ${JSON.stringify(data['sessionType'])}`);
            this.sessionType = data['sessionType'] as string;
          }

          if (data['isShowMenu'] !== undefined) {
            console.info(TAG, `isShowMenu : ${JSON.stringify(data['isShowMenu'])}`);
            this.isMenuShow = data['isShowMenu'] as boolean;
            if (!this.isMenuShow) {
              this.touchMenuItemIndex = -1;
            }
          }

          if (data['configurationColorMode'] !== undefined) {
            console.info(TAG, `configurationColorMode : ${JSON.stringify(data['configurationColorMode'])}`);
            this.configurationColorMode = data['configurationColorMode'] as number;
          }

          if (data['accessAudioControl'] !== undefined) {
            console.info(TAG, `accessAudioControl : ${JSON.stringify(data['accessAudioControl'])}`);
            this.accessibilityAudioControlStr = data['accessAudioControl'] as string;
          }

          if (data['isPc'] !== undefined) {
            console.info(TAG, `isPc : ${JSON.stringify(data['isPc'])}`);
            this.isPc = data['isPc'] as boolean;
          }

          if (data['isRTL'] !== undefined) {
            console.info(TAG, `isRTL : ${JSON.stringify(data['isRTL'])}`);
            this.isRTL = data['isRTL'] as boolean;
          }

          if (data['maxFontSizeScale'] !== undefined) {
            console.info(TAG, `maxFontSizeScale : ${JSON.stringify(data['maxFontSizeScale'])}`);
            this.maxFontSizeScale = data['maxFontSizeScale'] as number;
          }

          if (data['isShowLoadingProgress'] !== undefined) {
            console.info(TAG, `isShowLoadingProgress : ${JSON.stringify(data['isShowLoadingProgress'])}`);
            this.isShowLoadingProgress = data['isShowLoadingProgress'] as boolean;
          }

          if (data['textParams'] !== undefined) {
            console.info(TAG, `textParams : ${JSON.stringify(data['textParams'])}`);
            this.textParams = data['textParams'] as TextParams;
          }

          if (data['isAncoSession'] !== undefined) {
            console.info(TAG, `isAncoSession : ${JSON.stringify(data['isAncoSession'])}`);
            this.isAncoSession = data['isAncoSession'] as boolean;
          }

          if (data['roomList'] !== undefined) {
            console.info(TAG, `roomlist : ${JSON.stringify(data['roomList'])}`);
            this.roomListService = JSON.parse(JSON.stringify(data['roomList']));
          }

          if (data['HomeMusicPlayTaskId'] !== undefined) {
            console.info(TAG, `playTaskId : ${JSON.stringify(data['HomeMusicPlayTaskId'])}`);
            this.playTaskIdStr = data['HomeMusicPlayTaskId'] as string;
          }

          if (data['keyInputEven'] !== undefined) {
            console.info(TAG, `keyInputEven : ${JSON.stringify(data['keyInputEven'])}`);
            let keyInputOpt: number = data['keyInputEven'] as number;
            this.syncToRoomVolume(keyInputOpt);
            this.sendAllRoomVolumeToController();
            this.roomMaxVolume = this.findRoomMaxVolume();
            this.roomMaxVolumeChange();
          }

          if (data['houseMusicTitleGroup'] !== undefined) {
            console.info(TAG, `houseMusicTitleGroup : ${JSON.stringify(data['houseMusicTitleGroup'])}`);
            let houseMusicTitleGroup: string[] = JSON.parse(JSON.stringify(data['houseMusicTitleGroup']));
            this.houseMusicTitle = houseMusicTitleGroup[0];
            this.houseMusicPlay = houseMusicTitleGroup[1];
            this.houseMusicPlayCancel = houseMusicTitleGroup[2];
          }

          if (data['HomeMusicScanStatus'] !== undefined) {
            console.info(TAG, `HomeMusicScanStatus : ${JSON.stringify(data['HomeMusicScanStatus'])}`);
            this.scanStatus = data['HomeMusicScanStatus'] as number;
          }
        })
        .size({ width: '100%', height: '100%' })
        .bindMenu(
          this.isSubMenuExpanded? this.isSubMenuExpanded : this.isMenuShow,
          this.isSubMenuExpanded? this.castModeMenu() : this.deviceAndHouseMusicSys(),
          {
          backgroundBlurStyle: BlurStyle.NONE,
          placement: Placement.BottomRight,
          showInSubWindow: false,
          enableHoverMode: true,
          onDisappear: () => {
            if (this.isSubMenuExpanded) {
              this.isSubMenuExpanded = false;
              this.isMenuShow = true;
              this.menuShowStateCallback(this.isMenuShow);
            } else {
              this.isMenuShow = false;
              this.touchMenuItemIndex = -1;
              this.menuShowStateCallback(this.isMenuShow);
            }
            if (this.isSwitch) {
              this.isSubMenuExpanded = true;
              this.isSwitch = false;
              }
          },
          onAppear: () => {
            if (this.isSubMenuExpanded) {
              this.isMenuShow = false;
              this.touchMenuItemIndex = -1;
              this.menuShowStateCallback(this.isMenuShow);
            } else {
              if (this.extensionProxy != null && this.pickerClickTime !== -1) {
                this.extensionProxy.send({ 'timeCost': new Date().getTime() - this.pickerClickTime });
                this.pickerClickTime = -1;
              }
              this.menuShowStateCallback(this.isMenuShow);
            }
          }
        })
        .onRelease((releaseCode) => {
          console.error(TAG, `onRelease code ${releaseCode}`);
          if (releaseCode === 1) {
            this.needToRestart = true;
          }
        })
        .onError(() => {
          console.error(TAG, 'onError ready to restart');
          this.needToRestart = true;
        })
      }
      .accessibilityLevel('no-hide-descendants')
      .size({ width: '100%', height: '100%' })
    }
    .hoverEffect(HoverEffect.None)
    .backgroundColor('#00000000')
    .stateEffect(false)
    .size({ width: '100%', height: '100%' })
    .accessibilityLevel('yes')
    .accessibilityText(this.accessibilityAudioControlStr)
    .onClick(() => {
        if (this.needToRestart) {
          this.needToRestart = false;
          this.restartUECMessage += 1;
          return;
        }
        let hasOnlySpeakerAndEarpiece: boolean = this.deviceList.length === 2 && !this.hasExtDevice(this.deviceList);
        let hasNoDevices: boolean = this.deviceList === null || this.deviceList.length === 0;
        let isCalling: boolean = this.sessionType === 'voice_call' || this.sessionType === 'video_call';
        let isExtMenuScene: boolean = isCalling && (hasNoDevices || hasOnlySpeakerAndEarpiece);
        let isPanelForMedia: boolean = !isCalling &&
          (this.pickerStyle === AVCastPickerStyle.STYLE_PANEL &&
            this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_PANEL);
        if (isExtMenuScene || isPanelForMedia) {
          this.isMenuShow = false;
          this.touchMenuItemIndex = -1;
          if (this.extensionProxy != null) {
            this.extensionProxy.send({'clickEvent': true});
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
    for (let i = 0; i < allDevice.length; i++) {
      let isEarpieceOrSpeaker: boolean = (allDevice[i].deviceType === 1 || allDevice[i].deviceType === 2) &&
        allDevice[i].networkId === 'LocalDevice';
      if (!isEarpieceOrSpeaker) {
        return true;
      }
    }
    return false;
  }

  private menuShowStateCallback(isMenuShow: boolean): void {
    if (this.onStateChange != null &&
      (this.pickerStyle === AVCastPickerStyle.STYLE_MENU ||
      this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_MENU)) {
      let menuShowState: AVCastPickerState = isMenuShow ?
        AVCastPickerState.STATE_APPEARING : AVCastPickerState.STATE_DISAPPEARING;
      this.onStateChange(menuShowState);
    }
  }

  @Builder
  private buildCustomPicker() {
    Stack({ alignContent: Alignment.Center}) {
      Column() {
        if (this.isShowLoadingProgress) {
          LoadingProgress()
            .color(this.activeColor === 'liveCardLoadingColor' ? '#FFFFFFFF' : $r('sys.color.icon_secondary'))
            .width('20vp')
            .height('20vp')
        } else {
          this.customPicker();
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

@Extend(Text) function highQualityStyles(maxScale: number) {
  .fontFamily('HarmonyOS Sans SC 2025')
  .fontSize(10)
  .fontWeight(FontWeight.Medium)
  .fontColor($r('sys.color.font_secondary'))
  .maxFontScale(maxScale)
}