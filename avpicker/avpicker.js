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

if (!('finalizeConstruction' in ViewPU.prototype)) {
    Reflect.set(ViewPU.prototype, 'finalizeConstruction', () => { });
}

const TAG = 'avcastpicker_component ';
const castPlusAudioType = 8;
const t = 20;
const HIGH_QUALITY_MAX_SCALE = 1.5;

export let AVCastPickerState;
(function(l11) {
    l11[l11.STATE_APPEARING = 0] = 'STATE_APPEARING';
    l11[l11.STATE_DISAPPEARING = 1] = 'STATE_DISAPPEARING';
})(AVCastPickerState || (AVCastPickerState = {}));

export let AVCastPickerStyle;
(function(k11) {
    k11[k11.STYLE_PANEL = 0] = 'STYLE_PANEL';
    k11[k11.STYLE_MENU = 1] = 'STYLE_MENU';
})(AVCastPickerStyle || (AVCastPickerStyle = {}));

export let DeviceSource;
(function(j11) {
    j11[j11.LOCAL = 0] = 'LOCAL';
    j11[j11.CAST = 1] = 'CAST';
})(DeviceSource || (DeviceSource = {}));

export let ConfigurationColorMode;
(function(u11) {
    u11[u11.COLOR_MODE_NOT_SET = -1] = 'COLOR_MODE_NOT_SET';
    u11[u11.COLOR_MODE_DARK = 0] = 'COLOR_MODE_DARK';
    u11[u11.COLOR_MODE_LIGHT = 1] = 'COLOR_MODE_LIGHT';
})(ConfigurationColorMode || (ConfigurationColorMode = {}));

export let AVCastPickerColorMode;
(function(v11) {
    v11[v11.AUTO = 0] = 'AUTO';
    v11[v11.DARK = 1] = 'DARK';
    v11[v11.LIGHT = 2] = 'LIGHT';
})(AVCastPickerColorMode || (AVCastPickerColorMode = {}));

export let HiPlayCastMode;
(function(w11) {
    w11[w11.DEVICE_LEVEL = 1] = 'DEVICE_LEVEL';
    w11[w11.APP_LEVEL = 2] = 'APP_LEVEL';
})(HiPlayCastMode || (HiPlayCastMode = {}));

export let KeyInputCode;
(function (i3) {
    i3[i3.KEYCODE_VOLUME_UP = 16] = 'KEYCODE_VOLUME_UP';
    i3[i3.KEYCODE_VOLUME_DOWN = 17] = 'KEYCODE_VOLUME_DOWN';
})(KeyInputCode || (KeyInputCode = {}));

export class AVCastPicker extends ViewPU {
    constructor(d11, e11, f11, g11 = -1, h11 = undefined, i11) {
        super(d11, f11, g11, i11);
        if (typeof h11 === 'function') {
            this.paramsGenerator_ = h11;
        }
        this.__normalColor = new ObservedPropertySimplePU(undefined, this, 'normalColor');
        this.__activeColor = new ObservedPropertySimplePU(undefined, this, 'activeColor');
        this.__colorMode = new ObservedPropertySimplePU(AVCastPickerColorMode.AUTO, this, 'colorMode');
        this.__deviceList = new ObservedPropertyObjectPU([], this, 'deviceList');
        this.__fontSizeScale = new ObservedPropertyObjectPU(1, this, 'fontSizeScale');
        this.__sessionType = new ObservedPropertySimplePU('audio', this, 'sessionType');
        this.__pickerStyle = new ObservedPropertySimplePU(AVCastPickerStyle.STYLE_PANEL, this, 'pickerStyle');
        this.__pickerStyleFromMediaController =
            new ObservedPropertySimplePU(AVCastPickerStyle.STYLE_PANEL, this, 'pickerStyleFromMediaController');
        this.__isMenuShow = new ObservedPropertySimplePU(false, this, 'isMenuShow');
        this.__touchMenuItemIndex = new ObservedPropertySimplePU(-1, this, 'touchMenuItemIndex');
        this.__textParams = new ObservedPropertyObjectPU({}, this, 'textParams');
        this.__isAncoSession = new ObservedPropertySimplePU(false, this, 'isAncoSession');
        this.onStateChange = undefined;
        this.extensionProxy = null;
        this.pickerClickTime = -1;
        this.customPicker = undefined;
        this.__configurationColorMode =
            new ObservedPropertySimplePU(ConfigurationColorMode.COLOR_MODE_NOT_SET, this, 'configurationColorMode');
        this.__deviceInfoType = new ObservedPropertySimplePU('', this, 'deviceInfoType');
        this.__maxFontSizeScale = new ObservedPropertySimplePU(1, this, 'maxFontSizeScale');
        this.__accessibilityAudioControlStr = new ObservedPropertySimplePU('音视频投播', this, 'accessibilityAudioControlStr');
        this.__houseMusicTitle = new ObservedPropertySimplePU('', this, 'houseMusicTitle');
        this.__houseMusicPlay = new ObservedPropertySimplePU('', this, 'houseMusicPlay');
        this.__houseMusicPlayCancel = new ObservedPropertySimplePU('', this, 'houseMusicPlayCancel');
        this.__roomListService = new ObservedPropertyObjectPU([], this, 'roomListService');
        this.__isAllSelecting = new ObservedPropertySimplePU(false, this, 'isAllSelecting');
        this.__timeoutIds = new ObservedPropertyObjectPU([], this, 'timeoutIds');
        this.__playTaskIdStr = new ObservedPropertySimplePU('', this, 'playTaskIdStr');
        this.__roomIsSelect = new ObservedPropertyObjectPU([], this, 'roomIsSelect');
        this.__isSelectRoomListService = new ObservedPropertyObjectPU([], this, 'isSelectRoomListService');
        this.__roomSelectStatusPending = new ObservedPropertyObjectPU([], this, 'roomSelectStatusPending');
        this.__houseMusicIsSelect = new ObservedPropertySimplePU(false, this, 'houseMusicIsSelect');
        this.__scanStatus = new ObservedPropertySimplePU(-1, this, 'scanStatus');
        this.__roomVolumeVisible = new ObservedPropertyObjectPU([], this, 'roomVolumeVisible');
        this.__roomCurrVolume = new ObservedPropertyObjectPU([], this, 'roomCurrVolume');
        this.__roomMaxVolume = new ObservedPropertySimplePU(0, this, 'roomMaxVolume');
        this.__roomItemHeight = new ObservedPropertySimplePU(0, this, 'roomItemHeight');
        this.scroller = new Scroller();
        this.__isShowHomeAudio = new ObservedPropertySimplePU(false, this, 'isShowHomeAudio');
        this.__isPc = new ObservedPropertySimplePU(false, this, 'isPc');
        this.__isRTL = new ObservedPropertySimplePU(false, this, 'isRTL');
        this.__restartUECMessage = new ObservedPropertySimplePU(1, this, 'restartUECMessage');
        this.needToRestart = false;
        this.__isShowLoadingProgress = new ObservedPropertySimplePU(false, this, 'isShowLoadingProgress');
        this.pickerCountOnCreation = 0;
        this.__isDisabledByPickerLimit = new ObservedPropertySimplePU(false, this, 'isDisabledByPickerLimit');
        this.__isDeviceLevel = new ObservedPropertySimplePU(true, this, 'isDeviceLevel');
        this.__isSubMenuExpanded = new ObservedPropertySimplePU(false, this, 'isSubMenuExpanded');
        this.setInitiallyProvidedValue(e11);
        this.declareWatch('isMenuShow', this.MenuStateChange);
        this.declareWatch('isSubMenuExpanded', this.MenuStateChange);
        this.declareWatch('roomListService', this.roomListChange);
        this.declareWatch('playTaskIdStr', this.homeMusicPlayTaskIdChange);
        this.declareWatch('houseMusicIsSelect', this.selectHomeMusicSys);
        this.declareWatch('scanStatus', this.homeMusicScanStatusChange);
        this.finalizeConstruction();
    }

    setInitiallyProvidedValue(c11) {
        if (c11.normalColor !== undefined) {
            this.normalColor = c11.normalColor;
        }
        if (c11.activeColor !== undefined) {
            this.activeColor = c11.activeColor;
        }
        if (c11.colorMode !== undefined) {
            this.colorMode = c11.colorMode;
        }
        if (c11.deviceList !== undefined) {
            this.deviceList = c11.deviceList;
        }
        if (c11.fontSizeScale !== undefined) {
            this.fontSizeScale = c11.fontSizeScale;
        }
        if (c11.sessionType !== undefined) {
            this.sessionType = c11.sessionType;
        }
        if (c11.pickerStyle !== undefined) {
            this.pickerStyle = c11.pickerStyle;
        }
        if (c11.pickerStyleFromMediaController !== undefined) {
            this.pickerStyleFromMediaController = c11.pickerStyleFromMediaController;
        }
        if (c11.isMenuShow !== undefined) {
            this.isMenuShow = c11.isMenuShow;
        }
        if (c11.touchMenuItemIndex !== undefined) {
            this.touchMenuItemIndex = c11.touchMenuItemIndex;
        }
        if (c11.textParams !== undefined) {
            this.textParams = c11.textParams;
        }  
        if (c11.isAncoSession !== undefined) {
            this.isAncoSession = c11.isAncoSession;
        }
        if (c11.onStateChange !== undefined) {
            this.onStateChange = c11.onStateChange;
        }
        if (c11.extensionProxy !== undefined) {
            this.extensionProxy = c11.extensionProxy;
        }
        if (c11.pickerClickTime !== undefined) {
            this.pickerClickTime = c11.pickerClickTime;
        }
        if (c11.customPicker !== undefined) {
            this.customPicker = c11.customPicker;
        }
        if (c11.configurationColorMode !== undefined) {
            this.configurationColorMode = c11.configurationColorMode;
        }
        if (c11.deviceInfoType !== undefined) {
            this.deviceInfoType = c11.deviceInfoType;
        }
        if (c11.maxFontSizeScale !== undefined) {
            this.maxFontSizeScale = c11.maxFontSizeScale;
        }
        if (c11.accessibilityAudioControlStr !== undefined) {
            this.accessibilityAudioControlStr = c11.accessibilityAudioControlStr;
        }
        if (c11.houseMusicTitle !== undefined) {
            this.houseMusicTitle = c11.houseMusicTitle;
        }
        if (c11.houseMusicPlay !== undefined) {
            this.houseMusicPlay = c11.houseMusicPlay;
        }
        if (c11.houseMusicPlayCancel !== undefined) {
            this.houseMusicPlayCancel = c11.houseMusicPlayCancel;
        }
        if (c11.roomListService !== undefined) {
            this.roomListService = c11.roomListService;
        }
        if (c11.isAllSelecting !== undefined) {
            this.isAllSelecting = c11.isAllSelecting;
        }
        if (c11.timeoutIds !== undefined) {
            this.timeoutIds = c11.timeoutIds;
        }
        if (c11.playTaskIdStr !== undefined) {
            this.playTaskIdStr = c11.playTaskIdStr;
        }
        if (c11.roomIsSelect !== undefined) {
            this.roomIsSelect = c11.roomIsSelect;
        }
        if (c11.isSelectRoomListService !== undefined) {
            this.isSelectRoomListService = c11.isSelectRoomListService;
        }
        if (c11.roomSelectStatusPending !== undefined) {
            this.roomSelectStatusPending = c11.roomSelectStatusPending;
        }
        if (c11.houseMusicIsSelect !== undefined) {
            this.houseMusicIsSelect = c11.houseMusicIsSelect;
        }
        if (c11.scanStatus !== undefined) {
            this.scanStatus = c11.scanStatus;
        }
        if (c11.roomVolumeVisible !== undefined) {
            this.roomVolumeVisible = c11.roomVolumeVisible;
        }
        if (c11.roomCurrVolume !== undefined) {
            this.roomCurrVolume = c11.roomCurrVolume;
        }
        if (c11.roomMaxVolume !== undefined) {
            this.roomMaxVolume = c11.roomMaxVolume;
        }
        if (c11.roomItemHeight !== undefined) {
            this.roomItemHeight = c11.roomItemHeight;
        }
        if (c11.scroller !== undefined) {
            this.scroller = c11.scroller;
        }
        if (c11.isShowHomeAudio !== undefined) {
            this.isShowHomeAudio = c11.isShowHomeAudio;
        }
        if (c11.isPc !== undefined) {
            this.isPc = c11.isPc;
        }
        if (c11.isRTL !== undefined) {
            this.isRTL = c11.isRTL;
        }
        if (c11.restartUECMessage !== undefined) {
            this.restartUECMessage = c11.restartUECMessage;
        }
        if (c11.needToRestart !== undefined) {
            this.needToRestart = c11.needToRestart;
        }
        if (c11.isShowLoadingProgress !== undefined) {
            this.isShowLoadingProgress = c11.isShowLoadingProgress;
        }
        if (c11.pickerCountOnCreation !== undefined) {
            this.pickerCountOnCreation = c11.pickerCountOnCreation;
        }
        if (c11.isDisabledByPickerLimit !== undefined) {
            this.isDisabledByPickerLimit = c11.isDisabledByPickerLimit;
        }
        if (c11.isDeviceLevel !== undefined) {
            this.isDeviceLevel = c11.isDeviceLevel;
        }
        if (c11.isSubMenuExpanded !== undefined) {
            this.isSubMenuExpanded = c11.isSubMenuExpanded;
        }
    }

    updateStateVars(b11) {
    }

    purgeVariableDependenciesOnElmtId(a11) {
        this.__normalColor.purgeDependencyOnElmtId(a11);
        this.__activeColor.purgeDependencyOnElmtId(a11);
        this.__colorMode.purgeDependencyOnElmtId(a11);
        this.__deviceList.purgeDependencyOnElmtId(a11);
        this.__fontSizeScale.purgeDependencyOnElmtId(a11);
        this.__sessionType.purgeDependencyOnElmtId(a11);
        this.__pickerStyle.purgeDependencyOnElmtId(a11);
        this.__pickerStyleFromMediaController.purgeDependencyOnElmtId(a11);
        this.__isMenuShow.purgeDependencyOnElmtId(a11);
        this.__touchMenuItemIndex.purgeDependencyOnElmtId(a11);
        this.__textParams.purgeDependencyOnElmtId(a11);
        this.__isAncoSession.purgeDependencyOnElmtId(a11);
        this.__configurationColorMode.purgeDependencyOnElmtId(a11);
        this.__deviceInfoType.purgeDependencyOnElmtId(a11);
        this.__maxFontSizeScale.purgeDependencyOnElmtId(a11);
        this.__accessibilityAudioControlStr.purgeDependencyOnElmtId(a11);
        this.__houseMusicTitle.purgeDependencyOnElmtId(a11);
        this.__houseMusicPlay.purgeDependencyOnElmtId(a11);
        this.__houseMusicPlayCancel.purgeDependencyOnElmtId(a11);
        this.__roomListService.purgeDependencyOnElmtId(a11);
        this.__isAllSelecting.purgeDependencyOnElmtId(a11);
        this.__timeoutIds.purgeDependencyOnElmtId(a11);
        this.__playTaskIdStr.purgeDependencyOnElmtId(a11);
        this.__roomIsSelect.purgeDependencyOnElmtId(a11);
        this.__isSelectRoomListService.purgeDependencyOnElmtId(a11);
        this.__roomSelectStatusPending.purgeDependencyOnElmtId(a11);
        this.__houseMusicIsSelect.purgeDependencyOnElmtId(a11);
        this.__scanStatus.purgeDependencyOnElmtId(a11);
        this.__roomVolumeVisible.purgeDependencyOnElmtId(a11);
        this.__roomCurrVolume.purgeDependencyOnElmtId(a11);
        this.__roomMaxVolume.purgeDependencyOnElmtId(a11);
        this.__roomItemHeight.purgeDependencyOnElmtId(a11);
        this.__isShowHomeAudio.purgeDependencyOnElmtId(a11);
        this.__isPc.purgeDependencyOnElmtId(a11);
        this.__isRTL.purgeDependencyOnElmtId(a11);
        this.__restartUECMessage.purgeDependencyOnElmtId(a11);
        this.__isShowLoadingProgress.purgeDependencyOnElmtId(a11);
        this.__isDisabledByPickerLimit.purgeDependencyOnElmtId(a11);
        this.__isDeviceLevel.purgeDependencyOnElmtId(a11);
        this.__isSubMenuExpanded.purgeDependencyOnElmtId(a11);
    }

    aboutToBeDeleted() {
        this.__normalColor.aboutToBeDeleted();
        this.__activeColor.aboutToBeDeleted();
        this.__colorMode.aboutToBeDeleted();
        this.__deviceList.aboutToBeDeleted();
        this.__fontSizeScale.aboutToBeDeleted();
        this.__sessionType.aboutToBeDeleted();
        this.__pickerStyle.aboutToBeDeleted();
        this.__pickerStyleFromMediaController.aboutToBeDeleted();
        this.__isMenuShow.aboutToBeDeleted();
        this.__touchMenuItemIndex.aboutToBeDeleted();
        this.__textParams.aboutToBeDeleted();
        this.__isAncoSession.aboutToBeDeleted();
        this.__configurationColorMode.aboutToBeDeleted();
        this.__deviceInfoType.aboutToBeDeleted();
        this.__maxFontSizeScale.aboutToBeDeleted();
        this.__accessibilityAudioControlStr.aboutToBeDeleted();
        this.__houseMusicTitle.aboutToBeDeleted();
        this.__houseMusicPlay.aboutToBeDeleted();
        this.__houseMusicPlayCancel.aboutToBeDeleted();
        this.__roomListService.aboutToBeDeleted();
        this.__isAllSelecting.aboutToBeDeleted();
        this.__timeoutIds.aboutToBeDeleted();
        this.__playTaskIdStr.aboutToBeDeleted();
        this.__roomIsSelect.aboutToBeDeleted();
        this.__isSelectRoomListService.aboutToBeDeleted();
        this.__roomSelectStatusPending.aboutToBeDeleted();
        this.__houseMusicIsSelect.aboutToBeDeleted();
        this.__scanStatus.aboutToBeDeleted();
        this.__roomVolumeVisible.aboutToBeDeleted();
        this.__roomCurrVolume.aboutToBeDeleted();
        this.__roomMaxVolume.aboutToBeDeleted();
        this.__roomItemHeight.aboutToBeDeleted();
        this.__isShowHomeAudio.aboutToBeDeleted();
        this.__isPc.aboutToBeDeleted();
        this.__isRTL.aboutToBeDeleted();
        this.__restartUECMessage.aboutToBeDeleted();
        this.__isShowLoadingProgress.aboutToBeDeleted();
        this.__isDisabledByPickerLimit.aboutToBeDeleted();
        this.__isDeviceLevel.aboutToBeDeleted();
        this.__isSubMenuExpanded.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }

    get normalColor() {
        return this.__normalColor.get();
    }

    set normalColor(z10) {
        this.__normalColor.set(z10);
    }

    get activeColor() {
        return this.__activeColor.get();
    }

    set activeColor(y10) {
        this.__activeColor.set(y10);
    }

    get colorMode() {
        return this.__colorMode.get();
    }

    set colorMode(b1) {
        this.__colorMode.set(b1);
    }

    get deviceList() {
        return this.__deviceList.get();
    }

    set deviceList(x10) {
        this.__deviceList.set(x10);
    }

    get fontSizeScale() {
        return this.__fontSizeScale.get();
    }

    set fontSizeScale(x10) {
        this.__fontSizeScale.set(x10);
    }

    get sessionType() {
        return this.__sessionType.get();
    }

    set sessionType(w10) {
        this.__sessionType.set(w10);
    }

    get pickerStyle() {
        return this.__pickerStyle.get();
    }

    set pickerStyle(v10) {
        this.__pickerStyle.set(v10);
    }

    get pickerStyleFromMediaController() {
        return this.__pickerStyleFromMediaController.get();
    }

    set pickerStyleFromMediaController(b1) {
        this.__pickerStyleFromMediaController.set(b1);
    }

    get isMenuShow() {
        return this.__isMenuShow.get();
    }

    set isMenuShow(u10) {
        this.__isMenuShow.set(u10);
    }

    get touchMenuItemIndex() {
        return this.__touchMenuItemIndex.get();
    }

    set touchMenuItemIndex(t10) {
        this.__touchMenuItemIndex.set(t10);
    }

    get textParams() {
        return this.__textParams.get();
    }
 
    set textParams(t10) {
        this.__textParams.set(t10);
    }

    get isAncoSession() {
        return this.__isAncoSession.get();
    }
 
    set isAncoSession(t10) {
        this.__isAncoSession.set(t10);
    }

    get configurationColorMode() {
        return this.__configurationColorMode.get();
    }

    set configurationColorMode(a1) {
        this.__configurationColorMode.set(a1);
    }

    get deviceInfoType() {
        return this.__deviceInfoType.get();
    }

    set deviceInfoType(b1) {
        this.__deviceInfoType.set(b1);
    }

    get maxFontSizeScale() {
        return this.__maxFontSizeScale.get();
    }

    set maxFontSizeScale(e1) {
        this.__maxFontSizeScale.set(e1);
    }

    get accessibilityAudioControlStr() {
        return this.__accessibilityAudioControlStr.get();
    }

    set accessibilityAudioControlStr(d1) {
        this.__accessibilityAudioControlStr.set(d1);
    }

    get houseMusicTitle() {
        return this.__houseMusicTitle.get();
    }

    set houseMusicTitle(newValue) {
        this.__houseMusicTitle.set(newValue);
    }

    get houseMusicPlay() {
        return this.__houseMusicPlay.get();
    }

    set houseMusicPlay(newValue) {
        this.__houseMusicPlay.set(newValue);
    }

    get houseMusicPlayCancel() {
        return this.__houseMusicPlayCancel.get();
    }

    set houseMusicPlayCancel(newValue) {
        this.__houseMusicPlayCancel.set(newValue);
    }

    get roomListService() {
        return this.__roomListService.get();
    }

    set roomListService(newValue) {
        this.__roomListService.set(newValue);
    }

    get isAllSelecting() {
        return this.__isAllSelecting.get();
    }

    set isAllSelecting(newValue) {
        this.__isAllSelecting.set(newValue);
    }

    get timeoutIds() {
        return this.__timeoutIds.get();
    }

    set timeoutIds(newValue) {
        this.__timeoutIds.set(newValue);
    }

    get playTaskIdStr() {
        return this.__playTaskIdStr.get();
    }

    set playTaskIdStr(newValue) {
        this.__playTaskIdStr.set(newValue);
    }

    get roomIsSelect() {
        return this.__roomIsSelect.get();
    }

    set roomIsSelect(newValue) {
        this.__roomIsSelect.set(newValue);
    }

    get isSelectRoomListService() {
        return this.__isSelectRoomListService.get();
    }

    set isSelectRoomListService(newValue) {
        this.__isSelectRoomListService.set(newValue);
    }

    get roomSelectStatusPending() {
        return this.__roomSelectStatusPending.get();
    }

    set roomSelectStatusPending(newValue) {
        this.__roomSelectStatusPending.set(newValue);
    }

    get houseMusicIsSelect() {
        return this.__houseMusicIsSelect.get();
    }

    set houseMusicIsSelect(newValue) {
        this.__houseMusicIsSelect.set(newValue);
    }

    get scanStatus() {
        return this.__scanStatus.get();
    }

    set scanStatus(newValue) {
        this.__scanStatus.set(newValue);
    }

    get roomVolumeVisible() {
        return this.__roomVolumeVisible.get();
    }

    set roomVolumeVisible(newValue) {
        this.__roomVolumeVisible.set(newValue);
    }

    get roomCurrVolume() {
        return this.__roomCurrVolume.get();
    }

    set roomCurrVolume(newValue) {
        this.__roomCurrVolume.set(newValue);
    }

    get roomMaxVolume() {
        return this.__roomMaxVolume.get();
    }

    set roomMaxVolume(newValue) {
        this.__roomMaxVolume.set(newValue);
    }

    get roomItemHeight() {
        return this.__roomItemHeight.get();
    }

    set roomItemHeight(newValue) {
        this.__roomItemHeight.set(newValue);
    }

    get isShowHomeAudio() {
        return this.__isShowHomeAudio.get();
    }

    set isShowHomeAudio(newValue) {
        this.__isShowHomeAudio.set(newValue);
    }

    get isPc() {
        return this.__isPc.get();
    }

    set isPc(e1) {
        this.__isPc.set(e1);
    }

    get isRTL() {
        return this.__isRTL.get();
    }

    set isRTL(f1) {
        this.__isRTL.set(f1);
    }

    get restartUECMessage() {
        return this.__restartUECMessage.get();
    }

    set restartUECMessage(f1) {
        this.__restartUECMessage.set(f1);
    }

    get isShowLoadingProgress() {
        return this.__isShowLoadingProgress.get();
    }

    set isShowLoadingProgress(g1) {
        this.__isShowLoadingProgress.set(g1);
    }

    get isDisabledByPickerLimit() {
        return this.__isDisabledByPickerLimit.get();
    }

    set isDisabledByPickerLimit(g1) {
        this.__isDisabledByPickerLimit.set(g1);
    }

    get isDeviceLevel() {
        return this.__isDeviceLevel.get();
    }
    set isDeviceLevel(h1) {
        this.__isDeviceLevel.set(h1);
    }
 
    get isSubMenuExpanded() {
        return this.__isSubMenuExpanded.get();
    }
    set isSubMenuExpanded(i1) {
        this.__isSubMenuExpanded.set(i1);
    }

    aboutToAppear() {
        AVCastPicker.currentPickerCount += 1;
        this.pickerCountOnCreation = AVCastPicker.currentPickerCount;
        if (this.pickerCountOnCreation > t) {
            console.info(TAG, 'disable picker');
            this.isDisabledByPickerLimit = true;
        }
    }

    aboutToDisappear() {
        AVCastPicker.currentPickerCount -= 1;
        this.timeoutIds.forEach((id) => {
            clearTimeout(id);
        });
        this.timeoutIds = [];
    }

    MenuStateChange() {
        if (this.extensionProxy != null) {
            this.extensionProxy.send({ 'isMenuShow': this.isMenuShow });
            this.extensionProxy.send({ 'isSubMenuExpanded': this.isSubMenuExpanded });
            let d3 = (this.isMenuShow && this.houseMusicIsSelect);
            this.extensionProxy.send({ 'isSelectHomeMusicSys': d3 });
        }
    }

    showHighQuality(item) {
        if (item.supportedProtocols === undefined) {
            return false;
        }
        return (item.supportedProtocols & castPlusAudioType) !== 0;
    }

    createNullRoomService() {
        return [{ 'st': '', 'ts': '', 'sid': '', 'data': { 'bassWeight': 0, 'playTask': '', 'acousticsMode': 0, 'volumePercentage': 0, 'description': 0,
            'supportMusicLed': false, 'label': '', 'type': 0, 'roomId': '', 'limitedVolume': 0, 'volume': 0, 'faultCode': 0, 'supportStereo': 0,
            'playState': 0, 'speakerList': '', 'enable': 0, 'name': '', 'zoneId': '' } }];
    }

    refreshRoomList() {
        this.timeoutIds.forEach((id) => {
            clearTimeout(id);
        });
        this.timeoutIds = [];
        let k3 = this.roomListService;
        let w1 = true;
        let l2 = false;
        let o2 = 0;
        this.isShowHomeAudio = (k3.length > 0) ? true : false;
        for (let z1 = 0; z1 < k3.length; z1++) {
            this.roomSelectStatusPending[z1] = false;
            this.roomIsSelect[z1] = ((k3[z1].data.playTask === this.playTaskIdStr) &&
                (this.playTaskIdStr !== '')) ? true : false;
            this.roomCurrVolume[z1] = k3[z1].data.volume;
            this.roomVolumeVisible[z1] = this.roomIsSelect[z1] ? Visibility.Visible : Visibility.None;
            if (!this.roomIsSelect[z1]) {
                w1 = false;
            } else {
                l2 = true;
                if (o2 < k3[z1].data.volume) {
                    o2 = k3[z1].data.volume;
                }
            }
        }
        if (w1 && k3.length > 0) {
            this.isAllSelecting = true;
        }
        else {
            this.isAllSelecting = false;
        }
        this.houseMusicIsSelect = l2;
        if (l2) {
            this.roomMaxVolume = o2;
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
            let w2 = (this.isMenuShow && this.houseMusicIsSelect);
            this.extensionProxy.send({ 'isSelectHomeMusicSys': w2 });
        }
    }
    homeMusicScanStatusChange() {
        if (this.scanStatus === 0) {
            this.setAllRoomSelectStatusPending();
        }
        else {
            this.roomSelectStatusPendingInit();
        }
    }
    roomMaxVolumeChange() {
        if (this.extensionProxy != null) {
            this.extensionProxy.send({ 'homeMusicMaxVolumeSync': this.roomMaxVolume });
        }
    }
    findRoomMaxVolume() {
        let k2 = 0;
        for (let l2 = 0; l2 < this.roomListService.length; l2++) {
            if ((k2 < this.roomListService[l2].data.volume) && this.checkRoomIsSelect(l2)) {
                k2 = this.roomListService[l2].data.volume;
            }
        }
        return k2;
    }

    checkRoomIsSelect(index) {
        if ((this.roomListService[index].data.playTask === this.playTaskIdStr) &&
            (this.playTaskIdStr !== '')) {
            return true;
        }
        return false;
    }
    getCurrIsAllSelectStatus() {
        let c2 = true;
        for (let d2 = 0; d2 < this.roomListService.length; d2++) {
            if (!this.checkRoomIsSelect(d2)) {
                c2 = false;
            }
        }
        if (c2 && (this.roomListService.length > 0)) {
            return true;
        }
        return false;
    }
    roomSelectStatusPendingInit() {
        for (let b2 = 0; b2 < this.roomListService.length; b2++) {
            this.roomSelectStatusPending[b2] = false;
        }
    }
    setAllRoomSelectStatusPending() {
        for (let a2 = 0; a2 < this.roomListService.length; a2++) {
            this.roomSelectStatusPending[a2] = true;
        }
    }
    getCurrSelectRoom(index, e2) {
        this.isSelectRoomListService.length = 0;
        for (let f2 = 0; f2 < this.roomListService.length; f2++) {
            if (f2 === index) {
                if (e2) {
                    this.isSelectRoomListService.push(this.roomListService[index]);
                }
                continue;
            }
            if (this.checkRoomIsSelect(f2)) {
                this.isSelectRoomListService.push(this.roomListService[f2]);
            }
        }
    }
    onSliderValueChange(index, value, mode) {
        switch (mode) {
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
    syncToRoomVolume(input) {
        let h2 = 0;
        let i2 = 10;
        let j2 = 15;
        for (let k2 = 0; k2 < this.roomListService.length; k2++) {
            if (!this.checkRoomIsSelect(k2)) {
                continue;
            }
            let l2 = Math.round(this.roomListService[k2].data.volume * 3 / 2 / i2);
            let m2 = (input === KeyInputCode.KEYCODE_VOLUME_UP) ? l2 + 1 : l2 - 1;
            if (m2 <= h2) {
                m2 = h2;
            }
            else if (m2 < h2 + 1) {
                m2 = h2 + 1;
            }
            else if (m2 >= j2) {
                m2 = j2;
            }
            else if (m2 > j2 - 1) {
                m2 = j2 - 1;
            }
            else {
                m2 = Math.round(m2);
            }
            this.roomListService[k2].data.volume = Math.round(m2 * i2 * 2 / 3);
            this.roomCurrVolume[k2] = this.roomListService[k2].data.volume;
        }
    }
    sendAllRoomVolumeToController() {
        if (this.extensionProxy != null) {
            for (let h2 = 0; h2 < this.roomListService.length; h2++) {
                this.roomListService[h2].data.description = h2 + 1;
                this.extensionProxy.send({ 'roomVolumeChange': this.roomListService[h2] });
            }
        }
    }
    allSelectOnClickEven() {
        this.setAllRoomSelectStatusPending();
        const d2 = setTimeout(() => {
            this.roomSelectStatusPendingInit();
        }, 3000);
        if (typeof d2 === 'number') {
            this.timeoutIds.push(d2);
        }
        if (this.extensionProxy != null) {
            if (!this.getCurrIsAllSelectStatus()) {
                this.extensionProxy.send({ 'roomSelectChange': this.roomListService });
                this.extensionProxy.send({ 'roomIsSelectAll': true });
            }
            else {
                this.extensionProxy.send({ 'roomSelectChange': this.createNullRoomService() });
                this.extensionProxy.send({ 'roomIsSelectAll': false });
            }
        }
    }

    initialRender() {
        this.observeComponentCreation2((r10, s10) => {
            Column.create();
            Column.size({ width: '100%', height: '100%'});
        }, Column);
        this.observeComponentCreation2((n10, o10) => {
            If.create();
            if (this.isDisabledByPickerLimit) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.buildDisabledPicker.bind(this)();
                });
            } else if (this.customPicker === undefined) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.buildDefaultPicker.bind(this)(false);
                });
            } else {
                this.ifElseBranchUpdateFunction(1, () => {
                    this.buildCustomPicker.bind(this)();
                });
            }
        }, If);
        If.pop();
        Column.pop();
    }

    iconBuilder(b3, c3, d3 = null) {
        this.observeComponentCreation2((f3, g3) => {
            If.create();
            if (this.deviceInfoType === 'true') {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((n3, o3) => {
                        SymbolGlyph.create(!c3 ? { 'id': -1, 'type': -1, params: [b3.deviceIconName],
                            'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' } :
                            { 'id': -1, 'type': -1, params: [b3.selectedIconName],
                            'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                        SymbolGlyph.fontSize('24vp');
                        SymbolGlyph.fontColor((c3 && this.configurationColorMode !==
                            ConfigurationColorMode.COLOR_MODE_DARK) ?
                            [{ 'id': -1, 'type': 10001, params: ['sys.color.comp_background_emphasize'],
                            'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }] :
                            [{ 'id': -1, 'type': 10001, params: ['sys.color.icon_primary'],
                            'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }]);
                        SymbolGlyph.renderingStrategy(2);
                    }, SymbolGlyph);
                });
            } else {
                this.ifElseBranchUpdateFunction(1, () => {
                    this.observeComponentCreation2((j3, k3) => {
                        Image.create(!c3 ? { 'id': -1, 'type': -1,
                            params: [b3.deviceIconName], 'bundleName': '__harDefaultBundleName__',
                            'moduleName': '__harDefaultModuleName__' } : { 'id': -1, 'type': -1, params: [b3.selectedIconName],
                            'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                        Image.width(24);
                        Image.height(24);
                        Image.fillColor((c3 && this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
                            { 'id': -1, 'type': 10001, params: ['sys.color.comp_background_emphasize'],
                            'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' } :
                            { 'id': -1, 'type': 10001, params: ['sys.color.icon_primary'],
                            'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                    }, Image);
                });
            }
        }, If);
        If.pop();
    }

    textBuilder(u1, v1 = null) {
        this.observeComponentCreation2((x1, y1) => {
            Text.create(u1.deviceName);
            Text.fontSize({ 'id': -1, 'type': 10002,
                params: ['sys.float.ohos_id_text_size_body2'], 'bundleName': '__harDefaultBundleName__',
                'moduleName': '__harDefaultModuleName__' });
            Text.fontColor((u1.isConnected && !this.houseMusicIsSelect) ?
                (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ? 
                { 'id': -1, 'type': 10001, params: ['sys.color.comp_background_emphasize'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' } :
                { 'id': -1, 'type': 10001, params: ['sys.color.font_primary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }) :
                (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ? 
                { 'id': -1, 'type': 10001, params: ['sys.color.font_primary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' } :
                { 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }));
            Text.textOverflow({ overflow: TextOverflow.Ellipsis });
            Text.maxLines(2);
            Text.wordBreak(WordBreak.BREAK_WORD);
            Text.maxFontScale(this.maxFontSizeScale);
            Text.direction(this.isRTL ? Direction.Rtl : Direction.Ltr);
        }, Text);
        Text.pop();
    }

    subTextBuilder(u3, v1 = null) {
        this.observeComponentCreation2((x1, y1) => {
            Row.create();
            Row.width('100%');
        }, Row);
        this.observeComponentCreation2((x1, y1) => {
            Text.create(u3.deviceSubName || '');
            Text.fontSize({ 'id': -1, 'type': 10002,
                params: ['sys.float.ohos_id_text_size_body2'], 'bundleName': '__harDefaultBundleName__',
                'moduleName': '__harDefaultModuleName__' });
            Text.fontColor((u3.isConnected && !this.houseMusicIsSelect) ?
                (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ? 
                { 'id': -1, 'type': 10001, params: ['sys.color.font_emphasize'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' } :
                { 'id': -1, 'type': 10001, params: ['sys.color.font_primary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }) :
                (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK ? 
                { 'id': -1, 'type': 10001, params: ['sys.color.font_primary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' } :
                { 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }));
            Text.textOverflow({ overflow: TextOverflow.Ellipsis });
            Text.maxLines(1);
            Text.maxFontScale(this.maxFontSizeScale);
            Text.direction(this.isRTL ? Direction.Rtl : Direction.Ltr);
        }, Text);
        Text.pop();
        Row.pop();
    }

    highQualityIconBuilder(u2, v1 = null) {
        Row.create();
        Row.direction(Direction.Ltr);
        this.observeComponentCreation2((x1, y1) => {
            Text.create(u2 ? u2.iconLeft : '');
            Text.fontFamily('HarmonyOS Sans SC 2025');
            Text.fontSize(10);
            Text.fontWeight(FontWeight.Medium);
            Text.fontColor({ 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.maxFontScale(Math.min(HIGH_QUALITY_MAX_SCALE, this.maxFontSizeScale));
        }, Text);
        Text.pop();
        this.observeComponentCreation2((x1, y1) => {
            Text.create(u2 ? u2.iconRight : '');
            Text.fontFamily('HarmonyOS Sans SC 2025');
            Text.fontSize(10);
            Text.fontWeight(FontWeight.Medium);
            Text.fontColor({ 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.maxFontScale(Math.min(HIGH_QUALITY_MAX_SCALE, this.maxFontSizeScale));
            Text.margin({left: 2 * (Math.min(HIGH_QUALITY_MAX_SCALE, this.fontSizeScale))});
        }, Text);
        Text.pop();
        Row.pop();
    }

    deviceMenu(o8 = null) {
        this.observeComponentCreation2((j10, k10) => {
            Column.create();
            Column.width(this.isPc ? 326 : 216);
            Column.borderRadius(this.isPc ? 8 : 20);
            Column.backgroundColor(this.isShowHomeAudio ? { 'id': -1, 'type': 10001,
                params: ['sys.color.background_primary'], 'bundleName': '__harDefaultBundleName__',
                'moduleName': '__harDefaultModuleName__' } : '#00000000');
        }, Column);
        this.observeComponentCreation2((r8, s8) => {
            ForEach.create();
            const t8 = (v8, w8) => {
                const x8 = v8;
                this.observeComponentCreation2((g10, h10) => {
                    Flex.create({
                        direction: FlexDirection.Column,
                        justifyContent: FlexAlign.SpaceBetween,
                        alignItems: ItemAlign.End
                    });
                    Flex.width('100%');
                    Flex.onClick(() => {
                        if (this.extensionProxy != null && this.houseMusicIsSelect) {
                            this.setAllRoomSelectStatusPending();
                            const s2 = setTimeout(() => {
                                this.roomSelectStatusPendingInit();
                            }, 3000);
                            if (typeof s2 === 'number') {
                                this.timeoutIds.push(s2);
                            }
                            this.extensionProxy.send({ 'roomSelectChange': this.createNullRoomService() });
                        }
                        if (this.extensionProxy != null && !x8.isConnected) {
                            this.extensionProxy.send({ 'selectedDeviceInfo': x8 });
                        }
                    });
                    Flex.accessibilityGroup(true);
                    Flex.accessibilitySelected(x8.isConnected);
                }, Flex);
                this.observeComponentCreation2((c10, d10) => {
                    Flex.create({
                        direction: FlexDirection.Row,
                        justifyContent: FlexAlign.SpaceBetween,
                        alignItems: ItemAlign.Center
                    });
                    Flex.constraintSize({ minHeight: this.isPc ? 40 : 48 });
                    Flex.padding({ left: 12, right: 12 });
                    Flex.onTouch((f10) => {
                        if (f10.type === TouchType.Down) {
                            this.touchMenuItemIndex = w8;
                        }
                        else if (f10.type === TouchType.Up) {
                            this.touchMenuItemIndex = -1;
                        }
                    });
                    Flex.backgroundColor(this.touchMenuItemIndex === w8 ? { 'id': -1, 'type': 10001,
                        params: ['sys.color.interactive_click'], 'bundleName': '__harDefaultBundleName__',
                        'moduleName': '__harDefaultModuleName__' } : '#00FFFFFF');
                    Flex.borderRadius(this.touchMenuItemIndex === w8 ? (this.isPc ? { 'id': -1, 'type': 10002,
                        params: ['sys.float.corner_radius_level2'], 'bundleName': '__harDefaultBundleName__',
                        'moduleName': '__harDefaultModuleName__' } : { 'id': -1, 'type': 10002,
                        params: ['sys.float.corner_radius_level8'], 'bundleName': '__harDefaultBundleName__',
                        'moduleName': '__harDefaultModuleName__' }) : 0);
                }, Flex);
                this.observeComponentCreation2((a10, b10) => {
                    Row.create();
                    Row.alignItems(VerticalAlign.Center);
                }, Row);
                this.iconBuilder.bind(this)(x8, false);

                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    Flex.create({ direction: FlexDirection.Column, justifyContent: FlexAlign.Start });
                    Flex.width(this.isPc ? 254 : 144);
                    Flex.padding({
                        left: 8,
                        top: this.isPc ? 11 : (this.showHighQuality(x8) ? 7 : 17),
                        right: 8,
                        bottom: this.isPc ? 11 : (this.showHighQuality(x8) ? 7 : 17),
                    });
                }, Flex);
                this.textBuilder.bind(this)(x8);
                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    If.create();
                    if (x8.fromCall) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.subTextBuilder.bind(this)(x8);
                        });
                    }
                    else if (x8.highQualityParams !== undefined && this.showHighQuality(x8)) {
                        this.ifElseBranchUpdateFunction(1, () => {
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                Flex.create();
                                Flex.borderRadius(4);
                                Flex.border({
                                    width: Math.min(HIGH_QUALITY_MAX_SCALE, this.fontSizeScale),
                                    color: { 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                                        'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }
                                });
                                Flex.padding({
                                    top: 2.5,
                                    right: 4,
                                    bottom: 2.5,
                                    left: 4
                                });
                                Flex.margin({ top: 4 });
                                Flex.width('auto');
                            }, Flex);
                            this.highQualityIconBuilder.bind(this)(x8.highQualityParams);
                            Flex.pop();
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                If.create();
                                if ((x8.isConnected || x8.castUid !== 0) && x8.supportCastMode === HiPlayCastMode.DEVICE_LEVEL) {
                                    this.ifElseBranchUpdateFunction(0, () => {
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Flex.create({
                                                direction: FlexDirection.Row,
                                                alignItems: ItemAlign.Center
                                            });
                                            Flex.onClick(() => {
                                                if (x8.isConnected && !this.isAncoSession) {
                                                    this.isDeviceLevel = (x8.castMode === HiPlayCastMode.DEVICE_LEVEL);
                                                    if (this.extensionProxy != null) {
                                                        this.extensionProxy.send({ 'isShowBadge': false})
                                                    }
                                                    if (!this.isSubMenuExpanded) {
                                                        this.isMenuShow = false;
                                                        this.isSubMenuExpanded = true;
                                                    }
                                                }
                                            });
                                            Flex.accessibilityLevel('yes');
                                            Flex.accessibilityText(`${this.textParams?.accessCastMode}` + 
                                                `${x8?.castMode === HiPlayCastMode.DEVICE_LEVEL
                                                    ? this.textParams?.allMediaAudio
                                                    : this.textParams?.accessPlayingNow}` +
                                                `${this.textParams?.accessNewPoint}`);
                                            Flex.padding({ top: 2.5, bottom: 2.5 });
                                            Flex.margin({ top: 4 });
                                            Flex.width('auto');
                                        }, Flex);
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Row.create();
                                            Row.margin({
                                                right: this.isRTL ? 0 : 4,
                                                left: this.isRTL ? 4 : 0,
                                            });
                                            Row.direction(Direction.Ltr);
                                        }, Row);
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            If.create();
                                            if (x8.castMode === HiPlayCastMode.DEVICE_LEVEL) {
                                                this.ifElseBranchUpdateFunction(0, () => {
                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                        SymbolGlyph.create({ 'id': -1, 'type': 40000, params: ['sys.symbol.speaker_wave_2'],
                                                             'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                                                        SymbolGlyph.fontSize(`16vp`);
                                                        SymbolGlyph.fontColor([{ 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                                                             'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }]);
                                                    }, SymbolGlyph);
                                                });
                                            }
                                            else {
                                                this.ifElseBranchUpdateFunction(1, () => {
                                                    this.SmallPicIcon.bind(this)(x8.bundleInfo?.pixelData);
                                                });
                                            }
                                        }, If);
                                        If.pop();
                                        Row.pop();
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            Row.create();
                                            Row.direction(Direction.Ltr);
                                        }, Row);
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            If.create();
                                            if (x8.castMode === HiPlayCastMode.DEVICE_LEVEL) {
                                                this.ifElseBranchUpdateFunction(0, () => {
                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                        Text.create(this.textParams?.allMediaAudio);
                                                        Text.fontWeight('sys.string.ohos_id_text_font_family_regular');
                                                        Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.ohos_id_text_size_body3'],
                                                             'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                                                        Text.textOverflow({ overflow: TextOverflow.Ellipsis });
                                                        Text.maxFontScale(this.maxFontSizeScale);
                                                        Text.wordBreak(WordBreak.BREAK_ALL);
                                                        Text.maxLines(1);

                                                    }, Text);
                                                    Text.pop();
                                                });
                                            }
                                            else {
                                                this.ifElseBranchUpdateFunction(1, () => {
                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                        Text.create(this.textParams?.playingNow);
                                                        Text.fontWeight('sys.string.ohos_id_text_font_family_regular');
                                                        Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.ohos_id_text_size_body3'],
                                                             'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                                                        Text.textOverflow({ overflow: TextOverflow.Ellipsis });
                                                        Text.maxFontScale(this.maxFontSizeScale);
                                                        Text.wordBreak(WordBreak.BREAK_ALL);
                                                        Text.maxLines(1);
                                                    }, Text);
                                                    Text.pop();
                                                });
                                            }
                                        }, If);
                                        If.pop();
                                        Row.pop();
                                        this.observeComponentCreation2((elmtId, isInitialRender) => {
                                            If.create();
                                            if (x8.isConnected && !this.isAncoSession) {
                                                this.ifElseBranchUpdateFunction(0, () => {
                                                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                        If.create();
                                                        if (x8.bundleInfo?.isShowBadge) {
                                                            this.ifElseBranchUpdateFunction(0, () => {
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Row.create();
                                                                    Row.onDisAppear(() => {
                                                                        if (x8.bundleInfo?.isShowBadge && x8?.deviceState === 0) {
                                                                            if (this.extensionProxy != null) {
                                                                                this.extensionProxy.send({ 'isShowBadge': false})
                                                                            }
                                                                        }
                                                                    })
                                                                    Row.margin({ left: 8, right: 8})
                                                                    Row.direction(Direction.Ltr);
                                                                }, Row);
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Badge.create({
                                                                        value: '',
                                                                        style: { badgeSize: 6, BadgeColor:  {'id': -1, 'type': 10001, params: ['sys.color.warning'],
                                                                        'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__'} }
                                                                    });
                                                                    Badge.width(18);
                                                                    Badge.height(16);
                                                                }, Badge);
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    SymbolGlyph.create({ 'id': -1, 'type': 40000, params: ['sys.symbol.arrowtriangle_down_fill'],
                                                                        'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                                                                    SymbolGlyph.fontSize('16vp');
                                                                    SymbolGlyph.fontColor([{ 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                                                                        'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }]);
                                                                }, SymbolGlyph);
                                                                Badge.pop();
                                                                Row.pop();
                                                            });
                                                        }
                                                        else {
                                                            this.ifElseBranchUpdateFunction(1, () => {
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    Row.create();
                                                                    Row.margin({ left: 8, right: 8})
                                                                    Row.direction(Direction.Ltr);
                                                                }, Row);
                                                                this.observeComponentCreation2((elmtId, isInitialRender) => {
                                                                    SymbolGlyph.create({ 'id': -1, 'type': 40000, params: ['sys.symbol.arrowtriangle_down_fill'],
                                                                        'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                                                                    SymbolGlyph.fontSize('16vp');
                                                                    SymbolGlyph.fontColor([{ 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                                                                        'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }]);
                                                                }, SymbolGlyph);
                                                                Row.pop();
                                                            });
                                                        }
                                                    }, If);
                                                    If.pop();
                                                    Flex.pop();
                                                });
                                            }
                                            else {
                                                this.ifElseBranchUpdateFunction(1, () => {
                                                });
                                            }
                                        }, If);
                                        If.pop();
                                    });
                                }
                                else {
                                    this.ifElseBranchUpdateFunction(1, () => {
                                    });
                                }
                            }, If);
                            If.pop();
                        });
                    }
                    else {
                        this.ifElseBranchUpdateFunction(2, () => {
                        });
                    }
                }, If);
                If.pop();
                Flex.pop();

                Row.pop();
                this.observeComponentCreation2((m9, n9) => {
                    If.create();
                    if (x8.isConnected && x8.selectedIconName !== null && x8.selectedIconName !== undefined &&
                        !this.houseMusicIsSelect) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.observeComponentCreation2((u9, v9) => {
                                Row.create();
                                Row.alignItems(VerticalAlign.Center);
                            }, Row);
                            this.iconBuilder.bind(this)(x8, true);
                            Row.pop();
                        });
                    } else {
                        this.ifElseBranchUpdateFunction(1, () => {
                        });
                    }
                }, If);
                If.pop();
                Flex.pop();
                this.observeComponentCreation2((f9, g9) => {
                    If.create();
                    if (!this.isPc && (w8 !== this.deviceList.length - 1)) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.observeComponentCreation2((k9, l9) => {
                                Divider.create();
                                Divider.opacity(0.5);
                                Divider.color({ 'id': -1, 'type': 10001, params: ['sys.color.comp_divider'],
                                    'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                                Divider.padding({ right: (this.isRTL ? 44 : 12), left: (this.isRTL ? 12 : 44) });
                            }, Divider);
                        });
                    } else if (this.isPc && (w8 !== this.deviceList.length - 1)) {
                        this.ifElseBranchUpdateFunction(1, () => {
                            this.observeComponentCreation2((c2, d2) => {
                                Row.create();
                                Row.width('100%');
                                Row.height(2);
                            }, Row);
                            Row.pop();
                        });
                    } else {
                        this.ifElseBranchUpdateFunction(2, () => {
                        });
                    }
                }, If);
                If.pop();
                Flex.pop();
            };
            this.forEachUpdateFunction(r8, this.deviceList, t8, undefined, true, false);
        }, ForEach);
        ForEach.pop();
        Column.pop();
    }

    HomeMusicSystemTitleBuilder(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Row.create();
            Row.width('100%');
            Row.justifyContent(FlexAlign.SpaceBetween);
            Row.padding({ top: '12vp', right: '16vp', bottom: '4vp', left: '16vp' });
            Row.borderRadius({ topLeft: '32vp', topRight: '32vp' });
        }, Row);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(this.houseMusicTitle);
            Text.fontColor({ 'id': -1, 'type': 10001, params: ['sys.color.font_primary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.Subtitle_M'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.fontWeight(FontWeight.Medium);
            Text.constraintSize({ maxWidth: '65%' });
        }, Text);
        Text.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(this.isAllSelecting ? this.houseMusicPlayCancel : this.houseMusicPlay);
            Text.fontColor((this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
                '#FF0A59F7' : '#FF317AF7');
            Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.Body_M'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.fontWeight(FontWeight.Medium);
            Text.constraintSize({ maxWidth: '35%' });
            Text.onClick(() => {
                this.allSelectOnClickEven();
            });
        }, Text);
        Text.pop();
        Row.pop();
    }

    BigFontHomeMusicSystemTitleBuilder(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
            Column.width('100%');
            Column.alignItems(HorizontalAlign.Start);
            Column.padding({ top: '12vp', right: '16vp', bottom: '4vp', left: '16vp' });
            Column.borderRadius({ topLeft: '32vp', topRight: '32vp' });
        }, Column);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(this.houseMusicTitle);
            Text.fontColor({ 'id': -1, 'type': 10001, params: ['sys.color.font_primary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.Subtitle_M'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.fontWeight(FontWeight.Medium);
        }, Text);
        Text.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(this.isAllSelecting ? this.houseMusicPlayCancel : this.houseMusicPlay);
            Text.fontColor((this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
                '#FF0A59F7' : '#FF317AF7');
            Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.Body_M'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.fontWeight(FontWeight.Medium);
            Text.onClick(() => {
                this.allSelectOnClickEven();
            });
        }, Text);
        Text.pop();
        Column.pop();
    }

    HomeMusicSystemRoomListBuilder(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Scroll.create(this.scroller);
            Scroll.padding({ top: '4vp', right: '16vp', bottom: '4vp', left: '16vp' });
            Scroll.width('100%');
            Scroll.constraintSize({ minHeight: this.roomItemHeight });
            Scroll.align(Alignment.Start);
            Scroll.borderRadius({ bottomLeft: '32vp', bottomRight: '32vp' });
            Scroll.scrollBar(BarState.Auto);
        }, Scroll);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
        }, Column);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            ForEach.create();
            const forEachItemGenFunction = (_item, index) => {
                const item = _item;
                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    Stack.create({ alignContent: Alignment.Start });
                    Stack.constraintSize({ minHeight: 48 });
                    Stack.width('100%');
                }, Stack);
                this.RoomItemBuilder.bind(this)(item, index);
                Stack.pop();
                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    If.create();
                    if (index !== this.roomListService.length - 1) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.DividerBuilder.bind(this)();
                        });
                    }
                    else {
                        this.ifElseBranchUpdateFunction(1, () => {
                        });
                    }
                }, If);
                If.pop();
            };
            this.forEachUpdateFunction(elmtId, this.roomListService, forEachItemGenFunction, undefined, true, false);
        }, ForEach);
        ForEach.pop();
        Column.pop();
        Scroll.pop();
    }

    RoomItemBuilder(item, index, parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create({ alignItems: ItemAlign.Center });
        }, Flex);
        this.RoomHouseBuilder.bind(this)();
        this.RoomNameAndVolumeBuilder.bind(this)(item, index);
        this.RoomCheckBuilder.bind(this)(item, index);
        Flex.pop();
    }

    RoomHouseBuilder(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            SymbolGlyph.create({ 'id': -1, 'type': 40000, params: ['sys.symbol.music_house_fill'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            SymbolGlyph.fontSize('24vp');
            SymbolGlyph.fontColor((this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ?
                [{ 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }] :
                [{ 'id': -1, 'type': 10001, params: ['sys.color.icon_primary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }]);
            SymbolGlyph.margin({
                right: { 'id': -1, 'type': 10002, params: ['sys.float.ohos_id_elements_margin_horizontal_l'],
                    'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' },
                left: 0
            });
            SymbolGlyph.draggable(false);
            SymbolGlyph.flexGrow(0);
            SymbolGlyph.flexShrink(0);
            SymbolGlyph.flexBasis('auto');
            SymbolGlyph.renderingStrategy(SymbolRenderingStrategy.SINGLE);
        }, SymbolGlyph);
    }

    RoomNameAndVolumeBuilder(item, index, parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create({ direction: FlexDirection.Column, alignItems: ItemAlign.Start });
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(item.data.name);
            Text.fontWeight('sys.string.ohos_id_text_font_family_medium');
            Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.ohos_id_text_size_body1'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.textOverflow({ overflow: TextOverflow.Ellipsis });
            Text.wordBreak(WordBreak.BREAK_ALL);
            Text.width('100%');
            Text.constraintSize({ minHeight: 16 });
        }, Text);
        Text.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Slider.create({
                value: this.roomCurrVolume[index],
                min: 0,
                max: 100,
                step: 1,
                style: SliderStyle.NONE,
                direction: Axis.Horizontal
            });
            Slider.visibility(this.roomVolumeVisible[index]);
            Slider.blockColor(Color.Transparent);
            Slider.showSteps(false);
            Slider.showTips(false);
            Slider.blockStyle({
                type: SliderBlockType.SHAPE,
                shape: new Path({ commands: 'M60 60 M30 30 L15 56 L45 56 Z' })
            });
            Slider.height(16);
            Slider.onChange((value, mode) => {
                console.info(TAG, `room slider onChange: ${value}, mode=${mode}, index=${index}`);
                this.roomListService[index].data.volume = value;
                this.roomCurrVolume[index] = value;
                this.onSliderValueChange(index, value, mode);
            });
        }, Slider);
        Flex.pop();
    }

    RoomCheckBuilder(item, index, parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            If.create();
            if (!this.roomSelectStatusPending[index]) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Checkbox.create();
                        Checkbox.select(this.roomIsSelect[index]);
                        Checkbox.shape(CheckBoxShape.CIRCLE);
                        Checkbox.onClick(() => {
                            this.roomSelectStatusPending[index] = true;
                            const w1 = setTimeout(() => {
                                this.roomSelectStatusPendingInit();
                            }, 3000);
                            if (typeof w1 === 'number') {
                                this.timeoutIds.push(w1);
                            }
                            this.getCurrSelectRoom(index, !this.roomIsSelect[index]);
                            if (this.isSelectRoomListService.length > 0) {
                                if (this.extensionProxy != null) {
                                    this.extensionProxy.send({ 'roomSelectChange': this.isSelectRoomListService });
                                }
                            }
                            else {
                                if (this.extensionProxy != null) {
                                    this.extensionProxy.send({ 'roomSelectChange': this.createNullRoomService() });
                                }
                            }
                        });
                        Checkbox.width(30);
                        Checkbox.margin({
                            left: '16vp'
                        });
                    }, Checkbox);
                    Checkbox.pop();
                });
            }
            else {
                this.ifElseBranchUpdateFunction(1, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        LoadingProgress.create();
                        LoadingProgress.width(36);
                        LoadingProgress.margin({
                            left: '16vp'
                        });
                    }, LoadingProgress);
                });
            }
        }, If);
        If.pop();
    }

    DividerBuilder(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Row.create();
            Row.margin({ left: '24vp' });
            Row.zIndex(1);
        }, Row);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Divider.create();
            Divider.color({ 'id': -1, 'type': 10001, params: ['sys.color.comp_divider'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Divider.opacity(0.5);
            Divider.margin({
                left: { 'id': -1, 'type': 10002, params: ['sys.float.ohos_id_elements_margin_horizontal_l'],
                    'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' },
                right: 0
            });
        }, Divider);
        Row.pop();
    }

    houseMusicSys(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            If.create();
            if (this.roomListService.length > 0) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        Column.create();
                        Column.onTouch((event) => {
                            event?.stopPropagation();
                        });
                        Column.backgroundColor({ 'id': -1, 'type': 10001,
                            params: ['sys.color.background_primary'], 'bundleName': '__harDefaultBundleName__',
                            'moduleName': '__harDefaultModuleName__' });
                        Column.borderRadius(this.isPc ? 8 : 20);
                    }, Column);
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        If.create();
                        if (this.fontSizeScale > 1.75) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.BigFontHomeMusicSystemTitleBuilder.bind(this)();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                                this.HomeMusicSystemTitleBuilder.bind(this)();
                            });
                        }
                    }, If);
                    If.pop();
                    this.HomeMusicSystemRoomListBuilder.bind(this)();
                    Column.pop();
                });
            }
            else {
                this.ifElseBranchUpdateFunction(1, () => {
                });
            }
        }, If);
        If.pop();
    }

    deviceAndHouseMusicSys(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create({space: 8});
            Column.width(this.isPc ? 326 : 216);
            Column.borderRadius(this.isPc ? 8 : 20);
        }, Column);
        this.deviceMenu.bind(this)();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            If.create();
            if (this.sessionType !== 'voice_call' && this.sessionType !== 'video_call') {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.houseMusicSys.bind(this)();
                });
            }
            else {
                this.ifElseBranchUpdateFunction(1, () => {
                });
            }
        }, If);
        If.pop();
        Column.pop();
    }

    castModeMenu(p8) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
            Column.padding({ top: 4, bottom: 4 });
        }, Column);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create();
            Flex.width(224);
            Flex.height(48);
            Flex.onClick(() => {
                this.isDeviceLevel = true;
                if (this.extensionProxy != null) {
                    this.extensionProxy.send({ 'castMode': HiPlayCastMode.DEVICE_LEVEL });
                }
                if (!this.isMenuShow) {
                    this.isSubMenuExpanded = false;
                    this.isMenuShow = true;
                }
            });
            Flex.accessibilityLevel('yes');
            Flex.accessibilitySelected(this.isDeviceLevel ? true : false);
            Flex.accessibilityRole(AccessibilityRoleType.MENU_ITEM);
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center });
            Flex.margin({ left: 4, right: 4 });
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create({ alignItems: ItemAlign.Center });
            Flex.margin({ left: 12, right: 12 });
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create({ direction: FlexDirection.Column, justifyContent: FlexAlign.Center });
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(this.textParams?.allMediaAudio);
            Text.fontWeight('sys.string.ohos_id_text_font_family_medium');
            Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.ohos_id_text_size_body1'],
                 'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.width('100%');
            Text.textOverflow({ overflow: TextOverflow.Ellipsis });
            Text.maxFontScale(this.maxFontSizeScale);
            Text.wordBreak(WordBreak.BREAK_ALL);
            Text.maxLines(1);
        }, Text);
        Text.pop();
        Flex.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Row.create();
            Row.width(48);

        }, Row);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            If.create();
            if (this.isDeviceLevel) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        SymbolGlyph.create({ 'id': -1, 'type': 40000, params: ['sys.symbol.checkmark'],
                             'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                        SymbolGlyph.fontSize('24vp');
                        SymbolGlyph.fontColor((this.configurationColorMode !==
                            ConfigurationColorMode.COLOR_MODE_DARK) ?
                            [{
                                'id': -1, 'type': 10001, params: ['sys.color.comp_background_emphasize'],
                                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__'
                            }] :
                            [{
                                'id': -1, 'type': 10001, params: ['sys.color.icon_primary'],
                                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__'
                            }]);
                    }, SymbolGlyph);
                });
            }
            else {
                this.ifElseBranchUpdateFunction(1, () => {
                });
            }
        }, If);
        If.pop();
        Row.pop();
        Flex.pop();
        Flex.pop();
        Flex.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Divider.create();
            Divider.width(192);
        }, Divider);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create();
            Flex.width(224);
            Flex.height(48);
            Flex.onClick(() => {
                this.isDeviceLevel = false;
                if (this.extensionProxy != null) {
                    this.extensionProxy.send({ 'castMode': HiPlayCastMode.APP_LEVEL });
                }
                if (!this.isMenuShow) {
                    this.isSubMenuExpanded = false;
                    this.isMenuShow = true;
                }
            });
            Flex.accessibilityLevel('yes');
            Flex.accessibilitySelected(!this.isDeviceLevel ? true : false);
            Flex.accessibilityRole(AccessibilityRoleType.MENU_ITEM);
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center });
            Flex.margin({ left: 4, right: 4 });
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create({ alignItems: ItemAlign.Center });
            Flex.margin({ left: 12, right: 12 });
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Flex.create({ direction: FlexDirection.Column, justifyContent: FlexAlign.Center });
        }, Flex);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(this.textParams?.currentApp);
            Text.fontWeight('sys.string.ohos_id_text_font_family_medium');
            Text.fontSize({ 'id': -1, 'type': 10002, params: ['sys.float.ohos_id_text_size_body1'],
                 'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.width('100%');
            Text.textOverflow({ overflow: TextOverflow.Ellipsis });
            Text.maxFontScale(this.maxFontSizeScale);
            Text.wordBreak(WordBreak.BREAK_ALL);
            Text.maxLines(1);
        }, Text);
        Text.pop();
        Flex.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Row.create();
            Row.width(48);
            Row.height(48);
            Row.justifyContent(FlexAlign.End)
        }, Row);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            If.create();
            if (!this.isDeviceLevel) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((elmtId, isInitialRender) => {
                        SymbolGlyph.create({ 'id': -1, 'type': 40000, params: ['sys.symbol.checkmark'],
                             'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
                        SymbolGlyph.fontSize('24vp');
                        SymbolGlyph.fontColor((this.configurationColorMode !==
                            ConfigurationColorMode.COLOR_MODE_DARK) ?
                            [{
                                'id': -1, 'type': 10001, params: ['sys.color.comp_background_emphasize'],
                                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__'
                            }] :
                            [{
                                'id': -1, 'type': 10001, params: ['sys.color.icon_primary'],
                                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__'
                            }]);
                    }, SymbolGlyph);
                });
            }
            else {
                this.ifElseBranchUpdateFunction(1, () => {
                });
            }
        }, If);
        If.pop();
        Row.pop();
        Flex.pop();
        Flex.pop();
        Flex.pop();
        Column.pop();
    }

    SmallPicIcon(q8, u8 = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
            Column.clip(true);
            Column.size({
                width: '16vp',
                height: '16vp'
            });
            Column.backgroundColor('#00ffffff');
            Column.borderRadius({ 'id': -1, 'type': 10002, params: ['sys.float.ohos_id_corner_radius_default_xs'], 'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
        }, Column);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Image.create(q8);
            Image.size({ width: '100%', height: '100%' });
            Image.backgroundColor('#00ffffff');
            Image.draggable(false);
            Image.interpolation(ImageInterpolation.Medium);
            Image.autoResize(false);
        }, Image);
        Column.pop();
    }
    buildDisabledPicker(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
        }, Column);
        Column.pop();
    }
    buildDefaultPicker(c8, d8 = null) {
        this.observeComponentCreation2((f8, g8) => {
            Button.createWithChild();
            Button.size({ width: '100%', height: '100%' });
            Button.hoverEffect(HoverEffect.None);
            Button.stateEffect(false);
            Button.backgroundColor('#00000000');
            Button.accessibilityLevel('yes');
            Button.accessibilityText(`${this.accessibilityAudioControlStr}${this.textParams?.accessNewPoint}`);
            Button.onClick(() => {
                if (this.extensionProxy == null) {
                    return;
                }
                if (this.needToRestart) {
                    this.needToRestart = false;
                    this.restartUECMessage += 1;
                    return;
                }
                let u = this.deviceList.length === 2 &&
                    !this.hasExtDevice(ObservedObject.GetRawObject(this.deviceList));
                let v = this.deviceList === null || this.deviceList.length === 0;
                let w = this.sessionType === 'voice_call' || this.sessionType === 'video_call';
                let x = w && (v || u);
                let y = !w && (this.pickerStyle === AVCastPickerStyle.STYLE_PANEL &&
                    this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_PANEL);
                if (x || y) {
                    this.isMenuShow = false;
                    this.touchMenuItemIndex = -1;
                    this.extensionProxy.send({'clickEvent': true});
                } else {
                    this.isMenuShow = !this.isMenuShow;
                    if (this.isMenuShow) {
                        this.pickerClickTime = new Date().getTime();
                    } else {
                        this.touchMenuItemIndex = -1;
                    }
                }
            });
        }, Button);
        this.observeComponentCreation2((f8, g8) => {
            Column.create();
            Column.bindMenu(this.isSubMenuExpanded, { builder: () => {
                this.castModeMenu.call(this);
            } }, {
            placement: Placement.BottomRight,
            showInSubWindow: false,
            enableHoverMode: true,
            onDisappear: () => {
                this.isSubMenuExpanded = false;
                this.touchMenuItemIndex = -1;
            },
            onAppear: () => {
                if (this.extensionProxy != null && this.pickerClickTime !== -1) {
                    this.extensionProxy.send({ 'timeCost': new Date().getTime() - this.pickerClickTime });
                    this.pickerClickTime = -1;
                }
            }
            });
            Column.accessibilityLevel('no-hide-descendants');
            Column.size({ width: '100%', height: '100%' });
        }, Column);
        this.observeComponentCreation2((f8, g8) => {
            UIExtensionComponent.create({
                abilityName: 'UIExtAbility',
                bundleName: 'com.hmos.mediacontroller',
                parameters: {
                    'normalColor': this.normalColor,
                    'activeColor': this.activeColor,
                    'pickerColorMode': this.colorMode,
                    'avCastPickerStyle': this.pickerStyle,
                    'ability.want.params.uiExtensionType': 'sysPicker/mediaControl',
                    'isCustomPicker': c8,
                    'message': this.restartUECMessage,
                    'currentPickerCount': this.pickerCountOnCreation,
                    'sessionType': this.sessionType,
                }
            });
            UIExtensionComponent.onRemoteReady((n8) => {
                console.info(TAG, 'onRemoteReady');
                this.extensionProxy = n8;
            });
            UIExtensionComponent.onReceive((l8) => {
                if (l8.deviceInfoType !== undefined) {
                    console.info(TAG, `deviceInfoType : ${JSON.stringify(l8.deviceInfoType)}`);
                    this.deviceInfoType = l8.deviceInfoType;
                }

                if (l8.pickerStyle !== undefined) {
                    console.info(TAG, `picker style : ${JSON.stringify(l8.pickerStyle)}`);
                    this.pickerStyleFromMediaController = l8.pickerStyle;
                }

                if (l8.deviceList !== undefined) {
                    console.info(TAG, `picker device list : ${JSON.stringify(l8.deviceList)}`);
                    this.deviceList = JSON.parse(JSON.stringify(l8.deviceList));
                    let u = this.deviceList.length === 2 && !this.hasExtDevice(ObservedObject.GetRawObject(this.deviceList));
                    let v = this.deviceList === null || this.deviceList.length === 0;
                    let w = this.sessionType === 'voice_call' || this.sessionType === 'video_call';
                    let x = w && (v || u);
                    let b21 = !w && (this.pickerStyle === AVCastPickerStyle.STYLE_PANEL &&
                        this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_PANEL);
                    if (x || b21) {
                        this.isMenuShow = false;
                        this.touchMenuItemIndex = -1;
                    }
                }

                if (l8.fontSizeScale !== undefined) {
                    console.info(TAG, `font size scale : ${JSON.stringify(l8.fontSizeScale)}`);
                    this.fontSizeScale = l8.fontSizeScale;
                }

                if (l8.state !== undefined) {
                    console.info(TAG, `picker state change : ${JSON.stringify(l8.state)}`);
                    let w = this.sessionType === 'voice_call' || this.sessionType === 'video_call';
                    let b21 = !w && (this.pickerStyle === AVCastPickerStyle.STYLE_PANEL &&
                        this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_PANEL);
                    if (this.onStateChange != null && b21) {
                        if (parseInt(JSON.stringify(l8.state)) === AVCastPickerState.STATE_APPEARING) {
                            this.onStateChange(AVCastPickerState.STATE_APPEARING);
                        }
                        else {
                            this.onStateChange(AVCastPickerState.STATE_DISAPPEARING);
                        }
                    }
                }

                if (l8.sessionType !== undefined) {
                    console.info(TAG, `session type : ${JSON.stringify(l8.sessionType)}`);
                    this.sessionType = l8.sessionType;
                }

                if (l8.isShowMenu !== undefined) {
                    console.info(TAG, `isShowMenu : ${l8.isShowMenu}`);
                    this.isMenuShow = l8.isShowMenu;
                    if (!this.isMenuShow) {
                        this.touchMenuItemIndex = -1;
                    }
                }

                if (l8.isSubMenuExpanded !== undefined) {
                    console.info(TAG, `isShowMenu : ${l8.isSubMenuExpanded}`);
                    this.isSubMenuExpanded = l8.isSubMenuExpanded;
                    if (!this.isSubMenuExpanded) {
                        this.touchMenuItemIndex = -1;
                    }
                }

                if (l8.configurationColorMode !== undefined) {
                    console.info(TAG, `configurationColorMode : ${l8.configurationColorMode}`);
                    this.configurationColorMode = l8.configurationColorMode;
                }


                if (l8.accessAudioControl !== undefined) {
                    console.info(TAG, `accessibilityAudioControlStr : ${l8.accessAudioControl}`);
                    this.accessibilityAudioControlStr = l8.accessAudioControl;
                }

                if (l8.isPc !== undefined) {
                    console.info(TAG, `isPc : ${l8.isPc}`);
                    this.isPc = l8.isPc;
                }

                if (l8.isRTL !== undefined) {
                    console.info(TAG, `isRTL : ${l8.isRTL}`);
                    this.isRTL = l8.isRTL;
                }

                if (l8.maxFontSizeScale !== undefined) {
                    console.info(TAG, `maxFontSizeScale : ${l8.maxFontSizeScale}`);
                    this.maxFontSizeScale = l8.maxFontSizeScale;
                }

                if (l8.isShowLoadingProgress !== undefined) {
                    console.info(TAG, `isShowLoadingProgress : ${l8.isShowLoadingProgress}`);
                    this.isShowLoadingProgress = l8.isShowLoadingProgress;
                }

                if (l8.textParams !== undefined) {
                    console.info(TAG, `textParams : ${l8.textParams}`);
                    this.textParams = l8.textParams;
                }

                if (l8.isAncoSession !== undefined) {
                    console.info(TAG, `isAncoSession : ${l8.isAncoSession}`);
                    this.isAncoSession = l8.isAncoSession;
                }

                if (l8.roomList !== undefined) {
                    console.info(TAG, `roomlist : ${JSON.stringify(l8.roomList)}`);
                    this.roomListService = JSON.parse(JSON.stringify(l8.roomList));
                }

                if (l8.HomeMusicPlayTaskId !== undefined) {
                    console.info(TAG, `playTaskId : ${l8.HomeMusicPlayTaskId}`);
                    this.playTaskIdStr = l8.HomeMusicPlayTaskId;
                }

                if (l8.keyInputEven !== undefined) {
                    console.info(TAG, `keyInputEven: ${l8.keyInputEven}`);
                    let k1 = l8.keyInputEven;
                    this.syncToRoomVolume(k1);
                    this.sendAllRoomVolumeToController();
                    this.roomMaxVolume = this.findRoomMaxVolume();
                    this.roomMaxVolumeChange();
                }

                if (l8.houseMusicTitleGroup !== undefined) {
                    console.info(TAG, `houseMusicTitleGroup : ${JSON.stringify(l8.houseMusicTitleGroup)}`);
                    let k1 = JSON.parse(JSON.stringify(l8.houseMusicTitleGroup));
                    this.houseMusicTitle = k1[0];
                    this.houseMusicPlay = k1[1];
                    this.houseMusicPlayCancel = k1[2];
                }

                if (l8.HomeMusicScanStatus !== undefined) {
                    console.info(TAG, `HomeMusicScanStatus : ${JSON.stringify(l8.HomeMusicScanStatus)}`);
                    this.scanStatus = l8.HomeMusicScanStatus;
                }
            });
            UIExtensionComponent.size({ width: '100%', height: '100%' });
            UIExtensionComponent.bindMenu(this.isMenuShow, { builder: () => {
                this.deviceAndHouseMusicSys.call(this);
            } }, {
                backgroundBlurStyle: (this.isShowHomeAudio ? BlurStyle.NONE : BlurStyle.BACKGROUND_ULTRA_THICK),
                backgroundColor: (this.isShowHomeAudio ? '#00000000' :
                    (this.configurationColorMode !== ConfigurationColorMode.COLOR_MODE_DARK) ? { 'id': -1, 'type': 10001,
                    params: ['sys.color.background_primary'], 'bundleName': '__harDefaultBundleName__',
                    'moduleName': '__harDefaultModuleName__' } : '#00FFFFFF'),
            placement: Placement.BottomRight,
            showInSubWindow: false,
            enableHoverMode: true,
            onDisappear: () => {
                this.isMenuShow = false;
                this.touchMenuItemIndex = -1;
                this.menuShowStateCallback(this.isMenuShow);
            },
            onAppear: () => {
                if (this.extensionProxy != null && this.pickerClickTime !== -1) {
                    this.extensionProxy.send({ 'timeCost': new Date().getTime() - this.pickerClickTime });
                    this.pickerClickTime = -1;
                }
                this.menuShowStateCallback(this.isMenuShow);
            }
        });
            UIExtensionComponent.onRelease((releaseCode) => {
                console.error(TAG, `onRelease code ${releaseCode}`);
                if (releaseCode === 1) {
                    this.needToRestart = true;
                }
            });
            UIExtensionComponent.onError(() => {
                console.error(TAG, 'onError ready to restart');
                this.needToRestart = true;
            });
            UIExtensionComponent.accessibilityLevel('yes');
            UIExtensionComponent.accessibilityText(this.__accessibilityAudioControlStr);
            UIExtensionComponent.accessibilityUseSamePage(AccessibilitySamePageMode.FULL_SILENT);
        }, UIExtensionComponent);
        Column.pop();
        Button.pop();
    }

    hasExtDevice(a) {
        for (let b = 0; b < a.length; b++) {
            let q1 = (a[b].deviceType === 1 || a[b].deviceType === 2) && a[b].networkId === 'LocalDevice';
            if (!q1) {
                return true;
            }
        }
        return false;
    }

    menuShowStateCallback(k) {
        if (this.onStateChange != null && (this.pickerStyle === AVCastPickerStyle.STYLE_MENU ||
            this.pickerStyleFromMediaController === AVCastPickerStyle.STYLE_MENU)) {
            let l = k ? AVCastPickerState.STATE_APPEARING : AVCastPickerState.STATE_DISAPPEARING;
            this.onStateChange(l);
        }
    }

    buildCustomPicker(s7 = null) {
        this.observeComponentCreation2((a8, b8) => {
            Stack.create({ alignContent: Alignment.Center});
            Stack.size({ width: '100%', height: '100%' });
        }, Stack);
        this.observeComponentCreation2((y7, z7) => {
            Column.create();
            Column.alignItems(HorizontalAlign.Center);
            Column.justifyContent(FlexAlign.Center);
            Column.size({ width: '100%', height: '100%' });
            Column.zIndex(0);
        }, Column);
        this.observeComponentCreation2((c7, s7) => {
            If.create();
            if (this.isShowLoadingProgress) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((c7, s7) => {
                        LoadingProgress.create();
                        LoadingProgress.color(this.activeColor === 'liveCardLoadingColor' 
                            ? '#FFFFFFFF' 
                            : {'id': -1, 'type': 10001, params: ['sys.color.icon_secondary'],
                            'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__'});
                        LoadingProgress.width('20vp');
                        LoadingProgress.height('20vp');
                    }, LoadingProgress);
                });
            } else {
                this.ifElseBranchUpdateFunction(1, () => {
                    this.customPicker.bind(this)();
                });
            }
        }, If);
        If.pop();
        Column.pop();
        this.observeComponentCreation2((w7, x7) => {
            Column.create();
            Column.alignItems(HorizontalAlign.Center);
            Column.justifyContent(FlexAlign.Center);
            Column.size({ width: '100%', height: '100%' });
            Column.zIndex(1);
        }, Column);
        this.buildDefaultPicker.bind(this)(true);
        Column.pop();
        Stack.pop();
    }

    rerender() {
        this.updateDirtyElements();
    }

    static getEntryName() {
        return 'AVCastPicker';
    }
}
AVCastPicker.currentPickerCount = 0;
export default AVCastPicker;