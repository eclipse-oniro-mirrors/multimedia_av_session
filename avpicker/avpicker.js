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
        this.onStateChange = undefined;
        this.extensionProxy = null;
        this.pickerClickTime = -1;
        this.customPicker = undefined;
        this.__configurationColorMode =
            new ObservedPropertySimplePU(ConfigurationColorMode.COLOR_MODE_NOT_SET, this, 'configurationColorMode');
        this.__deviceInfoType = new ObservedPropertySimplePU('', this, 'deviceInfoType');
        this.__maxFontSizeScale = new ObservedPropertySimplePU(1, this, 'maxFontSizeScale');
        this.__accessibilityConnectedStr = new ObservedPropertySimplePU('已连接', this, 'accessibilityConnectedStr');
        this.__accessibilityAudioControlStr = new ObservedPropertySimplePU('音视频投播', this, 'accessibilityAudioControlStr');
        this.__isPc = new ObservedPropertySimplePU(false, this, 'isPc');
        this.__isRTL = new ObservedPropertySimplePU(false, this, 'isRTL');
        this.__restartUECMessage = new ObservedPropertySimplePU(1, this, 'restartUECMessage');
        this.needToRestart = false;
        this.__isShowLoadingProgress = new ObservedPropertySimplePU(false, this, 'isShowLoadingProgress');
        this.pickerCountOnCreation = 0;
        this.setInitiallyProvidedValue(e11);
        this.declareWatch('isMenuShow', this.MenuStateChange);
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
        if (c11.accessibilityConnectedStr !== undefined) {
            this.accessibilityConnectedStr = c11.accessibilityConnectedStr;
        }
        if (c11.accessibilityAudioControlStr !== undefined) {
            this.accessibilityAudioControlStr = c11.accessibilityAudioControlStr;
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
        this.__configurationColorMode.purgeDependencyOnElmtId(a11);
        this.__deviceInfoType.purgeDependencyOnElmtId(a11);
        this.__maxFontSizeScale.purgeDependencyOnElmtId(a11);
        this.__accessibilityConnectedStr.purgeDependencyOnElmtId(a11);
        this.__accessibilityAudioControlStr.purgeDependencyOnElmtId(a11);
        this.__isPc.purgeDependencyOnElmtId(a11);
        this.__isRTL.purgeDependencyOnElmtId(a11);
        this.__restartUECMessage.purgeDependencyOnElmtId(a11);
        this.__isShowLoadingProgress.purgeDependencyOnElmtId(a11);
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
        this.__configurationColorMode.aboutToBeDeleted();
        this.__deviceInfoType.aboutToBeDeleted();
        this.__maxFontSizeScale.aboutToBeDeleted();
        this.__accessibilityConnectedStr.aboutToBeDeleted();
        this.__accessibilityAudioControlStr.aboutToBeDeleted();
        this.__isPc.aboutToBeDeleted();
        this.__isRTL.aboutToBeDeleted();
        this.__restartUECMessage.aboutToBeDeleted();
        this.__isShowLoadingProgress.aboutToBeDeleted();
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

    get accessibilityConnectedStr() {
        return this.__accessibilityConnectedStr.get();
    }

    set accessibilityConnectedStr(c1) {
        this.__accessibilityConnectedStr.set(c1);
    }

    get accessibilityAudioControlStr() {
        return this.__accessibilityAudioControlStr.get();
    }

    set accessibilityAudioControlStr(d1) {
        this.__accessibilityAudioControlStr.set(d1);
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

    aboutToAppear() {
        AVCastPicker.currentPickerCount += 1;
        this.pickerCountOnCreation = AVCastPicker.currentPickerCount;
    }

    aboutToDisappear() {
        AVCastPicker.currentPickerCount -= 1;
    }

    MenuStateChange() {
        if (this.extensionProxy != null) {
            this.extensionProxy.send({ 'isMenuShow': this.isMenuShow });
        }
    }

    showHighQuality(item) {
        if (item.supportedProtocols === undefined) {
            return false;
        }
        return (item.supportedProtocols & castPlusAudioType) !== 0;
    }

    initialRender() {
        this.observeComponentCreation2((r10, s10) => {
            Column.create();
            Column.size({ width: '100%', height: '100%'});
        }, Column);
        this.observeComponentCreation2((n10, o10) => {
            If.create();
            if (this.customPicker === undefined) {
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
            Text.fontColor(u1.isConnected ?
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
            Text.wordBreak(WordBreak.BREAK_ALL);
            Text.maxFontScale(this.maxFontSizeScale);
            Text.direction(this.isRTL ? Direction.Rtl : Direction.Ltr);
        }, Text);
        Text.pop();
    }

    highQualityIconBuilder(u2, v1 = null) {
        Row.create();
        Row.direction(Direction.Ltr);
        this.observeComponentCreation2((x1, y1) => {
            Text.create(u2 ? u2.iconLeft : '');
            Text.fontSize(7);
            Text.fontWeight(FontWeight.Medium);
            Text.fontColor({ 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.maxFontScale(this.maxFontSizeScale);
        }, Text);
        Text.pop();
        this.observeComponentCreation2((x1, y1) => {
            Text.create(u2 ? u2.iconRight : '');
            Text.fontSize(7);
            Text.fontWeight(FontWeight.Medium);
            Text.fontColor({ 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' });
            Text.maxFontScale(this.maxFontSizeScale);
            Text.margin({left: 2 * (Math.min(this.maxFontSizeScale, this.fontSizeScale))});
        }, Text);
        Text.pop();
        Row.pop();
    }

    deviceMenu(o8 = null) {
        this.observeComponentCreation2((j10, k10) => {
            Column.create();
            Column.width(this.isPc ? 326 : 216);
            Column.borderRadius(this.isPc ? 8 : 20);
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
                        if (this.extensionProxy != null && !x8.isConnected) {
                            this.extensionProxy.send({ 'selectedDeviceInfo': x8 });
                        }
                    });
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

                this.observeComponentCreation2((a10, b10) => {
                    Flex.create({
                        direction: FlexDirection.Column,
                        justifyContent: FlexAlign.Center,
                    });
                    Flex.padding({
                        left: 8,
                        top: this.isPc ? 11 : (this.showHighQuality(x8) ? 7 : 17),
                        right: 8,
                        bottom: this.isPc ? 11 : (this.showHighQuality(x8) ? 7 : 17),
                    });
                    Flex.width(this.isPc ? 254 : 144);
                }, Flex);
                this.textBuilder.bind(this)(x8);
                this.observeComponentCreation2((m9, n9) => {
                    If.create();
                    if (this.showHighQuality(x8)) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.observeComponentCreation2((u9, v9) => {
                                Flex.create();
                                Flex.borderRadius(3);
                                Flex.border({
                                    width: 0.5 * (Math.min(this.maxFontSizeScale, this.fontSizeScale)),
                                    color: { 'id': -1, 'type': 10001, params: ['sys.color.font_secondary'],
                                        'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__' }
                                });
                                Flex.padding({top: 1.5, right: 4, bottom: 1.5, left: 4});
                                Flex.margin({top: 2});
                                Flex.width('auto');
                            }, Flex);
                            this.highQualityIconBuilder.bind(this)(x8.highQualityParams);
                            Flex.pop();
                        });
                    } else {
                        this.ifElseBranchUpdateFunction(1, () => {
                        });
                    }
                }, If);
                If.pop();
                Flex.pop();

                Row.pop();
                this.observeComponentCreation2((m9, n9) => {
                    If.create();
                    if (x8.isConnected && x8.selectedIconName !== null && x8.selectedIconName !== undefined) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.observeComponentCreation2((u9, v9) => {
                                Row.create();
                                Row.alignItems(VerticalAlign.Center);
                                Row.accessibilityLevel('yes');
                                Row.accessibilityText(this.accessibilityConnectedStr);
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
                                Divider.height(1);
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

    buildDefaultPicker(c8, d8 = null) {
        this.observeComponentCreation2((f8, g8) => {
            Button.createWithChild();
            Button.size({ width: '100%', height: '100%' });
            Button.stateEffect(false);
            Button.backgroundColor('#00000000');
            Button.accessibilityLevel('yes');
            Button.accessibilityText(this.accessibilityAudioControlStr);
            Button.onClick(() => {
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
            });
        }, Button);
        this.observeComponentCreation2((f8, g8) => {
            Column.create();
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
                }
            });
            UIExtensionComponent.onRemoteReady((n8) => {
                console.info(TAG, 'onRemoteReady');
                this.extensionProxy = n8;
            });
            UIExtensionComponent.onReceive((l8) => {
                if (JSON.stringify(l8.deviceInfoType) !== undefined) {
                    console.info(TAG, `deviceInfoType : ${JSON.stringify(l8.deviceInfoType)}`);
                    this.deviceInfoType = l8.deviceInfoType;
                }

                if (JSON.stringify(l8.pickerStyle) !== undefined) {
                    console.info(TAG, `picker style : ${JSON.stringify(l8.pickerStyle)}`);
                    this.pickerStyleFromMediaController = l8.pickerStyle;
                }

                if (JSON.stringify(l8.deviceList) !== undefined) {
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

                if (JSON.stringify(l8.fontSizeScale) !== undefined) {
                    console.info(TAG, `font size scale : ${JSON.stringify(l8.fontSizeScale)}`);
                    this.fontSizeScale = l8.fontSizeScale;
                }

                if (JSON.stringify(l8.state) !== undefined) {
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

                if (JSON.stringify(l8.sessionType) !== undefined) {
                    console.info(TAG, `session type : ${JSON.stringify(l8.sessionType)}`);
                    this.sessionType = l8.sessionType;
                }

                if (JSON.stringify(l8.isShowMenu) !== undefined) {
                    console.info(TAG, `isShowMenu : ${l8.isShowMenu}`);
                    this.isMenuShow = l8.isShowMenu;
                    if (!this.isMenuShow) {
                        this.touchMenuItemIndex = -1;
                    }
                }

                if (JSON.stringify(l8.configurationColorMode) !== undefined) {
                    console.info(TAG, `configurationColorMode : ${l8.configurationColorMode}`);
                    this.configurationColorMode = l8.configurationColorMode;
                }

                if (JSON.stringify(l8.accessConnected) !== undefined) {
                    console.info(TAG, `accessibilityConnectedStr : ${l8.accessConnected}`);
                    this.accessibilityConnectedStr = l8.accessConnected;
                }

                if (JSON.stringify(l8.accessAudioControl) !== undefined) {
                    console.info(TAG, `accessibilityAudioControlStr : ${l8.accessAudioControl}`);
                    this.accessibilityAudioControlStr = l8.accessAudioControl;
                }

                if (JSON.stringify(l8.isPc) !== undefined) {
                    console.info(TAG, `isPc : ${l8.isPc}`);
                    this.isPc = l8.isPc;
                }

                if (JSON.stringify(l8.isRTL) !== undefined) {
                    console.info(TAG, `isRTL : ${l8.isRTL}`);
                    this.isRTL = l8.isRTL;
                }

                if (JSON.stringify(l8.maxFontSizeScale) !== undefined) {
                    console.info(TAG, `maxFontSizeScale : ${l8.maxFontSizeScale}`);
                    this.maxFontSizeScale = l8.maxFontSizeScale;
                }

                if (JSON.stringify(l8.isShowLoadingProgress) !== undefined) {
                    console.info(TAG, `isShowLoadingProgress : ${l8.isShowLoadingProgress}`);
                    this.isShowLoadingProgress = l8.isShowLoadingProgress;
                }
            });
            UIExtensionComponent.size({ width: '100%', height: '100%' });
            UIExtensionComponent.bindMenu(this.isMenuShow, { builder: () => { this.deviceMenu.call(this); }}, {
                placement: Placement.BottomRight,
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
                        LoadingProgress.color({'id': -1, 'type': 10001, params: ['sys.color.icon_secondary'],
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