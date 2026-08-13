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

if (!('finalizeConstruction' in ViewPU.prototype)) {
    Reflect.set(ViewPU.prototype, 'finalizeConstruction', () => { });
}

const TAG = 'avcastpicker_component ';
const t = 20;

export let AVCastPickerState;
(function(l11) {
    l11[l11.STATE_APPEARING = 0] = 'STATE_APPEARING';
    l11[l11.STATE_DISAPPEARING = 1] = 'STATE_DISAPPEARING';
})(AVCastPickerState || (AVCastPickerState = {}));

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
        this.__sessionType = new ObservedPropertySimplePU('audio', this, 'sessionType');
        this.onStateChange = undefined;
        this.extensionProxy = null;
        this.customPicker = undefined;
        this.__accessibilityAudioControlStr = new ObservedPropertySimplePU('音视频投播', this, 'accessibilityAudioControlStr');
        this.__restartUECMessage = new ObservedPropertySimplePU(1, this, 'restartUECMessage');
        this.needToRestart = false;
        this.pickerCountOnCreation = 0;
        this.__isDisabledByPickerLimit = new ObservedPropertySimplePU(false, this, 'isDisabledByPickerLimit');
        this.setInitiallyProvidedValue(e11);
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
        if (c11.sessionType !== undefined) {
            this.sessionType = c11.sessionType;
        }
        if (c11.onStateChange !== undefined) {
            this.onStateChange = c11.onStateChange;
        }
        if (c11.extensionProxy !== undefined) {
            this.extensionProxy = c11.extensionProxy;
        }
        if (c11.customPicker !== undefined) {
            this.customPicker = c11.customPicker;
        }
        if (c11.accessibilityAudioControlStr !== undefined) {
            this.accessibilityAudioControlStr = c11.accessibilityAudioControlStr;
        }
        if (c11.restartUECMessage !== undefined) {
            this.restartUECMessage = c11.restartUECMessage;
        }
        if (c11.needToRestart !== undefined) {
            this.needToRestart = c11.needToRestart;
        }
        if (c11.pickerCountOnCreation !== undefined) {
            this.pickerCountOnCreation = c11.pickerCountOnCreation;
        }
        if (c11.isDisabledByPickerLimit !== undefined) {
            this.isDisabledByPickerLimit = c11.isDisabledByPickerLimit;
        }
    }

    updateStateVars(b11) {
    }

    purgeVariableDependenciesOnElmtId(a11) {
        this.__normalColor.purgeDependencyOnElmtId(a11);
        this.__activeColor.purgeDependencyOnElmtId(a11);
        this.__colorMode.purgeDependencyOnElmtId(a11);
        this.__sessionType.purgeDependencyOnElmtId(a11);
        this.__accessibilityAudioControlStr.purgeDependencyOnElmtId(a11);
        this.__restartUECMessage.purgeDependencyOnElmtId(a11);
        this.__isDisabledByPickerLimit.purgeDependencyOnElmtId(a11);
    }

    aboutToBeDeleted() {
        this.__normalColor.aboutToBeDeleted();
        this.__activeColor.aboutToBeDeleted();
        this.__colorMode.aboutToBeDeleted();
        this.__sessionType.aboutToBeDeleted();
        this.__accessibilityAudioControlStr.aboutToBeDeleted();
        this.__restartUECMessage.aboutToBeDeleted();
        this.__isDisabledByPickerLimit.aboutToBeDeleted();
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

    get sessionType() {
        return this.__sessionType.get();
    }

    set sessionType(w10) {
        this.__sessionType.set(w10);
    }

    get accessibilityAudioControlStr() {
        return this.__accessibilityAudioControlStr.get();
    }

    set accessibilityAudioControlStr(d1) {
        this.__accessibilityAudioControlStr.set(d1);
    }

    get restartUECMessage() {
        return this.__restartUECMessage.get();
    }

    set restartUECMessage(f1) {
        this.__restartUECMessage.set(f1);
    }

    get isDisabledByPickerLimit() {
        return this.__isDisabledByPickerLimit.get();
    }

    set isDisabledByPickerLimit(g1) {
        this.__isDisabledByPickerLimit.set(g1);
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
            Button.accessibilityText(`${this.accessibilityAudioControlStr}`);
            Button.onClick(() => {
                if (this.needToRestart) {
                    this.needToRestart = false;
                    this.restartUECMessage += 1;
                    return;
                }
            });
        }, Button);
        this.observeComponentCreation2((f8, g8) => {
            UIExtensionComponent.create({
                abilityName: 'MultiScreenIconButton',
                bundleName: 'com.hmos.hwcomic',
                parameters: {
                    'normalColor': this.normalColor,
                    'activeColor': this.activeColor,
                    'pickerColorMode': this.colorMode,
                    'ability.want.params.uiExtensionType': 'sysPicker/mediaControl',
                    'isCustomPicker': c8,
                    'message': this.restartUECMessage,
                    'sessionType': this.sessionType,
                }
            });
            UIExtensionComponent.onRemoteReady((n8) => {
                console.info(TAG, 'onRemoteReady');
                this.extensionProxy = n8;
            });
            UIExtensionComponent.onReceive((l8) => {
                if (l8.state !== undefined) {
                    console.info(TAG, `picker state change : ${JSON.stringify(l8.state)}`);
                    if (this.onStateChange != null) {
                        if (parseInt(JSON.stringify(l8.state)) === AVCastPickerState.STATE_APPEARING) {
                            this.onStateChange(AVCastPickerState.STATE_APPEARING);
                        } else {
                            this.onStateChange(AVCastPickerState.STATE_DISAPPEARING);
                        }
                    }
                }

                if (l8.accessAudioControl !== undefined) {
                    console.info(TAG, `accessibilityAudioControlStr : ${l8.accessAudioControl}`);
                    this.accessibilityAudioControlStr = l8.accessAudioControl;
                }
            });
            UIExtensionComponent.size({ width: '100%', height: '100%' });
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
            UIExtensionComponent.focusable(false);
        }, UIExtensionComponent);
        Column.pop();
        Button.pop();
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
            this.ifElseBranchUpdateFunction(1, () => {
                this.customPicker.bind(this)();
            });
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