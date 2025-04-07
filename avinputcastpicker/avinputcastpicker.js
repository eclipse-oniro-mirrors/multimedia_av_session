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

if (!('finalizeConstruction' in ViewPU.prototype)) {
    Reflect.set(ViewPU.prototype, 'finalizeConstruction', () => {
    });
}
const TAG = 'AVInputCastPicker_component';

/**
 * Definition of av cast picker state.
 */
export let AVCastPickerState;
(function (AVCastPickerState) {
    /**
     * The picker starts showing.
     */
    AVCastPickerState[AVCastPickerState['STATE_APPEARING'] = 0] = 'STATE_APPEARING';
    /**
     * The picker finishes presenting.
     */
    AVCastPickerState[AVCastPickerState['STATE_DISAPPEARING'] = 1] = 'STATE_DISAPPEARING';
})(AVCastPickerState || (AVCastPickerState = {}));

export class AVInputCastPicker extends ViewPU {
    constructor(parent, params, __localStorage, elmtId = -1, paramsLambda = undefined, extraInfo) {
        super(parent, __localStorage, elmtId, extraInfo);
        if (typeof paramsLambda === 'function') {
            this.paramsGenerator_ = paramsLambda;
        }
        this.customPicker = undefined;
        this.__deviceInfoList = new ObservedPropertyObjectPU([], this, 'deviceInfoList');
        this.__touchMenuItemIndex = new ObservedPropertySimplePU(-1, this, 'touchMenuItemIndex');
        this.__isDarkMode = new ObservedPropertySimplePU(false, this, 'isDarkMode');
        this.__isRTL = new ObservedPropertySimplePU(false, this, 'isRTL');
        this.onStateChange = undefined;
        this.extensionProxy = null;
        this.pickerClickTime = -1;
        this.setInitiallyProvidedValue(params);
        this.finalizeConstruction();
    }

    setInitiallyProvidedValue(params) {
        if (params.customPicker !== undefined) {
            this.customPicker = params.customPicker;
        }
        if (params.deviceInfoList !== undefined) {
            this.deviceInfoList = params.deviceInfoList;
        }
        if (params.touchMenuItemIndex !== undefined) {
            this.touchMenuItemIndex = params.touchMenuItemIndex;
        }
        if (params.isDarkMode !== undefined) {
            this.isDarkMode = params.isDarkMode;
        }
        if (params.isRTL !== undefined) {
            this.isRTL = params.isRTL;
        }
        if (params.onStateChange !== undefined) {
            this.onStateChange = params.onStateChange;
        }
        if (params.extensionProxy !== undefined) {
            this.extensionProxy = params.extensionProxy;
        }
        if (params.pickerClickTime !== undefined) {
            this.pickerClickTime = params.pickerClickTime;
        }
    }

    updateStateVars(params) {
    }

    purgeVariableDependenciesOnElmtId(rmElmtId) {
        this.__deviceInfoList.purgeDependencyOnElmtId(rmElmtId);
        this.__touchMenuItemIndex.purgeDependencyOnElmtId(rmElmtId);
        this.__isDarkMode.purgeDependencyOnElmtId(rmElmtId);
        this.__isRTL.purgeDependencyOnElmtId(rmElmtId);
    }

    aboutToBeDeleted() {
        this.__deviceInfoList.aboutToBeDeleted();
        this.__touchMenuItemIndex.aboutToBeDeleted();
        this.__isDarkMode.aboutToBeDeleted();
        this.__isRTL.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }

    get deviceInfoList() {
        return this.__deviceInfoList.get();
    }

    set deviceInfoList(newValue) {
        this.__deviceInfoList.set(newValue);
    }

    get touchMenuItemIndex() {
        return this.__touchMenuItemIndex.get();
    }

    set touchMenuItemIndex(newValue) {
        this.__touchMenuItemIndex.set(newValue);
    }

    get isDarkMode() {
        return this.__isDarkMode.get();
    }

    set isDarkMode(newValue) {
        this.__isDarkMode.set(newValue);
    }

    get isRTL() {
        return this.__isRTL.get();
    }

    set isRTL(newValue) {
        this.__isRTL.set(newValue);
    }

    iconBuilder(item, isSelected, parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            SymbolGlyph.create(!isSelected ? {
                'id': -1,
                'type': -1,
                params: [item.deviceIconName],
                'bundleName': '__harDefaultBundleName__',
                'moduleName': '__harDefaultModuleName__'
            } : {
                'id': -1,
                'type': -1,
                params: [item.selectedIconName],
                'bundleName': '__harDefaultBundleName__',
                'moduleName': '__harDefaultModuleName__'
            });
            SymbolGlyph.fontSize('24vp');
            SymbolGlyph.fontColor((isSelected && !this.isDarkMode) ?
                [{
                    'id': -1,
                    'type': 10001,
                    params: ['sys.color.comp_background_emphasize'],
                    'bundleName': '__harDefaultBundleName__',
                    'moduleName': '__harDefaultModuleName__'
                }] : [{
                    'id': -1,
                    'type': 10001,
                    params: ['sys.color.icon_primary'],
                    'bundleName': '__harDefaultBundleName__',
                    'moduleName': '__harDefaultModuleName__'
                }]);
            SymbolGlyph.renderingStrategy(SymbolRenderingStrategy.SINGLE);
        }, SymbolGlyph);
    }

    textBuilder(item, parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Text.create(item.deviceName);
            Text.fontSize({
                'id': -1,
                'type': 10002,
                params: ['sys.float.ohos_id_text_size_body2'],
                'bundleName': '__harDefaultBundleName__',
                'moduleName': '__harDefaultModuleName__'
            });
            Text.fontColor(item.isConnected ? (!this.isDarkMode ? {
                'id': -1,
                'type': 10001,
                params: ['sys.color.font_emphasize'],
                'bundleName': '__harDefaultBundleName__',
                'moduleName': '__harDefaultModuleName__'
            } : {
                'id': -1,
                'type': 10001,
                params: ['sys.color.font_primary'],
                'bundleName': '__harDefaultBundleName__',
                'moduleName': '__harDefaultModuleName__'
            }) :
                (!this.isDarkMode ? {
                    'id': -1,
                    'type': 10001,
                    params: ['sys.color.font_primary'],
                    'bundleName': '__harDefaultBundleName__',
                    'moduleName': '__harDefaultModuleName__'
                } : {
                    'id': -1,
                    'type': 10001,
                    params: ['sys.color.font_secondary'],
                    'bundleName': '__harDefaultBundleName__',
                    'moduleName': '__harDefaultModuleName__'
                }));
            Text.width(254);
            Text.padding({
                left: 8,
                top: 11,
                right: 8,
                bottom: 11
            });
            Text.textOverflow({ overflow: TextOverflow.Ellipsis });
            Text.maxLines(2);
            Text.wordBreak(WordBreak.BREAK_ALL);
            Text.direction(this.isRTL ? Direction.Rtl : Direction.Ltr);
        }, Text);
        Text.pop();
    }

    deviceMenu(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
            Column.width(326);
            Column.borderRadius(8);
        }, Column);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            ForEach.create();
            const forEachItemGenFunction = (_item, index) => {
                const item = _item;
                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    Flex.create({
                        direction: FlexDirection.Column,
                        justifyContent: FlexAlign.SpaceBetween,
                        alignItems: ItemAlign.End
                    });
                    Flex.width('100%');
                    Flex.onClick(() => {
                        console.info(TAG, ` item click ${item.isConnected}`);
                        if (this.extensionProxy !== null && !item.isConnected) {
                            this.extensionProxy.send({ 'selectedDeviceInfo': item });
                        }
                    });
                }, Flex);
                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    Flex.create({
                        direction: FlexDirection.Row,
                        justifyContent: FlexAlign.SpaceBetween,
                        alignItems: ItemAlign.Center
                    });
                    Flex.constraintSize({ minHeight: 40 });
                    Flex.padding({ left: 12, right: 12 });
                    Flex.onTouch((event) => {
                        if (event.type === TouchType.Down) {
                            this.touchMenuItemIndex = index;
                        } else if (event.type === TouchType.Up) {
                            this.touchMenuItemIndex = -1;
                        }
                    });
                    Flex.backgroundColor(this.touchMenuItemIndex === index ? {
                        'id': -1,
                        'type': 10001,
                        params: ['sys.color.interactive_click'],
                        'bundleName': '__harDefaultBundleName__',
                        'moduleName': '__harDefaultModuleName__'
                    } : '#00FFFFFF');
                    Flex.borderRadius(this.touchMenuItemIndex === index ? {
                        'id': -1,
                        'type': 10002,
                        params: ['sys.float.corner_radius_level2'],
                        'bundleName': '__harDefaultBundleName__',
                        'moduleName': '__harDefaultModuleName__'
                    } : 0);
                }, Flex);
                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    Row.create();
                    Row.alignItems(VerticalAlign.Center);
                }, Row);
                this.iconBuilder.bind(this)(item, false);
                this.textBuilder.bind(this)(item);
                Row.pop();
                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    If.create();
                    if (item.isConnected && item.selectedIconName !== null && item.selectedIconName !== undefined) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                Row.create();
                                Row.alignItems(VerticalAlign.Center);
                            }, Row);
                            this.iconBuilder.bind(this)(item, true);
                            Row.pop();
                        });
                    } else {
                        this.ifElseBranchUpdateFunction(1, () => {
                        });
                    }
                }, If);
                If.pop();
                Flex.pop();
                this.observeComponentCreation2((elmtId, isInitialRender) => {
                    If.create();
                    if (index !== this.deviceInfoList.length - 1) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.observeComponentCreation2((elmtId, isInitialRender) => {
                                Row.create();
                                Row.width('100%');
                                Row.height(2);
                            }, Row);
                            Row.pop();
                        });
                    } else {
                        this.ifElseBranchUpdateFunction(1, () => {
                        });
                    }
                }, If);
                If.pop();
                Flex.pop();
            };
            this.forEachUpdateFunction(elmtId, this.deviceInfoList, forEachItemGenFunction, undefined, true, false);
        }, ForEach);
        ForEach.pop();
        Column.pop();
    }

    buildDefaultPicker(isCustomPicker, parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            UIExtensionComponent.create({
                abilityName: 'AVInputCastPickerAbility',
                bundleName: 'com.hmos.mediacontroller',
                parameters: {
                    'ability.want.params.uiExtensionType': 'sysPicker/mediaControl',
                    'isCustomPicker': isCustomPicker,
                }
            });
            UIExtensionComponent.size({ width: '100%', height: '100%' });
            UIExtensionComponent.bindMenu({
                builder: () => {
                    this.deviceMenu.call(this);
                }
            }, {
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
            });
            UIExtensionComponent.onClick(() => {
                this.pickerClickTime = new Date().getTime();
            });
            UIExtensionComponent.onRemoteReady((proxy) => {
                console.info(TAG, 'onRemoteReady');
                this.extensionProxy = proxy;
            });
            UIExtensionComponent.onReceive((data) => {
                if (JSON.stringify(data['deviceInfoList']) !== undefined) {
                    this.deviceInfoList = JSON.parse(JSON.stringify(data['deviceInfoList']));
                }
                if (JSON.stringify(data['isDarkMode']) !== undefined) {
                    console.info(TAG, `isDarkMode : ${JSON.stringify(data['isDarkMode'])}`);
                    this.isDarkMode = data['isDarkMode'];
                }
                if (JSON.stringify(data['isRTL']) !== undefined) {
                    console.info(TAG, `isRTL : ${JSON.stringify(data['isRTL'])}`);
                    this.isRTL = data['isRTL'];
                }
            });
            UIExtensionComponent.onTerminated((info) => {
                console.info(TAG, ` onTerminated code: ${info?.code}`);
            });
            UIExtensionComponent.onError((error) => {
                console.info(TAG, ` onError code: ${error?.code} message: ${error?.message}`);
            });
        }, UIExtensionComponent);
    }

    buildCustomPicker(parent = null) {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Stack.create({ alignContent: Alignment.Center });
            Stack.size({ width: '100%', height: '100%' });
        }, Stack);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
            Column.alignItems(HorizontalAlign.Center);
            Column.justifyContent(FlexAlign.Center);
            Column.size({ width: '100%', height: '100%' });
            Column.zIndex(0);
        }, Column);
        this.customPicker.bind(this)();
        Column.pop();
        this.observeComponentCreation2((elmtId, isInitialRender) => {
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

    initialRender() {
        this.observeComponentCreation2((elmtId, isInitialRender) => {
            Column.create();
            Column.size({ width: '100%', height: '100%' });
        }, Column);
        this.observeComponentCreation2((elmtId, isInitialRender) => {
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

    rerender() {
        this.updateDirtyElements();
    }
}

export default AVInputCastPicker;