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

if (!("finalizeConstruction" in ViewPU.prototype)) {
    Reflect.set(ViewPU.prototype, "finalizeConstruction", () => { });
}

const TAG = 'avcastpicker_component ';

export var AVCastPickerState;
(function(a3) {
    a3[a3.STATE_APPEARING = 0] = 'STATE_APPEARING';
    a3[a3.STATE_DISAPPEARING = 1] = 'STATE_DISAPPEARING';
})(AVCastPickerState || (AVCastPickerState = {}));

export var AVCastPickerStyle;
(function(z2) {
    z2[z2.STYLE_PANEL = 0] = 'STYLE_PANEL';
    z2[z2.STYLE_MENU = 1] = 'STYLE_MENU';
})(AVCastPickerStyle || (AVCastPickerStyle = {}));

export var DeviceSource;
(function(y2) {
    y2[y2.LOCAL = 0] = 'LOCAL';
    y2[y2.CAST = 1] = 'CAST';
})(DeviceSource || (DeviceSource = {}));

export class AVCastPicker extends ViewPU {
    constructor(s2, t2, u2, v2 = -1, w2 = undefined, x2) {
        super(s2, u2, v2, x2);
        if (typeof w2 === 'function') {
            this.paramsGenerator_ = w2;
        }
        this.__normalColor = new ObservedPropertySimplePU('#000000', this, 'normalColor');
        this.__activeColor = new ObservedPropertySimplePU('#000000', this, 'activeColor');
        this.__deviceList = new ObservedPropertyObjectPU([], this, 'deviceList');
        this.__sessionType = new ObservedPropertySimplePU('audio', this, 'sessionType');
        this.__pickerStyle = new ObservedPropertySimplePU(AVCastPickerStyle.STYLE_PANEL, this, 'pickerStyle');
        this.__isMenuShow = new ObservedPropertySimplePU(false, this, 'isMenuShow');
        this.__touchMenuItemIndex = new ObservedPropertySimplePU(-1, this, 'touchMenuItemIndex');
        this.onStateChange = undefined;
        this.extensionProxy = null;
        this.setInitiallyProvidedValue(t2);
        this.finalizeConstruction();
    }

    setInitiallyProvidedValue(r2) {
        if (r2.normalColor !== undefined) {
            this.normalColor = r2.normalColor;
        }
        if (r2.activeColor !== undefined) {
            this.activeColor = r2.activeColor;
        }
        if (r2.deviceList !== undefined) {
            this.deviceList = r2.deviceList;
        }
        if (r2.sessionType !== undefined) {
            this.sessionType = r2.sessionType;
        }
        if (r2.pickerStyle !== undefined) {
            this.pickerStyle = r2.pickerStyle;
        }
        if (r2.isMenuShow !== undefined) {
            this.isMenuShow = r2.isMenuShow;
        }
        if (r2.touchMenuItemIndex !== undefined) {
            this.touchMenuItemIndex = r2.touchMenuItemIndex;
        }
        if (r2.onStateChange !== undefined) {
            this.onStateChange = r2.onStateChange;
        }
        if (r2.extensionProxy !== undefined) {
            this.extensionProxy = r2.extensionProxy;
        }
    }

    updateStateVars(q2) {
    }

    purgeVariableDependenciesOnElmtId(p2) {
        this.__normalColor.purgeDependencyOnElmtId(p2);
        this.__activeColor.purgeDependencyOnElmtId(p2);
        this.__deviceList.purgeDependencyOnElmtId(p2);
        this.__sessionType.purgeDependencyOnElmtId(p2);
        this.__pickerStyle.purgeDependencyOnElmtId(p2);
        this.__isMenuShow.purgeDependencyOnElmtId(p2);
        this.__touchMenuItemIndex.purgeDependencyOnElmtId(p2);
    }

    aboutToBeDeleted() {
        this.__normalColor.aboutToBeDeleted();
        this.__activeColor.aboutToBeDeleted();
        this.__deviceList.aboutToBeDeleted();
        this.__sessionType.aboutToBeDeleted();
        this.__pickerStyle.aboutToBeDeleted();
        this.__isMenuShow.aboutToBeDeleted();
        this.__touchMenuItemIndex.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }

    get normalColor() {
        return this.__normalColor.get();
    }

    set normalColor(o2) {
        this.__normalColor.set(o2);
    }

    get activeColor() {
        return this.__activeColor.get();
    }

    set activeColor(n2) {
        this.__activeColor.set(n2);
    }

    get deviceList() {
        return this.__deviceList.get();
    }

    set deviceList(m2) {
        this.__deviceList.set(m2);
    }

    get sessionType() {
        return this.__sessionType.get();
    }

    set sessionType(l2) {
        this.__sessionType.set(l2);
    }

    get pickerStyle() {
        return this.__pickerStyle.get();
    }

    set pickerStyle(k2) {
        this.__pickerStyle.set(k2);
    }

    get isMenuShow() {
        return this.__isMenuShow.get();
    }

    set isMenuShow(j2) {
        this.__isMenuShow.set(j2);
    }

    get touchMenuItemIndex() {
        return this.__touchMenuItemIndex.get();
    }

    set touchMenuItemIndex(i2) {
        this.__touchMenuItemIndex.set(i2);
    }

    deviceMenu(l = null) {
        this.observeComponentCreation2((g2, h2) => {
            Column.create();
            Column.width(216);
        }, Column);
        this.observeComponentCreation2((o, p) => {
            ForEach.create();
            const q = (s, t) => {
                const u = s;
                this.observeComponentCreation2((d2, e2) => {
                    Flex.create({
                        direction: FlexDirection.Column,
                        justifyContent: FlexAlign.SpaceBetween,
                        alignItems: ItemAlign.End
                    });
                    Flex.width('100%');
                    Flex.onClick(() => {
                        if (this.extensionProxy != null && !u.isConnected) {
                            this.extensionProxy.send({ 'selectedDeviceInfo': u });
                        }
                    });
                }, Flex);
                this.observeComponentCreation2((z1, a2) => {
                    Flex.create({
                        direction: FlexDirection.Row,
                        justifyContent: FlexAlign.SpaceBetween,
                        alignItems: ItemAlign.Center
                    });
                    Flex.constraintSize({ minHeight: 48 });
                    Flex.padding({ left: 12, right: 12 });
                    Flex.onTouch((c2) => {
                        if (c2.type === TouchType.Down) {
                            this.touchMenuItemIndex = t;
                        }
                        else if (c2.type === TouchType.Up) {
                            this.touchMenuItemIndex = -1;
                        }
                    });
                    Flex.backgroundColor(this.touchMenuItemIndex === t ? { 'id': -1, 'type': 10001,
                        params: ['sys.color.ohos_id_color_click_effect'], 'bundleName': '__harDeafultBundleName__',
                        'moudelName': '__harDeafultBundleName__' } : '#00FFFFFF');
                    Flex.borderRadius(this.touchMenuItemIndex === t ? { 'id': -1, 'type': 10002,
                        params: ['sys.float.ohos_id_corner_radius_default_m'], 'bundleName': '__harDeafultBundleName__',
                        'moudelName': '__harDeafultBundleName__' } : 0)
                }, Flex);
                this.observeComponentCreation2((x1, y1) => {
                    Row.create();
                    Row.justifyContent(FlexAlign.Start);
                    Row.alignItems(VerticalAlign.Center);
                }, Row);
                this.observeComponentCreation2((v1, w1) => {
                    Image.create({ 'id': -1, 'type': -1,
                        params: ['u.deviceIconName'], 'bundleName': '__harDeafultBundleName__',
                        'moudelName': '__harDeafultBundleName__' });
                    Image.width(24);
                    Image.height(24);
                }, Image);
                this.observeComponentCreation2((t1, u1) => {
                    Text.create(u.deviceName);
                    Text.fontSize({ 'id': -1, 'type': 10002,
                        params: ['sys.float.ohos_id_text_size_body1'], 'bundleName': '__harDeafultBundleName__',
                        'moudelName': '__harDeafultBundleName__' });
                    Text.fontColor(u.isConnected ? { 'id': -1, 'type': 10001,
                        params: ['sys.color.ohos_id_color_text_primary_activated'], 'bundleName': '__harDeafultBundleName__',
                        'moudelName': '__harDeafultBundleName__' } : { 'id': -1, 'type': 10001,
                        params: ['sys.color.ohos_id_color_text_primary'], 'bundleName': '__harDeafultBundleName__',
                        'moudelName': '__harDeafultBundleName__' });
                    Text.width(u.isConnected ? 144 : 168)
                    Text.padding({
                        left: 8,
                        top: 12,
                        right: 18,
                        bottom: 12
                    })
                }, Text);
                Text.pop();
                Row.pop();
                this.observeComponentCreation2((j1, k1) => {
                    If.create();
                    if (u.isConnected && u.selectedIconName !== null && u.selectedIconName !== undefined) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.observeComponentCreation2((r1, s1) => {
                                Row.create();
                                Row.justifyContent(FlexAlign.Start);
                                Row.alignItems(VerticalAlign.Center);
                            }, Row);
                            this.observeComponentCreation2((p1, q1) => {
                                Image.create({ 'id': -1, 'type': -1,
                                    params: ['u.selectedIconName'], 'bundleName': '__harDeafultBundleName__',
                                    'moudelName': '__harDeafultBundleName__' });
                                Image.width(24);
                                Image.height(24);
                                Image.fillColor({ 'id': -1, 'type': 10001,
                                    params: ['sys.color.ohos_id_color_activated'], 'bundleName': '__harDeafultBundleName__',
                                    'moudelName': '__harDeafultBundleName__' });
                            }, Image);
                            Row.pop();
                        })
                    }
                    else {
                        this.ifElseBranchUpdateFunction(1, () => {
                        });
                    }
                }, If);
                If.pop();
                Flex.pop();
                this.observeComponentCreation2((c1, d1) => {
                    If.create();
                    if (t !== this.deviceList.length - 1) {
                        this.ifElseBranchUpdateFunction(0, () => {
                            this.observeComponentCreation2((h1, i1) => {
                                Divider.create();
                                Divider.height(1);
                                Divider.width(172);
                                Divider.color({ 'id': -1, 'type': 10001,
                                    params: ['sys.color.ohos_id_color_list_separator'], 'bundleName': '__harDeafultBundleName__',
                                    'moudelName': '__harDeafultBundleName__' });
                                Divider.padding({ right: 12 });
                            }, Divider);
                        });
                    }
                    else {
                        this.ifElseBranchUpdateFunction(1, () => {
                        });
                    }
                }, If);
                If.pop();
                Flex.pop();
            };
            this.forEachUpdateFunction(o, this.deviceList, q, undefined, true, false);
        }, ForEach);
        ForEach.pop();
        Column.pop();
    }

    initialRender() {
        this.observeComponentCreation2((j, k) => {
            Column.create();
            Column.size({ width: '100%', height: '100%' });
        }, Column);
        this.observeComponentCreation2(((c, d) => {
            UIExtensionComponent.create({
                abilityName: 'UIExtAbility',
                bundleName: 'com.hmos.mediacontroller',
                parameters: {
                    'normalColor': this.normalColor, 
                    'avCastPickerStyle': this.pickerStyle,
                    'ability.want.params.uiExtensionType': 'sys/commonUI',
                }
            });
            UIExtensionComponent.onRemoteReady((i) => {
                console.info(TAG, 'onRemoteReady');
                this.extensionProxy = i;
            });
            UIExtensionComponent.onReceive((h) => {
                if (JSON.stringify(h.state) !== undefined) {
                    console.info(TAG, `picker state change : ${JSON.stringify(h.state)}`);
                    if (this.onStateChange != null) {
                        if (parseInt(JSON.stringify(h.state)) === AVCastPickerState.STATE_APPEARING) {
                            this.onStateChange(AVCastPickerState.STATE_APPEARING);
                        }
                        else {
                            this.onStateChange(AVCastPickerState.STATE_DISAPPEARING);
                        }
                    }
                }

                if (JSON.stringify(h.deviceList) !== undefined) {
                    console.info(TAG, `picker device list : ${JSON.stringify(h.deviceList)}`);
                    this.deviceList = JSON.parse(JSON.stringify(h.deviceList));
                    if ((this.pickerStyle === AVCastPickerStyle.STYLE_MENU && this.deviceList?.length < 3
                      && (this.sessionType === 'voice_call' || this.sessionType === 'video_call'))
                      || this.pickerStyle === AVCastPickerStyle.STYLE_PANEL) {
                      this.isMenuShow = false;
                    }
                }

                if (JSON.stringify(h.pickerStyle) !== undefined) {
                    console.info(TAG, `picker style : ${JSON.stringify(h.pickerStyle)}`);
                    this.pickerStyle = h.pickerStyle;
                }

                if (JSON.stringify(h.sessionType) !== undefined) {
                    console.info(TAG, `session type : ${JSON.stringify(h.sessionType)}`);
                    this.sessionType = h.sessionType;
                }

                if (JSON.stringify(h.isShowMenu) !== undefined) {
                    console.info(TAG, `isShowMenu : ${h.isShowMenu}`);
                    this.isMenuShow = h.isShowMenu;
                }
            });
            UIExtensionComponent.size({ width: '100%', height: '100%' });
            UIExtensionComponent.bindMenu(this.isMenuShow, { builder: () => { this.deviceMenu.call(this); }}, {
                placement: Placement.TopRight,
                onDisappear: () => {
                  this.isMenuShow = false;
                }
            });
            UIExtensionComponent.onClick(() => {
                if ((this.pickerStyle === AVCastPickerStyle.STYLE_MENU && this.deviceList?.length < 3
                    && (this.sessionType === 'voice_call' || this.sessionType === 'video_call'))
                    || this.pickerStyle === AVCastPickerStyle.STYLE_PANEL) {
                    this.isMenuShow = false;
                }
                else {
                    this.isMenuShow = !this.isMenuShow;
                }
            });
        }), UIExtensionComponent);
        Column.pop();
    }

    rerender() {
        this.updateDirtyElements();
    }

    static getEntryName() {
        return "AVCastPicker";
    }
}

export default AVCastPicker;