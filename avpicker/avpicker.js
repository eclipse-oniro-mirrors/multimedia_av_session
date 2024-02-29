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

export var AVCastPickerState;
!function(e) {
  e[e.STATE_APPEARING = 0] = 'STATE_APPEARING';
  e[e.STATE_DISAPPEARING = 1] = 'STATE_DISAPPEARING';
}(AVCastPickerState || (AVCastPickerState = {}));

export class AVCastPicker extends ViewPU {
  constructor(e, t, o, n = -1) {
    super(e, o, n);
    this.__normalColor = new SynchedPropertySimpleOneWayPU(t.normalColor, this, 'normalColor');
    this.__activeColor = new SynchedPropertySimpleOneWayPU(t.activeColor, this, 'activeColor');
    this.onStateChange = void 0;
    this.setInitiallyProvidedValue(t);
  }

  setInitiallyProvidedValue(e) {
    void 0 === e.normalColor && this.__normalColor.set('#000000');
    void 0 === e.activeColor && this.__activeColor.set('#000000');
    void 0 !== e.onStateChange && (this.onStateChange = e.onStateChange);
  }

  updateStateVars(e) {
    this.__normalColor.reset(e.normalColor);
    this.__activeColor.reset(e.activeColor);
  }

  purgeVariableDependenciesOnElmtId(e) {
    this.__normalColor.purgeDependencyOnElmtId(e);
    this.__activeColor.purgeDependencyOnElmtId(e);
  }

  aboutToBeDeleted() {
    this.__normalColor.aboutToBeDeleted();
    this.__activeColor.aboutToBeDeleted();
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }

  get normalColor() {
    return this.__normalColor.get();
  }

  set normalColor(e) {
    this.__normalColor.set(e);
  }

  get activeColor() {
    return this.__activeColor.get();
  }

  set activeColor(e) {
    this.__activeColor.set(e);
  }

  initialRender() {
    this.observeComponentCreation2(((e, t) => {
      Column.create();
      Column.size({ width: '100%', height: '100%' });
    }), Column);
    this.observeComponentCreation2(((e, t) => {
      UIExtensionComponent.create({
        abilityName: 'UIExtAbility',
        bundleName: 'com.hmos.mediacontroller',
        parameters: { normalColor: this.normalColor }
      });
      UIExtensionComponent.onReceive((e => {
        console.info(TAG, `picker state change : ${JSON.stringify(e.state)}`);
        null != this.onStateChange && (parseInt(JSON.stringify(e.state)) === AVCastPickerState.STATE_APPEARING ?
          this.onStateChange(AVCastPickerState.STATE_APPEARING) :
          this.onStateChange(AVCastPickerState.STATE_DISAPPEARING));
      }));
      UIExtensionComponent.size({ width: '100%', height: '100%' });
    }), UIExtensionComponent);
    Column.pop();
  }

  rerender() {
    this.updateDirtyElements();
  }
}
export default AVCastPicker;