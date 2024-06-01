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

if (!('finalizeConstruction' in ViewPU.prototype)) {
  Reflect.set(ViewPU.prototype, 'finalizeConstruction', () => { });
}

const TAG = 'avpicker_component_mock ';

export class AVCastPicker extends ViewPU {
  constructor(j2, k2, l2, m2 = -1, n2 = undefined, o2) {
    super(j2, l2, m2, o2);
    if (typeof n2 === 'function') {
      this.paramsGenerator_ = n2;
    }
    this.customPicker = undefined;
    this.setInitiallyProvidedValue(k2);
    this.finalizeConstruction();
  }

  setInitiallyProvidedValue(i2) {
    if (i2.customPicker !== undefined) {
      this.customPicker = i2.customPicker;
    }
  }

  updateStateVars(h2) {
  }

  purgeVariableDependenciesOnElmtId(g2) {
  }

  aboutToBeDeleted() {
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }

  aboutToAppear() {
    console.info(TAG + 'aboutToAppear');
  }

  aboutToDisappear() {
    console.info(TAG + 'aboutToDisappear');
  }

  initialRender() {
    this.observeComponentCreation2((e2, f2) => {
      Column.create();
      Column.size({ width: '100%', height: '100%' });
    }, Column);
    this.observeComponentCreation2((a2, b2) => {
      If.create();
      if (this.customPicker === undefined) {
        this.ifElseBranchUpdateFunction(0, () => {
          this.buildDefaultPicker.bind(this)();
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

  buildDefaultPicker(o1 = null) {
    this.observeComponentCreation2((w1, x1) => {
      Column.create();
      Column.size({ width: '100%', height: '100%' });
    }, Column);
    this.observeComponentCreation2((u1, v1) => {
      Button.createWithChild();
      Button.type(ButtonType.Circle);
      Button.backgroundColor('#00000000');
      Button.size({ width: '100%', height: '100%' });
    }, Button);
    this.observeComponentCreation2((s1, t1) => {
      Image.create({'id': -1, 'type': 20000, params: ['sys.media.ohos_ic_public_cast_stream'],
        'bundleName': '__harDefaultBundleName__', 'moduleName': '__harDefaultModuleName__'});
      Image.size({ width: '100%', height: '100%' });
      Image.draggable(false);
    }, Image);
    Button.pop();
    Column.pop();
  }

  buildCustomPicker(h1 = null) {
    this.observeComponentCreation2((m1, n1) => {
      Column.create();
      Column.size({ width: '100%', height: '100%' });
    }, Column);
    this.observeComponentCreation2((k1, l1) => {
      Button.createWithChild();
      Button.type(ButtonType.Circle);
      Button.backgroundColor('#00000000');
      Button.size({ width: '100%', height: '100%' });
    }, Button);
    this.customPicker.bind(this)();
    Button.pop();
    Column.pop();
  }

  rerender() {
    this.updateDirtyElements();
  }
}

export default AVCastPicker;
