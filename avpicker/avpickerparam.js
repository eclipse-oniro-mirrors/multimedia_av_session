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

const TAG = 'avcastpickerparam_component ';

export var AVCastPickerState;
!function(e) {
  e[e.STATE_APPEARING = 0] = 'STATE_APPEARING';
  e[e.STATE_DISAPPEARING = 1] = 'STATE_DISAPPEARING';
}(AVCastPickerState || (AVCastPickerState = {}));

export class AVCastPickerParam extends ViewPU {
  constructor(e, t, o, n = -1, m = undefined) {
    super(e, o, n);
    if (typeof m === "funcation") {
        this.paramsGenerator_ = m;
    }
    this.setInitiallyProvidedValue(t);
  }

  setInitiallyProvidedValue(e) {
  }

  updateStateVars(g) {
  }

  purgeVariableDependenciesOnElmtId(e) {
  }

  aboutToBeDeleted() {
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }

  initialRender() {
    this.observeComponentCreation2(((e, t) => {
      Column.create();
      Column.size({ width: '100%', height: '100%' });
    }), Column);
    this.observeComponentCreation2(((e, t) => {
      Text.create();
      Text.size({ width: '100%', height: '100%' });
    }), Text);
    Column.pop();
  }

  rerender() {
    this.updateDirtyElements();
  }
}
export default AVCastPickerState;