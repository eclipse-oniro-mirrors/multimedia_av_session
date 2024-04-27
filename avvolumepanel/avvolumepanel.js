/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
  Reflect.set(ViewPU.prototype, "finalizeConstruction", () => {});
}
const TAG = 'AVVolumePanel';
class AVVolumePanelParameter {
}
export class AVVolumePanel extends ViewPU {
  constructor(p, q, r, s = -1, t = undefined, u) {
    super(p, r, s, u);
    if (typeof t === "function") {
      this.paramsGenerator_ = t;
    }
    this.__volumeLevel = new SynchedPropertySimpleOneWayPU(q.volumeLevel, this, "volumeLevel");
    this.__volumeParameter = new SynchedPropertyObjectOneWayPU(q.volumeParameter, this, "volumeParameter");
    this.volumeCallback = undefined;
    this.setInitiallyProvidedValue(q);
    this.declareWatch("volumeLevel", this.volumeChange);
    this.finalizeConstruction();
  }
  setInitiallyProvidedValue(o) {
    if (o.volumeLevel === undefined) {
      this.__volumeLevel.set(0);
    }
    if (o.volumeCallback !== undefined) {
      this.volumeCallback = o.volumeCallback;
    }
  }
  updateStateVars(n) {
    this.__volumeLevel.reset(n.volumeLevel);
    this.__volumeParameter.reset(n.volumeParameter);
  }
  purgeVariableDependenciesOnElmtId(m) {
    this.__volumeLevel.purgeDependencyOnElmtId(m);
    this.__volumeParameter.purgeDependencyOnElmtId(m);
  }
  aboutToBeDeleted() {
    this.__volumeLevel.aboutToBeDeleted();
    this.__volumeParameter.aboutToBeDeleted();
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }
  get volumeLevel() {
    return this.__volumeLevel.get();
  }
  set volumeLevel(l) {
    this.__volumeLevel.set(l);
  }
  get volumeParameter() {
    return this.__volumeParameter.get();
  }
  set volumeParameter(k) {
    this.__volumeParameter.set(k);
  }
  volumeChange() {
    console.info(TAG, `volumechange volumeLevel = ` + this.volumeLevel);
    this.volumeCallback.send({'volume': this.volumeLevel});
  }
  initialRender() {
    this.observeComponentCreation2((i, j) => {
      Column.create();
      Column.size({width: '100%', height: '100%'});
    }, Column);
    this.observeComponentCreation2((c, d) => {
      UIExtensionComponent.create({
        abilityName: 'AVVolumeExtension',
        bundleName: 'com.hmos.mediacontroller',
        parameters: {
          'volumeParameter': this.volumeParameter,
          'ability.want.params.uiExtensionType': 'sys/commonUI',
        }
      });
      UIExtensionComponent.onReceive((h) => {
        console.info(TAG, `onReceive : ${JSON.stringify(h['state'])}`);
      });
      UIExtensionComponent.onRemoteReady((g) => {
        console.info(TAG, `onRemoteReady callback : ${JSON.stringify(g)}`);
        this.volumeCallback = g;
      });
      UIExtensionComponent.size({ width: '100%', height: '100%' });
    }, UIExtensionComponent);
    Column.pop();
  }
  rerender() {
    this.updateDirtyElements();
  }
}
export default AVVolumePanel;