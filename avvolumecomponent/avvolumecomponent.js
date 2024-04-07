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
const TAG = 'avvolumecomponent ';
class AVVolumeSliderParameter {
}
export class AVVolumeComponent extends ViewPU {
  constructor(q, r, s, t = -1, u = undefined, v) {
    super(q, s, t, v);
    if (typeof u === "function") {
      this.paramsGenerator_ = u;
    }
    this.__volumeLevel = new SynchedPropertySimpleOneWayPU(r.volumeLevel, this, "volumeLevel");
    this.__sliderParameter = new SynchedPropertyObjectOneWayPU(r.sliderParameter, this, "sliderParameter");
    this.__sliderPosition = new SynchedPropertyObjectOneWayPU(r.sliderPosition, this, "sliderPosition");
    this.volumeCallback = undefined;
    this.setInitiallyProvidedValue(r);
    this.declareWatch("volumeLevel", this.volumeChange);
    this.finalizeConstruction();
  }
  setInitiallyProvidedValue(p) {
    if (p.volumeLevel === undefined) {
      this.__volumeLevel.set(0);
    }
    if (p.volumeCallback !== undefined) {
      this.volumeCallback = p.volumeCallback;
    }
  }
  updateStateVars(o) {
    this.__volumeLevel.reset(o.volumeLevel);
    this.__sliderParameter.reset(o.sliderParameter);
    this.__sliderPosition.reset(o.sliderPosition);
  }
  purgeVariableDependenciesOnElmtId(n) {
    this.__volumeLevel.purgeDependencyOnElmtId(n);
    this.__sliderParameter.purgeDependencyOnElmtId(n);
    this.__sliderPosition.purgeDependencyOnElmtId(n);
  }
  aboutToBeDeleted() {
    this.__volumeLevel.aboutToBeDeleted();
    this.__sliderParameter.aboutToBeDeleted();
    this.__sliderPosition.aboutToBeDeleted();
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }
  get volumeLevel() {
    return this.__volumeLevel.get();
  }
  set volumeLevel(m) {
    this.__volumeLevel.set(m);
  }
  get sliderParameter() {
    return this.__sliderParameter.get();
  }
  set sliderParameter(l) {
    this.__sliderParameter.set(l);
  }
  get sliderPosition() {
    return this.__sliderPosition.get();
  }
  set sliderPosition(k) {
    this.__sliderPosition.set(k);
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
          'sliderParameter': this.sliderParameter,
          'sliderPosition': this.sliderPosition,
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
export default AVVolumeComponent;