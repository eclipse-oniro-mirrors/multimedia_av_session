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
var AVVolumeStyle;
(function (v) {
  v[v["SYSTEM_BAR"] = 0] = "SYSTEM_BAR";
})(AVVolumeStyle || (AVVolumeStyle = {}));
export class AVVolumeComponent extends ViewPU {
  constructor(p, q, r, s = -1, t = undefined, u) {
    super(p, r, s, u);
    if (typeof t === "function") {
      this.paramsGenerator_ = t;
    }
    this.__volumeLevel = new SynchedPropertySimpleOneWayPU(q.volumeLevel, this, "volumeLevel");
    this.__volumeStyle = new SynchedPropertySimpleOneWayPU(q.volumeStyle, this, "volumeStyle");
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
    this.__volumeStyle.reset(n.volumeStyle);
  }
  purgeVariableDependenciesOnElmtId(m) {
    this.__volumeLevel.purgeDependencyOnElmtId(m);
    this.__volumeStyle.purgeDependencyOnElmtId(m);
  }
  aboutToBeDeleted() {
    this.__volumeLevel.aboutToBeDeleted();
    this.__volumeStyle.aboutToBeDeleted();
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }
  get volumeLevel() {
    return this.__volumeLevel.get();
  }
  set volumeLevel(l) {
    this.__volumeLevel.set(l);
  }
  get volumeStyle() {
    return this.__volumeStyle.get();
  }
  set volumeStyle(k) {
    this.__volumeStyle.set(k);
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
          "volumeStyle": this.volumeStyle,
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