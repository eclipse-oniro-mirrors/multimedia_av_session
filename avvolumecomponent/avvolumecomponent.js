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
var AVVolumeSliderStyle;
(function (c4) {
  c4[c4["OutSet"] = 0] = "OutSet";
  c4[c4["InSet"] = 1] = "InSet";
})(AVVolumeSliderStyle || (AVVolumeSliderStyle = {}));
class AVVolumeSliderParameter {
}
var AVVolumeStyle;
(function (b4) {
  b4[b4["SYSTEM_BAR"] = 0] = "SYSTEM_BAR";
  b4[b4["SLIDER_OVERLAY"] = 1] = "SLIDER_OVERLAY";
})(AVVolumeStyle || (AVVolumeStyle = {}));
export class AVVolumeComponent extends ViewPU {
  constructor(v3, w3, x3, y3 = -1, z3 = undefined,a4) {
    super(v3, x3, y3, a4);
    if (typeof z3 === "function") {
      this.paramsGenerator_ = z3;
    }
    this.__volumeLevel = new SynchedPropertySimpleOneWayPU(w3.volumeLevel, this, "volumeLevel");
    this.__sliderParameter = new SynchedPropertyObjectOneWayPU(w3.sliderParameter, this, "sliderParameter");
    this.__volumeStyle = new SynchedPropertySimpleOneWayPU(w3.volumeStyle, this, "volumeStyle");
    this.__sliderDirection = new SynchedPropertySimpleOneWayPU(w3.sliderDirection, this, "sliderDirection");
    this.__sliderBlockColor = new SynchedPropertyObjectOneWayPU(w3.sliderBlockColor, this, "sliderBlockColor");
    this.__sliderTrackColor = new SynchedPropertyObjectOneWayPU(w3.sliderTrackColor, this, "sliderTrackColor");
    this.__sliderSelectedColor = new SynchedPropertyObjectOneWayPU(w3.sliderSelectedColor, this, "sliderSelectedColor");
    this.__sliderTrackThickness = new SynchedPropertySimpleOneWayPU(w3.sliderTrackThickness, this, "sliderTrackThickness");
    this.__sliderStyle = new SynchedPropertySimpleOneWayPU(w3.sliderStyle, this, "sliderStyle");
    this.__sliderThumbImage = new SynchedPropertyObjectOneWayPU(w3.sliderThumbImage, this, "sliderThumbImage");
    this.__sliderPosition = new SynchedPropertyObjectOneWayPU(w3.sliderPosition, this, "sliderPosition");
    this.__sliderSize = new SynchedPropertyObjectOneWayPU(w3.sliderSize, this, "sliderSize");
    this.volumeCallback = undefined;
    this.setInitiallyProvidedValue(w3);
    this.declareWatch("volumeLevel", this.volumeChange);
    this.finalizeConstruction();
  }
  setInitiallyProvidedValue(u3) {
    if (u3.volumeLevel === undefined) {
      this.__volumeLevel.set(0);
    }
    if (u3.volumeCallback !== undefined) {
      this.volumeCallback = u3.volumeCallback;
    }
  }
  updateStateVars(t3) {
    this.__volumeLevel.reset(t3.volumeLevel);
    this.__sliderParameter.reset(t3.sliderParameter);
    this.__volumeStyle.reset(t3.volumeStyle);
    this.__sliderDirection.reset(t3.sliderDirection);
    this.__sliderBlockColor.reset(t3.sliderBlockColor);
    this.__sliderTrackColor.reset(t3.sliderTrackColor);
    this.__sliderSelectedColor.reset(t3.sliderSelectedColor);
    this.__sliderTrackThickness.reset(t3.sliderTrackThickness);
    this.__sliderStyle.reset(t3.sliderStyle);
    this.__sliderThumbImage.reset(t3.sliderThumbImage);
    this.__sliderPosition.reset(t3.sliderPosition);
    this.__sliderSize.reset(t3.sliderSize);
  }
  purgeVariableDependenciesOnElmtId(s3) {
    this.__volumeLevel.purgeDependencyOnElmtId(s3);
    this.__sliderParameter.purgeDependencyOnElmtId(s3);
    this.__volumeStyle.purgeDependencyOnElmtId(s3);
    this.__sliderDirection.purgeDependencyOnElmtId(s3);
    this.__sliderBlockColor.purgeDependencyOnElmtId(s3);
    this.__sliderTrackColor.purgeDependencyOnElmtId(s3);
    this.__sliderSelectedColor.purgeDependencyOnElmtId(s3);
    this.__sliderTrackThickness.purgeDependencyOnElmtId(s3);
    this.__sliderStyle.purgeDependencyOnElmtId(s3);
    this.__sliderThumbImage.purgeDependencyOnElmtId(s3);
    this.__sliderPosition.purgeDependencyOnElmtId(s3);
    this.__sliderSize.purgeDependencyOnElmtId(s3);
  }
  aboutToBeDeleted() {
    this.__volumeLevel.aboutToBeDeleted();
    this.__sliderParameter.aboutToBeDeleted();
    this.__volumeStyle.aboutToBeDeleted();
    this.__sliderDirection.aboutToBeDeleted();
    this.__sliderBlockColor.aboutToBeDeleted();
    this.__sliderTrackColor.aboutToBeDeleted();
    this.__sliderSelectedColor.aboutToBeDeleted();
    this.__sliderTrackThickness.aboutToBeDeleted();
    this.__sliderStyle.aboutToBeDeleted();
    this.__sliderThumbImage.aboutToBeDeleted();
    this.__sliderPosition.aboutToBeDeleted();
    this.__sliderSize.aboutToBeDeleted();
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }
  get volumeLevel() {
    return this.__volumeLevel.get();
  }
  set volumeLevel(r3) {
    this.__volumeLevel.set(r3);
  }
  get sliderParameter() {
    return this.__sliderParameter.get();
  }
  set sliderParameter(q3) {
    this.__sliderParameter.set(q3);
  }
  get volumeStyle() {
    return this.__volumeStyle.get();
  }
  set volumeStyle(p3) {
    this.__volumeStyle.set(p3);
  }
  get sliderDirection() {
    return this.__sliderDirection.get();
  }
  set sliderDirection(o3) {
    this.__sliderDirection.set(o3);
  }
  get sliderBlockColor() {
    return this.__sliderBlockColor.get();
  }
  set sliderBlockColor(n3) {
    this.__sliderBlockColor.set(n3);
  }
  get sliderTrackColor() {
    return this.__sliderTrackColor.get();
  }
  set sliderTrackColor(m3) {
    this.__sliderTrackColor.set(m3);
  }
  get sliderSelectedColor() {
    return this.__sliderSelectedColor.get();
  }
  set sliderSelectedColor(l3) {
    this.__sliderSelectedColor.set(l3);
  }
  get sliderTrackThickness() {
    return this.__sliderTrackThickness.get();
  }
  set sliderTrackThickness(k3) {
    this.__sliderTrackThickness.set(k3);
  }
  get sliderStyle() {
    return this.__sliderStyle.get();
  }
  set sliderStyle(j3) {
    this.__sliderStyle.set(j3);
  }
  get sliderThumbImage() {
    return this.__sliderThumbImage.get();
  }
  set sliderThumbImage(i3) {
    this.__sliderThumbImage.set(i3);
  }
  get sliderPosition() {
    return this.__sliderPosition.get();
  }
  set sliderPosition(h3) {
    this.__sliderPosition.set(h3);
  }
  get sliderSize() {
    return this.__sliderSize.get();
  }
  set sliderSize(g3) {
    this.__sliderSize.set(g3);
  }
  volumeChange() {
    console.info(TAG, `volumechange volumeLevel = ` + this.volumeLevel);
    this.volumeCallback.send({'volume': this.volumeLevel});
  }
  initialRender() {
    this.observeComponentCreation2((e3, f3) => {
      Column.create();
      Column.size({width: '100%', height: '100%'});
    }, Column);
    this.observeComponentCreation2((y2, z2) => {
      UIExtensionComponent.create({
        abilityName: 'AVVolumeExtension',
        bundleName: 'com.huawei.hmos.mediacontroller',
        parameters: {
          "volumeStyle": this.volumeStyle,
          "sliderParameter": this.sliderParameter,
          "sliderDirection": this.sliderDirection,
          "sliderBlockColor": this.sliderBlockColor,
          "sliderTrackColor": this.sliderTrackColor,
          "sliderSelectedColor": this.sliderSelectedColor,
          "sliderTrackThickness": this.sliderTrackThickness,
          "sliderStyle": this.sliderStyle,
          "sliderThumbImage": this.sliderThumbImage,
          "sliderPosition": this.sliderPosition,
          "sliderSize": this.sliderSize
        }
      });
      UIExtensionComponent.onReceive((d3) => {
        console.info(TAG, `onReceive : ${JSON.stringify(d3['state'])}`);
      });
      UIExtensionComponent.onRemoteReady((c3) => {
        console.info(TAG, `onRemoteReady callback : ${JSON.stringify(c3)}`);
        this.volumeCallback = c3;
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