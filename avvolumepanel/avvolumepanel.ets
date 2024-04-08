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

const TAG = 'AVVolumePanel';

class AVVolumePanelParameter {
  public position?: Position;
}

@Component
export struct AVVolumePanel {
  @Prop@Watch('volumeChange')
  volumeLevel?: number = 0;
  @Prop
  volumeParameter?: AVVolumePanelParameter;

  volumeCallback!: UIExtensionProxy;

  volumeChange() {
    console.info(TAG, `volumeChange volumeLevel = ` + this.volumeLevel);
    this.volumeCallback.send({'volume': this.volumeLevel});
  }

  build() {
    Column() {
      UIExtensionComponent(
        {
          abilityName: 'AVVolumeExtension',
          bundleName: 'com.hmos.mediacontroller',
          parameters: {
            'volumeParameter': this.volumeParameter,
          }
        })
        .onReceive((data) => {
          console.info(TAG, `onReceive : ${JSON.stringify(data['state'])}`);
        })
        .onRemoteReady((callback: UIExtensionProxy) => {
          console.info(TAG, `onRemoteReady callback : ${JSON.stringify(callback)}`);
          this.volumeCallback = callback;
        })
        .size({width: '100%', height: '100%'})
    }.size({width: '100%', height: '100%'})
  }
}