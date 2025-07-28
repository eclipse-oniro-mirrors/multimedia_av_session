/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
const MAX_PANEL_LIMIT = 20;

class AVVolumePanelParameter {
  public position?: Position;
}

@Component
export struct AVVolumePanel {
  @Prop@Watch('volumeChange')
  volumeLevel?: number = 0;
  @Prop
  volumeParameter?: AVVolumePanelParameter;

  /*
   * UIExtensionProxy.
   */
  private volumeCallback!: UIExtensionProxy;
  private panelCountOncreation: number = 0;
  @State isDisabledByPanelLimit: boolean = false;

  private static currentPanelCount: number = 0;

  volumeChange() {
    if (this.volumeCallback != null) {
      console.info(TAG, `volumeChange volumeLevel = ` + this.volumeLevel);
      this.volumeCallback.send({'volume': this.volumeLevel});
    }
  }

  aboutToAppear(): void {
    AVVolumePanel.currentPanelCount += 1;
    this.panelCountOncreation = AVVolumePanel.currentPanelCount;
    if (this.panelCountOncreation > MAX_PANEL_LIMIT) {
      console.info(TAG, 'disable panel');
      this.isDisabledByPanelLimit = true;
    }
  }

  aboutToDisAppear(): void {
    AVVolumePanel.currentPanelCount -= 1;
  }

  build() {
    Column() {
      if (this.isDisabledByPanelLimit) {
        Column();
      } else {
        UIExtensionComponent(
        {
          abilityName: 'AVVolumeExtension',
          bundleName: 'com.hmos.mediacontroller',
          parameters: {
            'volumeParameter': this.volumeParameter,
            'ability.want.params.uiExtensionType': 'sysPicker/mediaControl',
            'currentPanelCount': this.panelCountOncreation,
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
      }
    }.size({width: '100%', height: '100%'})
  }
}