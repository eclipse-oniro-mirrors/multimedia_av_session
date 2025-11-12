/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { Component, UIExtensionComponent, UIExtensionProxy, Column, Position } from '@ohos.arkui.component';
import { Watch, PropRef } from '@ohos.arkui.stateManagement'
import Want from '@ohos.app.ability.Want'
import { RecordData } from '@ohos.base';

const TAG = 'AVVolumePanel';

class AVVolumePanelParameter {
  public position?: Position;
}

@Component
export struct AVVolumePanel {
  @PropRef@Watch('volumeChange')
  volumeLevel?: int = 0;
  @PropRef
  volumeParameter: AVVolumePanelParameter;

  /*
   * UIExtensionProxy.
   */
  private volumeCallback!: UIExtensionProxy;
  private panelCountOncreation: number = 0;

  private static currentPanelCount: number = 0;

  volumeChange(volumeChange : string) {
    if (this.volumeCallback != null) {
      console.info(TAG, `volumeChange volumeLevel = ` + this.volumeLevel);
      this.volumeCallback.send({'volume': this.volumeLevel});
    }
  }

  aboutToAppear(): void {
    AVVolumePanel.currentPanelCount += 1;
    this.panelCountOncreation = AVVolumePanel.currentPanelCount;
  }

  aboutToDisAppear(): void {
    AVVolumePanel.currentPanelCount -= 1;
  }

  build() {
    Column() {
      UIExtensionComponent(
        {
          abilityName: 'AVVolumeExtension',
          bundleName: 'com.hmos.mediacontroller',
          parameters: {
            'volumeParameter': this.volumeParameter,
            'ability.want.params.uiExtensionType': 'sysPicker/mediaControl',
            'currentPanelCount': this.panelCountOncreation,
          } as Record<string, RecordData>
        } as Want)
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