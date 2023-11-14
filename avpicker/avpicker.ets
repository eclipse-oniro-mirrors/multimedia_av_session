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

/**
 * Definition of av cast picker state.
 */
export enum AVCastPickerState {
  /**
   * The picker starts showing.
   */
  STATE_APPEARING,

  /**
   * The picker finishes presenting.
   */
  STATE_DISAPPEARING,
}

@Component
export struct AVCastPicker {
  /**
   * Assigns the color of picker component at normal state.
   */
  @Prop normalColor: Color | number | string = '#000000';

  /**
   * Assigns the color of picker component at active state.
   */
  @Prop activeColor: Color | number | string = '#000000';

  /**
   * Picker state change callback.
   */
  private onStateChange?: (state: AVCastPickerState) => void;

  build() {
    Column() {
      UIExtensionComponent(
        {
          abilityName: 'UIExtAbility',
          bundleName: 'com.huawei.hmos.mediacontroller',
          parameters: {"normalColor": this.normalColor}
        })
        .onReceive((data) => {
          console.info(TAG, `picker state change : ${JSON.stringify(data['state'])}`);
          if (this.onStateChange != null) {
            if (parseInt(JSON.stringify(data['state'])) === AVCastPickerState.STATE_APPEARING) {
              this.onStateChange(AVCastPickerState.STATE_APPEARING);
            } else {
              this.onStateChange(AVCastPickerState.STATE_DISAPPEARING);
            }
          }
        })
      .size({width: '100%', height: '100%'})
    }.size({width: '100%', height: '100%'})
  }
}
