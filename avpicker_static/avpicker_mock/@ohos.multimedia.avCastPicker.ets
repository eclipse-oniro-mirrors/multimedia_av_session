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

import {
  BuilderParam, Component, Column, Row, Builder, Button, ButtonOptions, Image, $r, ButtonType, Circle
} from '@ohos.arkui.component';
import { State, Watch } from '@ohos.arkui.stateManagement'

const TAG = 'avcastpicker_component ';

@Component
export struct AVCastPicker {

  /**
   * Custom builder from application
   */
  @BuilderParam customPicker: () => void = () => {};

  build() {
    Column() {
      if (this.customPicker === undefined) {
        this.buildDefaultPicker();
      } else {
        this.buildCustomPicker();
      }
    }
    .size({width: '100%', height: '100%'})
  }

  @Builder
  private buildDefaultPicker() {
    Column() {
      Button({ type: ButtonType.Normal } as ButtonOptions) {
        Image($r('sys.media.ohos_ic_public_cast_stream'))
          .size({width: '100%', height: '100%'})
          .draggable(false)
      }
      .type(ButtonType.Circle)
      .backgroundColor('#00000000')
      .size({width: '100%', height: '100%'})
    }
    .size({width: '100%', height: '100%'})
  }

  @Builder
  private buildCustomPicker() {
    Column() {
      Button({ type: ButtonType.Normal } as ButtonOptions) {
        this.customPicker();
      }
      .type(ButtonType.Circle)
      .backgroundColor('#00000000')
      .size({width: '100%', height: '100%'})
    }
    .size({width: '100%', height: '100%'})
  }
}