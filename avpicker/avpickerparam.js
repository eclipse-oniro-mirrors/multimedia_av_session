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

export let AVCastPickerState;
(function(c) {
  c[c.STATE_APPEARING = 0] = 'STATE_APPEARING';
  c[c.STATE_DISAPPEARING = 1] = 'STATE_DISAPPEARING';
})(AVCastPickerState || (AVCastPickerState = {}));

export let AVCastPickerStyle;
(function(b) {
  b[b.STYLE_PANEL = 0] = 'STYLE_PANEL';
  b[b.STYLE_MENU = 1] = 'STYLE_MENU';
})(AVCastPickerStyle || (AVCastPickerStyle = {}));

export let AVCastPickerColorMode;
(function(a) {
  a[a.AUTO = 0] = 'AUTO';
  a[a.DARK = 1] = 'DARK';
  a[a.LIGHT = 1] = 'LIGHT';
})(AVCastPickerColorMode || (AVCastPickerColorMode = {}));

export class AVCastPickerParam {
  // param class no need to extends ViewPU
}
export default {AVCastPickerState, AVCastPickerStyle, AVCastPickerColorMode};