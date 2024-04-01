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

const TAG = 'avvolumecomponent';

enum AVVolumeSliderStyle {
  OutSet,
  InSet
}

class AVVolumeSliderParameter {
  private sliderDirection?: Axis;
  private sliderBlockColor?: ResourceColor;
  private sliderTrackColor?: ResourceColor;
  private sliderSelectedColor?: ResourceColor;
  private sliderTrackThickness?: number;
  private sliderStyle?: AVVolumeSliderStyle;
  private sliderThumbImage?: ResourceStr;
  private sliderPosition?: Position;
  private sliderSize?: SizeOptions;
}

enum AVVolumeStyle {
  SYSTEM_BAR,
  SLIDER_OVERLAY
}

@Component
export struct AVVolumeComponent {
  @Prop@Watch('volumeChange')
  volumeLevel?: number = 0;
  @Prop
  sliderParameter?: AVVolumeSliderParameter;
  @Prop
  volumeStyle?: AVVolumeStyle;
  @Prop
  sliderDirection?: Axis;
  @Prop
  sliderBlockColor?: ResourceColor;
  @Prop
  sliderTrackColor?: ResourceColor;
  @Prop
  sliderSelectedColor?: ResourceColor;
  @Prop
  sliderTrackThickness?: number;
  @Prop
  sliderStyle?: AVVolumeSliderStyle;
  @Prop
  sliderThumbImage?: ResourceStr;
  @Prop
  sliderPosition?: Position;
  @Prop
  sliderSize?: SizeOptions;

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
          bundleName: 'com.huawei.hmos.mediacontroller',
          parameters: {
            'volumeStyle': this.volumeStyle,
            'sliderParameter': this.sliderParameter,
            'sliderDirection': this.sliderDirection,
            'sliderBlockColor': this.sliderBlockColor,
            'sliderTrackColor': this.sliderTrackColor,
            'sliderSelectedColor': this.sliderSelectedColor,
            'sliderTrackThickness': this.sliderTrackThickness,
            'sliderStyle': this.sliderStyle,
            'sliderThumbImage': this.sliderThumbImage,
            'sliderPosition': this.sliderPosition,
            'sliderSize': this.sliderSize
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