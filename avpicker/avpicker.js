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

var Prompt = globalThis.requireNapi('prompt');
var commonEventManager = globalThis.requireNapi('commonEventManager');
var AVSessionManager = globalThis.requireNapi('multimedia.avsession');

const TAG = 'avpicker_component ';

export class avpicker extends ViewPU {
    constructor(parent, params, __localStorage, elmtId = -1) {
        super(parent, __localStorage, elmtId);
        this.setInitiallyProvidedValue(params);
    }

    setInitiallyProvidedValue(params) {
    }

    updateStateVars(params) {
    }

    purgeVariableDependenciesOnElmtId(rmElmtId) {
    }

    aboutToBeDeleted() {
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }

    aboutToAppear() {
        console.info(TAG + 'aboutToAppear');
        let subscriber = undefined;
        let subscribeInfo = {
            events: ['avpickerCommunication']
        };
        commonEventManager.createSubscriber(subscribeInfo, (err, data) => {
            if (err) {
                console.info(TAG + 'createSubscriber fail, err : ' + err);
                return;
            }
            subscriber = data;
            commonEventManager.subscribe(subscriber, (err, data) => {
                if (err) {
                    console.info(TAG + 'subscribe fail, err : ' + err);
                    return;
                }
                console.info(TAG + 'subscriber get message : ' + JSON.stringify(data));
                Prompt.showToast({ message: String(data.data), duration: 1500, bottom: 30 });
            });
        });
    }

    aboutToDisappear() {
        console.info(TAG + 'aboutToDisappear');
    }

    initialRender() {
        this.observeComponentCreation((elmtId, isInitialRender) => {
            ViewStackProcessor.StartGetAccessRecordingFor(elmtId);
            Column.create();
            Column.size({ width: '100%', height: '100%' })
            isInitialRender || Column.pop();
            ViewStackProcessor.StopGetAccessRecording();
        });
        this.observeComponentCreation((elmtId, isInitialRender) => {
            ViewStackProcessor.StartGetAccessRecordingFor(elmtId);
            UIExtensionComponent.create({
                want: { abilityName: 'AVPickerUiExtAbility', bundleName: 'com.ohos.systemui' }
            });
            UIExtensionComponent.size({ width: '100%', height: '100%' })
            isInitialRender || UIExtensionComponent.pop();
            ViewStackProcessor.StopGetAccessRecording();
        });
        UIExtensionComponent.pop();
        Column.pop();
    }
    
    rerender() {
        this.updateDirtyElements();
    }
}

export default avpicker;
