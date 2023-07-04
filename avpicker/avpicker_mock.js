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

const TAG = 'avpicker_component_mock ';

export class AVCastPicker extends ViewPU {
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
            Button.createWithLabel("AVCastPicker");
            Button.type(ButtonType.Circle);
            Button.size({ width: "100%", height: "100%"});
            isInitialRender || Button.pop();
            ViewStackProcessor.StopGetAccessRecording();
        });
        Button.pop();
        Column.pop();
    }

    rerender() {
        this.updateDirtyElements();
    }
}

export default AVCastPicker;
