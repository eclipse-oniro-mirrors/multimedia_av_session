/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVCONTROLLERITEM_FUZZER_H
#define OHOS_AVCONTROLLERITEM_FUZZER_H
#include <cstdint>
#include <cstddef>
namespace OHOS::AVSession {
void AvControllerItemRemoteRequestTest();
void AvControllerItemDataTest();
void AvControllerItemDataTestSecond(sptr<AVControllerItem> avControllerItem);
void AvControllerItemDataTestThird(sptr<AVControllerItem> avControllerItem);

void AvControllerItemTest();
void AvControllerItemTestImpl(sptr<AVControllerItem> avControllerItem);
void AvControllerItemTestImplSecond(sptr<AVControllerItem> avControllerItem);

class AvControllerItemFuzzer {
public:
    AvControllerItemFuzzer() = default;
    ~AvControllerItemFuzzer() = default;
    void FuzzOnRemoteRequest();
};
}
#endif
