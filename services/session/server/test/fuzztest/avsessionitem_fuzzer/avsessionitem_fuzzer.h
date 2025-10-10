/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVCONTROLLERCALLITEM_FUZZER_H
#define OHOS_AVCONTROLLERCALLITEM_FUZZER_H

#include <cstdint>
#include <cstddef>
#include "avsession_log.h"
#include "avsession_manager.h"

namespace OHOS::AVSession {
void AvSessionItemOnRemoteRequest();
void AvSessionItemTest();
void AvSessionItemTestImpl(sptr<AVSessionItem> avSessionItem);
void AvSessionItemTestAdded(sptr<AVSessionItem> avSessionItem);
void AvSessionCallItemTest(sptr<AVSessionItem> avSessionItem);
void AvSessionItemTestImplExtension(sptr<AVSessionItem> avSessionItem);
void AvSessionCallItemTestExtension(sptr<AVSessionItem> avSessionItem);
void AvSessionItemTestCustomData(sptr<AVSessionItem> avSessionItem);

class AvSessionItemFuzzer {
public:
    AvSessionItemFuzzer() = default;
    ~AvSessionItemFuzzer() = default;
    void AvSessionItemFuzzerTest();
};
}
#endif