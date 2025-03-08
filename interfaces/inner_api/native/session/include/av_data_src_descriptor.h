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

#ifndef OHOS_AV_DATA_SRC_DESCRIPTOR_H
#define OHOS_AV_DATA_SRC_DESCRIPTOR_H

#include "parcel.h"
#include "element_name.h"

namespace OHOS::AVSession {
struct AVDataSrcDescriptor {
    bool WriteToParcel(Parcel& out) const;
    bool ReadFromParcel(Parcel& in);

    int64_t fileSize = 0;
    bool hasCallback = false;
    std::function<int32_t(void*, uint32_t, int64_t)> callback_ = nullptr;
};
} // namespace OHOS::AVSession
#endif // OHOS_AV_DATA_SRC_DESCRIPTOR_H