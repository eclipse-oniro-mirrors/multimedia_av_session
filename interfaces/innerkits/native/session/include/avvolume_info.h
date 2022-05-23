/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVVOLUME_INFO_H
#define OHOS_AVVOLUME_INFO_H

namespace OHOS::AVSession {
enum {
    VOLUME_TYPE_ABSOLUTE,
    VOLUME_TYPE_RELATIVE,
    VOLUME_TYPE_FIXED
};

struct AVVolumeInfo {
    int32_t currentVolume_;
    int32_t maxVolume_;
    int32_t volumeType;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVVOLUME_INFO_H