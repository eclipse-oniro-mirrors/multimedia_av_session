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

#ifndef OHOS_AVSESSION_PIXEL_MAP_ADAPTER_H
#define OHOS_AVSESSION_PIXEL_MAP_ADAPTER_H

#include <cstdint>
#include <map>
#include <list>
#include "avsession_pixel_map.h"
#include "pixel_map.h"

namespace OHOS::AVSession {
class AVSessionPixelMapAdapter {
public:
    static std::shared_ptr<Media::PixelMap> ConvertFromInner(const std::shared_ptr<AVSessionPixelMap>& innerPixelMap);
    static std::shared_ptr<AVSessionPixelMap> ConvertToInner(const std::shared_ptr<Media::PixelMap>& pixelMap);
    static std::shared_ptr<AVSessionPixelMap>
        ConvertToInnerWithLimitedSize(const std::shared_ptr<Media::PixelMap>& pixelMap);
    static bool CopyPixMapToDst(Media::PixelMap &source, void* dstPixels, uint32_t bufferSize);
    static int32_t originalPixelMapBytes_;
    static int32_t originalWidth_;
    static int32_t originalHeight_;
    static std::mutex pixelMapLock_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_PIXEL_MAP_ADAPTER_H