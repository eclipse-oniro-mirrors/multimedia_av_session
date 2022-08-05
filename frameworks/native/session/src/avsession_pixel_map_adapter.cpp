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

#include "avsession_pixel_map_adapter.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
std::shared_ptr<Media::PixelMap> AVSessionPixelMapAdapter::ConvertFromInner(
    const std::shared_ptr<AVSessionPixelMap> &innerPixelMap)
{
    CHECK_AND_RETURN_RET_LOG(innerPixelMap != nullptr, nullptr, "invalid parameter");
    auto imageInfoBytes = innerPixelMap->GetImageInfo();
    const auto *buffer = imageInfoBytes.data();
    Media::ImageInfo imageInfo;
    std::copy(buffer, buffer + imageInfoBytes.size(), (uint8_t *)(&imageInfo));

    const std::shared_ptr<Media::PixelMap>& pixelMap = std::make_shared<Media::PixelMap>();
    pixelMap->SetImageInfo(imageInfo);

    std::vector<uint8_t> pixelData = innerPixelMap->GetPixelData();
    pixelMap->SetPixelsAddr(pixelData.data(), nullptr, pixelData.size(), Media::AllocatorType::CUSTOM_ALLOC, nullptr);

    Media::InitializationOptions options;
    options.alphaType = imageInfo.alphaType;
    options.pixelFormat = imageInfo.pixelFormat;
    options.scaleMode = OHOS::Media::ScaleMode::CENTER_CROP;
    options.size.width = imageInfo.size.width;
    options.size.height = imageInfo.size.height;
    options.editable = true;
    auto result = Media::PixelMap::Create(*pixelMap, options);
    return std::move(result);
}

std::shared_ptr<AVSessionPixelMap> AVSessionPixelMapAdapter::ConvertToInner(
    const std::shared_ptr<Media::PixelMap> &pixelMap)
{
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "invalid parameter");
    Media::ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    const auto *buffer = (uint8_t *)(&imageInfo);
    std::vector<uint8_t> imageInfoBytes(sizeof(Media::ImageInfo));
    imageInfoBytes.assign(buffer, buffer + sizeof(Media::ImageInfo));

    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    innerPixelMap->SetImageInfo(imageInfoBytes);

    std::vector<uint8_t> innerPixelData(pixelMap->GetByteCount());
    std::copy(pixelMap->GetPixels(), pixelMap->GetPixels() + pixelMap->GetByteCount(), innerPixelData.begin());
    innerPixelMap->SetPixelData(innerPixelData);
    return innerPixelMap;
}
} // OHOS::AVSession