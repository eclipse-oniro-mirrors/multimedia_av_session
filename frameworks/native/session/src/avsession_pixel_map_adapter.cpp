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
namespace {
    constexpr int32_t MAX_PIXEL_BUFFER_SIZE = 200 * 1024;
    constexpr uint8_t IMAGE_BYTE_SIZE = 2;
    constexpr uint8_t DATA_BYTE_SIZE = 4;
    constexpr uint8_t OFFSET_BYTE = 8;
}

int32_t AVSessionPixelMapAdapter::originalPixelMapBytes_ = 0;
int32_t AVSessionPixelMapAdapter::originalWidth_ = 0;
int32_t AVSessionPixelMapAdapter::originalHeight_ = 0;

std::shared_ptr<Media::PixelMap> AVSessionPixelMapAdapter::ConvertFromInner(
    const std::shared_ptr<AVSessionPixelMap> &innerPixelMap)
{
    CHECK_AND_RETURN_RET_LOG(innerPixelMap != nullptr, nullptr, "invalid parameter");
    CHECK_AND_RETURN_RET_LOG(innerPixelMap->GetInnerImgBuffer().size() > IMAGE_BYTE_SIZE, nullptr,
        "innerPixelMap innerImgBuffer size less than 2");

    std::vector<uint8_t> innerImgBuffer = innerPixelMap->GetInnerImgBuffer();
    innerPixelMap->Clear();
    uint16_t imgBufferSize = static_cast<uint16_t>(innerImgBuffer[0]);
    imgBufferSize = (imgBufferSize << OFFSET_BYTE) + innerImgBuffer[1];

    if (imgBufferSize > sizeof(Media::ImageInfo)) {
        SLOGE("imgBufferSize greater than %{public}zu", sizeof(Media::ImageInfo));
        return nullptr;
    }

    Media::ImageInfo imageInfo;
    std::copy(innerImgBuffer.data() + IMAGE_BYTE_SIZE,
        innerImgBuffer.data() + IMAGE_BYTE_SIZE + imgBufferSize, (uint8_t*)(&imageInfo));

    const std::shared_ptr<Media::PixelMap>& pixelMap = std::make_shared<Media::PixelMap>();
    pixelMap->SetImageInfo(imageInfo);

    uint32_t dataSize = 0;
    for (uint8_t i = 0; i < DATA_BYTE_SIZE; i++) {
        uint8_t tmpValue = innerImgBuffer[IMAGE_BYTE_SIZE + imgBufferSize + i];
        uint32_t size = tmpValue << (OFFSET_BYTE * (DATA_BYTE_SIZE - i - 1));
        dataSize += size;
    }
    void* dataAddr = static_cast<void*>(innerImgBuffer.data() + IMAGE_BYTE_SIZE + imgBufferSize + DATA_BYTE_SIZE);
    pixelMap->SetPixelsAddr(dataAddr, nullptr, dataSize, Media::AllocatorType::CUSTOM_ALLOC, nullptr);

    Media::InitializationOptions options;
    options.alphaType = imageInfo.alphaType;
    options.pixelFormat = imageInfo.pixelFormat;
    options.scaleMode = OHOS::Media::ScaleMode::CENTER_CROP;
    options.size.width = originalWidth_;
    options.size.height = originalHeight_;
    options.editable = true;
    auto result = Media::PixelMap::Create(*pixelMap, options);
    if (originalPixelMapBytes_ > MAX_PIXEL_BUFFER_SIZE) {
        float scaleRatio = (float)originalPixelMapBytes_ / (float)MAX_PIXEL_BUFFER_SIZE;
        pixelMap->scale(scaleRatio, scaleRatio);
    }
    return std::move(result);
}

std::shared_ptr<AVSessionPixelMap> AVSessionPixelMapAdapter::ConvertToInner(
    const std::shared_ptr<Media::PixelMap> &pixelMap)
{
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "invalid parameter");
    originalPixelMapBytes_ = pixelMap->GetByteCount();
    originalWidth_ = pixelMap->GetWidth();
    originalHeight_ = pixelMap->GetHeight();
    if (originalPixelMapBytes_ > MAX_PIXEL_BUFFER_SIZE) {
        float scaleRatio = (float)MAX_PIXEL_BUFFER_SIZE / (float)originalPixelMapBytes_;
        pixelMap->scale(scaleRatio, scaleRatio);
    }
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer;
    Media::ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    const auto *buffer = (uint8_t *)(&imageInfo);
    uint16_t imageInfoSize = static_cast<uint16_t>(sizeof(Media::ImageInfo));
    int32_t pixelDataSize = pixelMap->GetByteCount();
    size_t bufferSize = IMAGE_BYTE_SIZE + imageInfoSize + DATA_BYTE_SIZE + pixelDataSize;
    imgBuffer.reserve(bufferSize);
    imgBuffer.insert(imgBuffer.begin(), (imageInfoSize & 0xFF00) >> OFFSET_BYTE);
    imgBuffer.insert(imgBuffer.begin() + imgBuffer.size(), (imageInfoSize & 0x00FF));
    imgBuffer.insert(imgBuffer.begin() + imgBuffer.size(), buffer, buffer + imageInfoSize);

    uint32_t computedValue = 0xFF000000;
    for (uint8_t i = 0; i < DATA_BYTE_SIZE; i++) {
        uint8_t tmpValue = ((pixelDataSize & computedValue) >> (OFFSET_BYTE * (DATA_BYTE_SIZE - i - 1)));
        imgBuffer.insert(imgBuffer.begin() + imgBuffer.size(), tmpValue);
        computedValue = computedValue >> OFFSET_BYTE;
    }
    imgBuffer.insert(imgBuffer.begin() + imgBuffer.size(), pixelMap->GetPixels(),
        pixelMap->GetPixels() + pixelDataSize);
    innerPixelMap->SetInnerImgBuffer(imgBuffer);
    return innerPixelMap;
}
} // OHOS::AVSession