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

#include "avsession_pixel_map_adapter.h"
#include "avsession_log.h"
#include "securec.h"

using namespace OHOS::Media;

namespace OHOS::AVSession {
namespace {
    constexpr int32_t MAX_PIXEL_BUFFER_SIZE = 1 * 1024 * 1024;
    constexpr int32_t LIMITED_PIXEL_BUFFER_SIZE = 500 * 1024; // ipc max 1m at the same time
    constexpr uint8_t IMAGE_BYTE_SIZE = 2;
    constexpr uint8_t DATA_BYTE_SIZE = 4;
    constexpr uint8_t OFFSET_BYTE = 8;
}

int32_t AVSessionPixelMapAdapter::originalPixelMapBytes_ = 0;
int32_t AVSessionPixelMapAdapter::originalWidth_ = 0;
int32_t AVSessionPixelMapAdapter::originalHeight_ = 0;
std::mutex AVSessionPixelMapAdapter::pixelMapLock_;

std::shared_ptr<Media::PixelMap> AVSessionPixelMapAdapter::ConvertFromInner(
    const std::shared_ptr<AVSessionPixelMap>& innerPixelMap)
{
    CHECK_AND_RETURN_RET_LOG(innerPixelMap != nullptr, nullptr, "invalid parameter");
    CHECK_AND_RETURN_RET_LOG(innerPixelMap->GetInnerImgBuffer().size() > IMAGE_BYTE_SIZE, nullptr,
        "innerPixelMap innerImgBuffer size less than 2");

    std::vector<uint8_t> innerImgBuffer = innerPixelMap->GetInnerImgBuffer();
    uint16_t imgBufferSize = static_cast<uint16_t>(innerImgBuffer[0]);
    imgBufferSize = (imgBufferSize << OFFSET_BYTE) + innerImgBuffer[1];
    CHECK_AND_RETURN_RET_LOG(imgBufferSize == sizeof(Media::ImageInfo), nullptr,
        "imgBufferSize not equal to %{public}zu", sizeof(Media::ImageInfo));

    Media::ImageInfo imageInfo;
    std::copy(innerImgBuffer.data() + IMAGE_BYTE_SIZE,
        innerImgBuffer.data() + IMAGE_BYTE_SIZE + imgBufferSize, reinterpret_cast<uint8_t*>(&imageInfo));

    const std::shared_ptr<Media::PixelMap>& pixelMap = std::make_shared<Media::PixelMap>();
    pixelMap->SetImageInfo(imageInfo);

    uint32_t imgByteSizeExist = innerImgBuffer.size() - IMAGE_BYTE_SIZE - imgBufferSize - DATA_BYTE_SIZE;
    uint32_t imgByteSizeInner = static_cast<uint32_t>(pixelMap->GetByteCount());
    CHECK_AND_RETURN_RET_LOG(imgByteSizeInner == imgByteSizeExist, nullptr, "imageInfo size error");

    uint32_t dataSize = 0;
    for (uint8_t i = 0; i < DATA_BYTE_SIZE; i++) {
        uint32_t tmpValue = innerImgBuffer[IMAGE_BYTE_SIZE + imgBufferSize + i];
        dataSize += (tmpValue << (OFFSET_BYTE * (DATA_BYTE_SIZE - i - 1)));
    }
    CHECK_AND_RETURN_RET_LOG(dataSize == imgByteSizeExist, nullptr, "dataSize error");
    void* dataAddr = static_cast<void*>(innerImgBuffer.data() + IMAGE_BYTE_SIZE + imgBufferSize + DATA_BYTE_SIZE);
    pixelMap->SetPixelsAddr(dataAddr, nullptr, dataSize, Media::AllocatorType::CUSTOM_ALLOC, nullptr);
    SLOGI("ConvertFromInner without scalemode srcSize=[%{public}d, %{public}d}], dstSize=[%{public}d, %{public}d}]",
        pixelMap->GetWidth(), pixelMap->GetHeight(), originalWidth_, originalHeight_);
    Media::InitializationOptions options;
    options.alphaType = imageInfo.alphaType;
    options.pixelFormat = imageInfo.pixelFormat;
    options.size.width = originalWidth_;
    options.size.height = originalHeight_;
    options.editable = true;
    auto result = Media::PixelMap::Create(*pixelMap, options);
    return std::move(result);
}

bool AVSessionPixelMapAdapter::CopyPixMapToDst(Media::PixelMap &source, void* dstPixels, uint32_t bufferSize)
{
    if (source.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        SLOGD("CopyPixMapToDst in dma");
        ImageInfo imageInfo;
        source.GetImageInfo(imageInfo);
        for (int i = 0; i < imageInfo.size.height; ++i) {
            if (memcpy_s(dstPixels, source.GetRowBytes(),
                source.GetPixels() + i * source.GetRowStride(), source.GetRowBytes()) != 0) {
                SLOGE("copy source memory size %{public}u fail", bufferSize);
                return false;
            }
            // Move the destination buffer pointer to the next row
            dstPixels = reinterpret_cast<uint8_t *>(dstPixels) + source.GetRowBytes();
        }
    } else  {
        SLOGI("CopyPixMapToDst in normal way with bufferSize %{public}u", bufferSize);
        if (memcpy_s(dstPixels, bufferSize, source.GetPixels(), bufferSize) != 0) {
            SLOGE("copy source memory size %{public}u fail", bufferSize);
            return false;
        }
    }
    return true;
}

std::shared_ptr<AVSessionPixelMap> AVSessionPixelMapAdapter::ConvertAndSetInnerImgBuffer(
    const std::shared_ptr<Media::PixelMap>& pixelMapTemp)
{
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer;
    Media::ImageInfo imageInfo;
    pixelMapTemp->GetImageInfo(imageInfo);
    const auto* buffer = reinterpret_cast<uint8_t*>(&imageInfo);
    uint16_t imageInfoSize = static_cast<uint16_t>(sizeof(Media::ImageInfo));
    uint32_t pixelDataSize = static_cast<uint32_t>(pixelMapTemp->GetByteCount());
    size_t bufferSize = static_cast<size_t>(IMAGE_BYTE_SIZE + imageInfoSize + DATA_BYTE_SIZE + pixelDataSize);
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
    SLOGI("insert with size: %{public}hu, %{public}u, %{public}d",
        imageInfoSize, pixelDataSize, static_cast<int>(imgBuffer.size()));
    imgBuffer.insert(imgBuffer.begin() + imgBuffer.size(), pixelMapTemp->GetPixels(),
        pixelMapTemp->GetPixels() + pixelDataSize);
    innerPixelMap->SetInnerImgBuffer(imgBuffer);
    imgBuffer.clear();
    return innerPixelMap;
}

std::shared_ptr<AVSessionPixelMap> AVSessionPixelMapAdapter::ConvertToInner(
    const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    std::lock_guard<std::mutex> lockGuard(pixelMapLock_);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "invalid parameter");
    originalPixelMapBytes_ = pixelMap->GetByteCount();
    originalWidth_ = pixelMap->GetWidth();
    originalHeight_ = pixelMap->GetHeight();
    Media::ImageInfo imageInfoTemp;
    pixelMap->GetImageInfo(imageInfoTemp);
    const std::shared_ptr<Media::PixelMap>& pixelMapTemp = std::make_shared<Media::PixelMap>();
    pixelMapTemp->SetImageInfo(imageInfoTemp);
    uint32_t dataSize = static_cast<uint32_t>(originalPixelMapBytes_);
    void* dataAddr = malloc(dataSize);
    CHECK_AND_RETURN_RET_LOG(dataAddr != nullptr, nullptr, "create dataSize with null, return");

    if (!CopyPixMapToDst(*pixelMap, dataAddr, dataSize)) {
        SLOGE("CopyPixMapToDst failed");
        free(dataAddr);
        reutrn nullptr;
    }
    pixelMapTemp->SetPixelsAddr(dataAddr, nullptr, dataSize, Media::AllocatorType::CUSTOM_ALLOC, nullptr);
    if (originalPixelMapBytes_ > MAX_PIXEL_BUFFER_SIZE) {
        int32_t originSize = originalPixelMapBytes_;
        float scaleRatio = sqrt(static_cast<float>(MAX_PIXEL_BUFFER_SIZE) / static_cast<float>(originalPixelMapBytes_));
        pixelMapTemp->scale(scaleRatio, scaleRatio);
        originalPixelMapBytes_ = pixelMapTemp->GetByteCount();
        SLOGI("imgBufferSize exceeds limited: %{public}d scaled to %{public}d", originSize, originalPixelMapBytes_);
    }
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = ConvertAndSetInnerImgBuffer(pixelMapTemp);
    free(dataAddr);
    return innerPixelMap;
}

std::shared_ptr<AVSessionPixelMap> AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(
    const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    std::lock_guard<std::mutex> lockGuard(pixelMapLock_);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "invalid parameter");
    originalPixelMapBytes_ = pixelMap->GetByteCount();
    originalWidth_ = pixelMap->GetWidth();
    originalHeight_ = pixelMap->GetHeight();
    Media::ImageInfo imageInfoTemp;
    pixelMap->GetImageInfo(imageInfoTemp);
    const std::shared_ptr<Media::PixelMap>& pixelMapTemp = std::make_shared<Media::PixelMap>();
    pixelMapTemp->SetImageInfo(imageInfoTemp);
    uint32_t dataSize = static_cast<uint32_t>(originalPixelMapBytes_);
    void* dataAddr = malloc(dataSize);
    CHECK_AND_RETURN_RET_LOG(dataAddr != nullptr, nullptr, "create dataSize with null, return");

    if (!CopyPixMapToDst(*pixelMap, dataAddr, dataSize)) {
        SLOGE("CopyPixMapToDst failed");
        free(dataAddr);
        reutrn nullptr;
    }
    pixelMapTemp->SetPixelsAddr(dataAddr, nullptr, dataSize, Media::AllocatorType::CUSTOM_ALLOC, nullptr);
    if (originalPixelMapBytes_ > LIMITED_PIXEL_BUFFER_SIZE) {
        int32_t originSize = originalPixelMapBytes_;
        float scaleRatio =
            sqrt(static_cast<float>(LIMITED_PIXEL_BUFFER_SIZE) / static_cast<float>(originalPixelMapBytes_));
        pixelMapTemp->scale(scaleRatio, scaleRatio);
        originalPixelMapBytes_ = pixelMapTemp->GetByteCount();
        SLOGI("imgBufferSize exceeds limited: %{public}d scaled to %{public}d", originSize, originalPixelMapBytes_);
    }
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = ConvertAndSetInnerImgBuffer(pixelMapTemp);
    free(dataAddr);
    return innerPixelMap;
}
} // namespace OHOS::AVSession