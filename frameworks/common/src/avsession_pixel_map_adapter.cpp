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
#include "pixel_astc.h"
#include "image_source.h"

using namespace OHOS::Media;

namespace OHOS::AVSession {
namespace {
    constexpr int32_t MAX_PIXEL_BUFFER_SIZE = 1 * 1024 * 1024;
    constexpr int32_t LIMITED_PIXEL_BUFFER_SIZE = 500 * 1024; // ipc max 1m at the same time
    constexpr int32_t AVQUEUE_PIXEL_BUFFER_SIZE = 300 * 1024;
    constexpr int32_t MIN_PIXEL_BUFFER_SIZE = 40 * 1024;
    constexpr uint8_t IMAGE_BYTE_SIZE = 2;
    constexpr uint8_t DATA_BYTE_SIZE = 4;
    constexpr uint8_t OFFSET_BYTE = 8;
    constexpr uint8_t DEFAULT_IMAGE_INFO_SIZE = 48;
    constexpr int32_t DEFAULT_IMAGE_SIZE = 256;
    std::shared_ptr<Media::PixelMap> g_defaultMediaImage = nullptr;
}

int32_t AVSessionPixelMapAdapter::originalPixelMapBytes_ = 0;
std::mutex AVSessionPixelMapAdapter::pixelMapLock_;

void AVSessionPixelMapAdapter::CleanAVSessionPixelMap(std::shared_ptr<AVSessionPixelMap>& innerPixelMap)
{
    std::lock_guard<std::mutex> lockGuard(pixelMapLock_);
    if (innerPixelMap != nullptr) {
        innerPixelMap->Clear();
    }
}

void ConvertImageInfoFromInner(std::vector<uint8_t>& innerImgBuffer, Media::ImageInfo& imageInfo)
{
    int32_t innerImgSize = static_cast<int>(innerImgBuffer.size());
    CHECK_AND_RETURN_LOG(innerImgSize > static_cast<int32_t>(IMAGE_BYTE_SIZE + DEFAULT_IMAGE_INFO_SIZE),
        "innerPixelMap has no imageInfo");
    size_t offset = IMAGE_BYTE_SIZE;
    errno_t ret = memcpy_s(&imageInfo.size, sizeof(Media::Size),
        innerImgBuffer.data() + offset, sizeof(Media::Size));
    CHECK_AND_RETURN_LOG(ret == EOK, "imageInfo size err!");
    offset += sizeof(Media::Size);
    ret = memcpy_s(&imageInfo.pixelFormat, sizeof(Media::PixelFormat),
        innerImgBuffer.data() + offset, sizeof(Media::PixelFormat));
    CHECK_AND_RETURN_LOG(ret == EOK, "imageInfo pixelFormat err!");
    offset += sizeof(Media::PixelFormat);
    ret = memcpy_s(&imageInfo.colorSpace, sizeof(Media::ColorSpace),
        innerImgBuffer.data() + offset, sizeof(Media::ColorSpace));
    CHECK_AND_RETURN_LOG(ret == EOK, "imageInfo colorSpace err!");
    offset += sizeof(Media::ColorSpace);
    ret = memcpy_s(&imageInfo.alphaType, sizeof(Media::AlphaType),
        innerImgBuffer.data() + offset, sizeof(Media::AlphaType));
    CHECK_AND_RETURN_LOG(ret == EOK, "imageInfo alphaType err!");
    offset += sizeof(Media::AlphaType);
    ret = memcpy_s(&imageInfo.baseDensity, sizeof(int32_t), innerImgBuffer.data() + offset, sizeof(int32_t));
    CHECK_AND_RETURN_LOG(ret == EOK, "imageInfo baseDensity err!");
    imageInfo.encodedFormat = "";
}

std::shared_ptr<Media::PixelMap> AVSessionPixelMapAdapter::ConvertFromInner(
    const std::shared_ptr<AVSessionPixelMap>& innerPixelMap, bool isSizeLimited)
{
    std::lock_guard<std::mutex> lockGuard(pixelMapLock_);
    CHECK_AND_RETURN_RET_LOG(innerPixelMap != nullptr, nullptr, "invalid parameter");
    std::vector<uint8_t> innerImgBuffer = innerPixelMap->GetInnerImgBuffer();
    int32_t innerImgSize = static_cast<int>(innerImgBuffer.size());
    CHECK_AND_RETURN_RET_LOG(innerImgSize > static_cast<int32_t>(IMAGE_BYTE_SIZE + DEFAULT_IMAGE_INFO_SIZE),
        nullptr, "innerPixelMap has no imageInfo");
    uint16_t imgBufferSize = static_cast<uint16_t>(innerImgBuffer[0]);
    imgBufferSize = (imgBufferSize << OFFSET_BYTE) + innerImgBuffer[1];
    CHECK_AND_RETURN_RET_LOG(imgBufferSize == DEFAULT_IMAGE_INFO_SIZE, nullptr,
        "imgBufferSize not equal to %{public}u:%{public}u", DEFAULT_IMAGE_INFO_SIZE, imgBufferSize);

    Media::ImageInfo imageInfo;
    ConvertImageInfoFromInner(innerImgBuffer, imageInfo);

    const std::shared_ptr<Media::PixelMap>& pixelMap = std::make_shared<Media::PixelMap>();
    pixelMap->SetImageInfo(imageInfo);

    uint32_t imgByteSizeExist = innerImgBuffer.size() - IMAGE_BYTE_SIZE - imgBufferSize - DATA_BYTE_SIZE;
    uint32_t imgByteSizeInner = static_cast<uint32_t>(pixelMap->GetByteCount());

    CHECK_AND_RETURN_RET_LOG(imgByteSizeInner == imgByteSizeExist, nullptr, "imageInfo size error!");

    uint32_t dataSize = 0;
    for (uint8_t i = 0; i < DATA_BYTE_SIZE; i++) {
        uint32_t tmpValue = innerImgBuffer[IMAGE_BYTE_SIZE + imgBufferSize + i];
        dataSize += (tmpValue << (OFFSET_BYTE * (DATA_BYTE_SIZE - i - 1)));
    }
    CHECK_AND_RETURN_RET_LOG(dataSize == imgByteSizeExist, nullptr, "dataSize error");
    void* dataAddr = static_cast<void*>(innerImgBuffer.data() + IMAGE_BYTE_SIZE + imgBufferSize + DATA_BYTE_SIZE);
    pixelMap->SetPixelsAddr(dataAddr, nullptr, dataSize, Media::AllocatorType::CUSTOM_ALLOC, nullptr);
    uint8_t imgTopicNumber = innerImgBuffer[innerImgSize / 2] + innerImgBuffer[innerImgSize / 2 + 1];
    SLOGI("%{public}u|%{public}d-%{public}d|%{public}d-%{public}d",
        imgTopicNumber, pixelMap->GetWidth(), pixelMap->GetHeight(),
        innerPixelMap->GetOriginalWidth(), innerPixelMap->GetOriginalHeight());
    Media::InitializationOptions options;
    options.alphaType = imageInfo.alphaType;
    options.pixelFormat = imageInfo.pixelFormat;
    options.size.width = isSizeLimited ? innerPixelMap->GetOriginalWidth() : 0;
    options.size.height = isSizeLimited ? innerPixelMap->GetOriginalHeight() : 0;
    options.editable = true;
    auto result = Media::PixelMap::Create(*pixelMap, options);
    return std::move(result);
}

bool AVSessionPixelMapAdapter::CopyPixMapToDst(Media::PixelMap &source, void* dstPixels, uint32_t bufferSize)
{
    CHECK_AND_RETURN_RET_LOG(dstPixels != nullptr, false, "dstPixels is nullptr");
    if (source.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        SLOGD("CopyPixMapToDst in dma");
        ImageInfo imageInfo;
        source.GetImageInfo(imageInfo);
        const uint8_t *srcPixels = source.GetPixels();
        int32_t rowStride = source.GetRowStride();
        int32_t signedRowBytes = source.GetRowBytes();
        CHECK_AND_RETURN_RET_LOG(srcPixels != nullptr, false, "dma source pixels is nullptr");
        CHECK_AND_RETURN_RET_LOG(imageInfo.size.height >= 0 && signedRowBytes > 0 && rowStride >= 0,
            false, "dma image info is invalid");
        uint32_t rowBytes = static_cast<uint32_t>(signedRowBytes);
        CHECK_AND_RETURN_RET_LOG(
            static_cast<uint64_t>(imageInfo.size.height) * rowBytes <= bufferSize, false,
            "dma copy size exceeds bufferSize");
        for (int32_t i = 0; i < imageInfo.size.height; ++i) {
            uint32_t remainingSize = bufferSize - static_cast<uint32_t>(i) * rowBytes;
            if (memcpy_s(dstPixels, remainingSize,
                srcPixels + static_cast<size_t>(i) * static_cast<uint32_t>(rowStride), rowBytes) != 0) {
                SLOGE("copy source memory size %{public}u fail", bufferSize);
                return false;
            }
            // Move the destination buffer pointer to the next row
            dstPixels = reinterpret_cast<uint8_t *>(dstPixels) + rowBytes;
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
    uint16_t imageInfoSize = static_cast<uint16_t>(DEFAULT_IMAGE_INFO_SIZE);
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
    imgBuffer.insert(imgBuffer.begin() + imgBuffer.size(), pixelMapTemp->GetPixels(),
        pixelMapTemp->GetPixels() + pixelDataSize);
    innerPixelMap->SetInnerImgBuffer(imgBuffer);
    CHECK_AND_RETURN_RET_LOG(imgBuffer.size() > IMAGE_BYTE_SIZE, innerPixelMap, "imgBuffer size invalid");
    uint8_t imgTopicNumber =
        imgBuffer[imgBuffer.size() / IMAGE_BYTE_SIZE] + imgBuffer[imgBuffer.size() / IMAGE_BYTE_SIZE + 1];
    SLOGI("insert with size:%{public}hu,%{public}u,%{public}d|%{public}d",
        imageInfoSize, pixelDataSize, static_cast<int>(imgBuffer.size()), static_cast<int>(imgTopicNumber));
    imgBuffer.clear();
    return innerPixelMap;
}

std::shared_ptr<AVSessionPixelMap> AVSessionPixelMapAdapter::ConvertToInner(
    const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    std::lock_guard<std::mutex> lockGuard(pixelMapLock_);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "invalid parameter");

    Media::ImageInfo imageInfoForAstcConv;
    pixelMap->GetImageInfo(imageInfoForAstcConv);
    std::shared_ptr<Media::PixelMap> pixelMapExlAstc;
    if (imageInfoForAstcConv.pixelFormat == Media::PixelFormat::ASTC_4x4 ||
        imageInfoForAstcConv.pixelFormat == Media::PixelFormat::ASTC_6x6 ||
        imageInfoForAstcConv.pixelFormat == Media::PixelFormat::ASTC_8x8) {
        uint32_t code;
        auto pixelMapFromAstc = Media::PixelMap::ConvertFromAstc(pixelMap.get(), code, Media::PixelFormat::RGBA_8888);
        CHECK_AND_RETURN_RET_LOG(code == 0 && pixelMapFromAstc != nullptr, nullptr, "ConvertFromAstc fail");
        pixelMapExlAstc = std::move(pixelMapFromAstc);
        SLOGI("ConvertFromAstc done");
    } else {
        pixelMapExlAstc = pixelMap;
    }

    originalPixelMapBytes_ = pixelMapExlAstc->GetByteCount();
    int32_t width = pixelMapExlAstc->GetWidth();
    int32_t height = pixelMapExlAstc->GetHeight();
    Media::ImageInfo imageInfoTemp;
    pixelMapExlAstc->GetImageInfo(imageInfoTemp);
    const std::shared_ptr<Media::PixelMap>& pixelMapTemp = std::make_shared<Media::PixelMap>();
    pixelMapTemp->SetImageInfo(imageInfoTemp);
    uint32_t dataSize = static_cast<uint32_t>(originalPixelMapBytes_);
    CHECK_AND_RETURN_RET_LOG((dataSize > 0 && dataSize <= INT32_MAX), nullptr, "create dataSize with null, return");
    void* dataAddr = malloc(dataSize);
    CHECK_AND_RETURN_RET_LOG(dataAddr != nullptr, nullptr, "create dataSize with null, return");

    if (!CopyPixMapToDst(*pixelMapExlAstc, dataAddr, dataSize)) {
        SLOGE("CopyPixMapToDst failed");
        free(dataAddr);
        return nullptr;
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
    innerPixelMap->SetOriginalSize(width, height);
    free(dataAddr);
    return innerPixelMap;
}

std::shared_ptr<AVSessionPixelMap> AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(
    const std::shared_ptr<Media::PixelMap>& pixelMap, bool isAVQueueImg)
{
    std::lock_guard<std::mutex> lockGuard(pixelMapLock_);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "invalid parameter");
    originalPixelMapBytes_ = pixelMap->GetByteCount();
    int32_t width = pixelMap->GetWidth();
    int32_t height = pixelMap->GetHeight();
    Media::ImageInfo imageInfoTemp;
    pixelMap->GetImageInfo(imageInfoTemp);
    const std::shared_ptr<Media::PixelMap>& pixelMapTemp = std::make_shared<Media::PixelMap>();
    CHECK_AND_RETURN_RET_LOG(pixelMapTemp != nullptr, nullptr, "pixelMapTemp nullptr");
    pixelMapTemp->SetImageInfo(imageInfoTemp);
    uint32_t dataSize = static_cast<uint32_t>(originalPixelMapBytes_);
    CHECK_AND_RETURN_RET_LOG((dataSize > 0 && dataSize <= INT32_MAX), nullptr, "create dataSize with null, return");
    void* dataAddr = malloc(dataSize);
    CHECK_AND_RETURN_RET_LOG(dataAddr != nullptr, nullptr, "create dataSize with null, return");

    if (!CopyPixMapToDst(*pixelMap, dataAddr, dataSize)) {
        SLOGE("CopyPixMapToDst failed");
        free(dataAddr);
        return nullptr;
    }
    pixelMapTemp->SetPixelsAddr(dataAddr, nullptr, dataSize, Media::AllocatorType::CUSTOM_ALLOC, nullptr);
    int limitedSize = isAVQueueImg ? AVQUEUE_PIXEL_BUFFER_SIZE : LIMITED_PIXEL_BUFFER_SIZE;
    if (originalPixelMapBytes_ > limitedSize) {
        int32_t originSize = originalPixelMapBytes_;
        float scaleRatio =
            sqrt(static_cast<float>(limitedSize) / static_cast<float>(originalPixelMapBytes_));
        pixelMapTemp->scale(scaleRatio, scaleRatio);
        originalPixelMapBytes_ = pixelMapTemp->GetByteCount();
        SLOGI("imgBufferSize exceeds limitedEx %{public}d: %{public}d scaled to %{public}d",
            limitedSize, originSize, originalPixelMapBytes_);
    }
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = ConvertAndSetInnerImgBuffer(pixelMapTemp);
    innerPixelMap->SetOriginalSize(width, height);
    free(dataAddr);
    return innerPixelMap;
}

std::shared_ptr<AVSessionPixelMap> AVSessionPixelMapAdapter::ConvertToInnerWithMinSize(
    const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    std::lock_guard<std::mutex> lockGuard(pixelMapLock_);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "invalid parameter");
    originalPixelMapBytes_ = pixelMap->GetByteCount();
    int32_t width = pixelMap->GetWidth();
    int32_t height = pixelMap->GetHeight();
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
        return nullptr;
    }
    pixelMapTemp->SetPixelsAddr(dataAddr, nullptr, dataSize, Media::AllocatorType::CUSTOM_ALLOC, nullptr);
    if (originalPixelMapBytes_ > MIN_PIXEL_BUFFER_SIZE) {
        int32_t originSize = originalPixelMapBytes_;
        float scaleRatio =
            sqrt(static_cast<float>(MIN_PIXEL_BUFFER_SIZE) / static_cast<float>(originalPixelMapBytes_));
        pixelMapTemp->scale(scaleRatio, scaleRatio);
        originalPixelMapBytes_ = pixelMapTemp->GetByteCount();
        SLOGI("imgBufferSize exceeds limitedMin: %{public}d scaled to %{public}d", originSize, originalPixelMapBytes_);
    }
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = ConvertAndSetInnerImgBuffer(pixelMapTemp);
    innerPixelMap->SetOriginalSize(width, height);
    free(dataAddr);
    return innerPixelMap;
}

std::string AVSessionPixelMapAdapter::GetDefaultImageStr()
{
    std::string imgStr = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDAwMDAwIiBoZWlnaHQ9IjI0LjAwMDAwMCIgd"
    "mlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5r"
    "PSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj4KCTxkZXNjPgoJCQlDcmVhdGVkIHdpdGggUGl4c28uCgk8L2Rlc2M+Cgk8ZGV"
    "mcy8+Cgk8ZyBvcGFjaXR5PSIwLjMwMDAwMCI+CgkJPGNpcmNsZSBpZD0i6JKZ54mIIiByPSIxMi4wMDAwMDAiIHRyYW5zZm9ybT0ibW"
    "F0cml4KDAgMSAtMSAwIDEyIDEyKSIgZmlsbD0iI0ZGRkZGRiIgZmlsbC1vcGFjaXR5PSIxLjAwMDAwMCIvPgoJCTxjaXJjbGUgaWQ9I"
    "uiSmeeJiCIgcj0iMTEuNTAwMDAwIiB0cmFuc2Zvcm09Im1hdHJpeCgwIDEgLTEgMCAxMiAxMikiIHN0cm9rZT0iI0ZGRkZGRiIgc3Ry"
    "b2tlLW9wYWNpdHk9IjAiIHN0cm9rZS13aWR0aD0iMS4wMDAwMDAiLz4KCTwvZz4KCTxtYXNrIGlkPSJtYXNrXzE1M183OTU5IiBmaWx"
    "sPSJ3aGl0ZSI+CgkJPHBhdGggaWQ9IuW9oueKtue7k+WQiCIgZD0iTTE3LjY0MzYgNi42NTM5OUMxNy42NTM1IDYuNzE2OCAxNy42Nj"
    "AxIDYuNzgwMDkgMTcuNjYzNCA2Ljg0MzUxTDE3LjY2NTkgNi45Mzg4NEwxNy42NjY2IDE0LjE2NjZDMTcuNjY2NiAxNC4xNzk3IDE3L"
    "jY2NjIgMTQuMTkyNiAxNy42NjU1IDE0LjIwNTVDMTcuNjYxNiAxNC44NjgzIDE3LjY1NDYgMTUuMTgzNyAxNy41MTE0IDE1LjcxNDlD"
    "MTcuMzY1OCAxNi4yNTQzIDE3LjA4MDkgMTYuNzYyMSAxNi41MTMyIDE3LjA4OTRDMTUuNDggMTcuNjg0OCAxNC4yMjggMTcuNDUwOSA"
    "xMy43MTY3IDE2LjU2NjlDMTMuMjA1NCAxNS42ODI5IDEzLjYyODUgMTQuNDgzNSAxNC42NjE2IDEzLjg4ODFDMTUuMDg2MSAxMy42ND"
    "M0IDE1LjYyNTcgMTMuNDI3MSAxNS45OTg5IDEzLjA4NTVDMTYuMjIzIDEyLjg4MDQgMTYuMzMyMiAxMi41ODU1IDE2LjMzMjIgMTEuO"
    "TE4OEMxNi4zMzIyIDExLjkwMDQgMTYuMzMyNSAxMS44ODI0IDE2LjMzMyAxMS44NjUxTDE2LjMzMjcgOC41MDk4OUw5LjY2NjU2IDku"
    "Njg2MjhMOS42NjY1NiAxNS4xMzEyQzkuNjY3MyAxNS4yNzA4IDkuNjY3MjQgMTUuNDExMyA5LjY2NjU2IDE1LjU1MDNMOS42NjY1NiA"
    "xNS42NjY3QzkuNjY2NTYgMTUuNjc4MyA5LjY2NjI2IDE1LjY4OTggOS42NjU2NSAxNS43MDE0QzkuNjYxNSAxNi4zMDk2IDkuNjQ5Mz"
    "UgMTYuNjIwNCA5LjUxMjA4IDE3LjEyOTVDOS4zNjY1OCAxNy42Njg4IDkuMDgxNiAxOC4xNzY3IDguNTEzOTIgMTguNTAzOUM3LjQ4M"
    "DcxIDE5LjA5OTQgNi4yMjg3IDE4Ljg2NTQgNS43MTc0MSAxNy45ODE0QzUuMjA2MTIgMTcuMDk3NCA1LjYyOTIxIDE1Ljg5OCA2LjY2"
    "MjM1IDE1LjMwMjZDNy4wODY3OSAxNS4wNTggNy42MjY0IDE0Ljg0MTcgNy45OTk2MyAxNC41QzguMjIzNjkgMTQuMjk0OSA4LjMzMjk"
    "1IDE0IDguMzMyOTUgMTMuMzMzM0M4LjMzMjk1IDEzLjMyMjcgOC4zMzMwNyAxMy4zMTIyIDguMzMzMjUgMTMuMzAxOUw4LjMzMzI1ID"
    "cuODMwNzVDOC4zMzMyNSA2Ljk2NzUzIDguOTM0MTQgNi4yMjcwNSA5Ljc2NjYgNi4wNDE1Nkw5Ljg4MTUzIDYuMDE5NzFMMTUuNTQ3N"
    "SA1LjEyNzk5QzE2LjU0NzcgNC45NzA1MiAxNy40ODYyIDUuNjUzNzUgMTcuNjQzNiA2LjY1Mzk5WiIgY2xpcC1ydWxlPSJldmVub2Rk"
    "IiBmaWxsPSIiIGZpbGwtb3BhY2l0eT0iMS4wMDAwMDAiIGZpbGwtcnVsZT0iZXZlbm9kZCIvPgoJPC9tYXNrPgoJPHBhdGggaWQ9IuW"
    "9oueKtue7k+WQiCIgZD0iTTE3LjY0MzYgNi42NTM5OUMxNy42NTM1IDYuNzE2OCAxNy42NjAxIDYuNzgwMDkgMTcuNjYzNCA2Ljg0Mz"
    "UxTDE3LjY2NTkgNi45Mzg4NEwxNy42NjY2IDE0LjE2NjZDMTcuNjY2NiAxNC4xNzk3IDE3LjY2NjIgMTQuMTkyNiAxNy42NjU1IDE0L"
    "jIwNTVDMTcuNjYxNiAxNC44NjgzIDE3LjY1NDYgMTUuMTgzNyAxNy41MTE0IDE1LjcxNDlDMTcuMzY1OCAxNi4yNTQzIDE3LjA4MDkg"
    "MTYuNzYyMSAxNi41MTMyIDE3LjA4OTRDMTUuNDggMTcuNjg0OCAxNC4yMjggMTcuNDUwOSAxMy43MTY3IDE2LjU2NjlDMTMuMjA1NCA"
    "xNS42ODI5IDEzLjYyODUgMTQuNDgzNSAxNC42NjE2IDEzLjg4ODFDMTUuMDg2MSAxMy42NDM0IDE1LjYyNTcgMTMuNDI3MSAxNS45OT"
    "g5IDEzLjA4NTVDMTYuMjIzIDEyLjg4MDQgMTYuMzMyMiAxMi41ODU1IDE2LjMzMjIgMTEuOTE4OEMxNi4zMzIyIDExLjkwMDQgMTYuM"
    "zMyNSAxMS44ODI0IDE2LjMzMyAxMS44NjUxTDE2LjMzMjcgOC41MDk4OUw5LjY2NjU2IDkuNjg2MjhMOS42NjY1NiAxNS4xMzEyQzku"
    "NjY3MyAxNS4yNzA4IDkuNjY3MjQgMTUuNDExMyA5LjY2NjU2IDE1LjU1MDNMOS42NjY1NiAxNS42NjY3QzkuNjY2NTYgMTUuNjc4MyA"
    "5LjY2NjI2IDE1LjY4OTggOS42NjU2NSAxNS43MDE0QzkuNjYxNSAxNi4zMDk2IDkuNjQ5MzUgMTYuNjIwNCA5LjUxMjA4IDE3LjEyOT"
    "VDOS4zNjY1OCAxNy42Njg4IDkuMDgxNiAxOC4xNzY3IDguNTEzOTIgMTguNTAzOUM3LjQ4MDcxIDE5LjA5OTQgNi4yMjg3IDE4Ljg2N"
    "TQgNS43MTc0MSAxNy45ODE0QzUuMjA2MTIgMTcuMDk3NCA1LjYyOTIxIDE1Ljg5OCA2LjY2MjM1IDE1LjMwMjZDNy4wODY3OSAxNS4w"
    "NTggNy42MjY0IDE0Ljg0MTcgNy45OTk2MyAxNC41QzguMjIzNjkgMTQuMjk0OSA4LjMzMjk1IDE0IDguMzMyOTUgMTMuMzMzM0M4LjM"
    "zMjk1IDEzLjMyMjcgOC4zMzMwNyAxMy4zMTIyIDguMzMzMjUgMTMuMzAxOUw4LjMzMzI1IDcuODMwNzVDOC4zMzMyNSA2Ljk2NzUzID"
    "guOTM0MTQgNi4yMjcwNSA5Ljc2NjYgNi4wNDE1Nkw5Ljg4MTUzIDYuMDE5NzFMMTUuNTQ3NSA1LjEyNzk5QzE2LjU0NzcgNC45NzA1M"
    "iAxNy40ODYyIDUuNjUzNzUgMTcuNjQzNiA2LjY1Mzk5WiIgY2xpcC1ydWxlPSJldmVub2RkIiBmaWxsPSIjMDAwMDAwIiBmaWxsLW9w"
    "YWNpdHk9IjAuNDAwMDAwIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiIG1hc2s9InVybCgjbWFza18xNTNfNzk1OSkiLz4KCTxwYXRoIGlkPSL"
    "lvaLnirbnu5PlkIgiIGQ9IiIgY2xpcC1ydWxlPSJldmVub2RkIiBmaWxsPSIjMDAwMDAwIiBmaWxsLW9wYWNpdHk9IjAuMDAwMDAwIi"
    "BmaWxsLXJ1bGU9ImV2ZW5vZGQiLz4KPC9zdmc+Cg==";
    return imgStr;
}

std::shared_ptr<Media::PixelMap> AVSessionPixelMapAdapter::ConvertDefaultImage()
{
    if (g_defaultMediaImage) {
        return g_defaultMediaImage;
    }

    std::string image = GetDefaultImageStr();
    uint32_t errorCode = 0;
    SourceOptions opts;
    auto imageSource = ImageSource::CreateImageSource(reinterpret_cast<const uint8_t*>(image.c_str()),
        image.length(), opts, errorCode);
    if (imageSource != nullptr) {
        DecodeOptions dOpts;
        dOpts.allocatorType = Media::AllocatorType::HEAP_ALLOC;
        dOpts.desiredSize.width = DEFAULT_IMAGE_SIZE;
        dOpts.desiredSize.height = DEFAULT_IMAGE_SIZE;
        g_defaultMediaImage = imageSource->CreatePixelMap(dOpts, errorCode);
        if (g_defaultMediaImage != nullptr) {
            SLOGI("ConvertDefaultImage CreatePixelMap success");
            return g_defaultMediaImage;
        }
    } else {
        SLOGE("ConvertDefaultImage createImageSource fail");
    }
    return nullptr;
}
} // namespace OHOS::AVSession
