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

#include "avsessionpixelmapadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <array>
#include <fuzzer/FuzzedDataProvider.h>

#include "avsession_pixel_map_adapter.h"
#include "avsession_log.h"
#include "avmeta_data.h"
#include "avqueue_info.h"
#include "securec.h"
#include "permission_checker.h"
#include "hash_calculator.h"
#include "avsession_dynamic_loader.h"

namespace OHOS::AVSession {
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t MAX_PIXEL_SIZE = 10 * 10 * 200;
static constexpr int32_t LIMITED_PIXEL_SIZE = 10 * 10 * 80;
static constexpr int32_t MIN_PIXEL_SIZE = 10 * 10 * 8;
static constexpr int32_t IMAGE_WIDTH = 100;
static constexpr int32_t IMAGE_HEIGHT = 100;
static constexpr int32_t MUSIC_UID = 20020048;

static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos = 0;
static std::vector<std::uint8_t> g_buffer(MAX_PIXEL_SIZE * IMAGE_HEIGHT, 0x03);
static const std::string AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH = std::string("libavsession_dynamic_insight.z.so");
using TestFunc = void(*)();

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || g_pos >= g_dataSize || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

void CopyPixMapToDstTest()
{
    OHOS::Media::PixelMap source;
    OHOS::Media::ImageInfo imageInfo = {
        .size = {IMAGE_WIDTH, IMAGE_HEIGHT},
        .pixelFormat = OHOS::Media::PixelFormat::ARGB_8888,
        .colorSpace = OHOS::Media::ColorSpace::SRGB,
        .alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        .baseDensity = 0,
        .encodedFormat = ""
    };
    source.SetImageInfo(imageInfo);
    source.SetPixelsAddr(nullptr, nullptr, MIN_PIXEL_SIZE, OHOS::Media::AllocatorType::DMA_ALLOC, nullptr);
    AVSessionPixelMapAdapter::CopyPixMapToDst(source, nullptr, 0);
    source.SetPixelsAddr(nullptr, nullptr, MIN_PIXEL_SIZE, OHOS::Media::AllocatorType::CUSTOM_ALLOC, nullptr);
    AVSessionPixelMapAdapter::CopyPixMapToDst(source, nullptr, 0);
}

void ConvertToInnerTest()
{
    OHOS::Media::PixelMap source;
    OHOS::Media::ImageInfo imageInfo = {
        .size = {IMAGE_WIDTH, IMAGE_HEIGHT},
        .pixelFormat = OHOS::Media::PixelFormat::ARGB_8888,
        .colorSpace = OHOS::Media::ColorSpace::SRGB,
        .alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        .baseDensity = 0,
        .encodedFormat = ""
    };
    source.SetImageInfo(imageInfo);
    source.SetPixelsAddr(g_buffer.data(), nullptr, MAX_PIXEL_SIZE, OHOS::Media::AllocatorType::DMA_ALLOC, nullptr);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::make_shared<OHOS::Media::PixelMap>(source);
    AVSessionPixelMapAdapter::ConvertToInner(pixelMap);
}

void ConvertToInnerWithLimitedSizeTest()
{
    OHOS::Media::PixelMap source;
    OHOS::Media::ImageInfo imageInfo = {
        .size = {IMAGE_WIDTH, IMAGE_HEIGHT},
        .pixelFormat = OHOS::Media::PixelFormat::ARGB_8888,
        .colorSpace = OHOS::Media::ColorSpace::SRGB,
        .alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        .baseDensity = 0,
        .encodedFormat = ""
    };
    source.SetImageInfo(imageInfo);
    source.SetPixelsAddr(g_buffer.data(), nullptr, LIMITED_PIXEL_SIZE, OHOS::Media::AllocatorType::DMA_ALLOC, nullptr);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::make_shared<OHOS::Media::PixelMap>(source);
    AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
}

void ConvertToInnerWithMinSizeTest()
{
    OHOS::Media::PixelMap source;
    OHOS::Media::ImageInfo imageInfo = {
        .size = {IMAGE_WIDTH, IMAGE_HEIGHT},
        .pixelFormat = OHOS::Media::PixelFormat::ARGB_8888,
        .colorSpace = OHOS::Media::ColorSpace::SRGB,
        .alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        .baseDensity = 0,
        .encodedFormat = ""
    };
    source.SetImageInfo(imageInfo);
    source.SetPixelsAddr(g_buffer.data(), nullptr, MIN_PIXEL_SIZE, OHOS::Media::AllocatorType::DMA_ALLOC, nullptr);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::make_shared<OHOS::Media::PixelMap>(source);
    AVSessionPixelMapAdapter::ConvertToInnerWithMinSize(pixelMap);
}

void AVQueueInfoMarshllingTest()
{
    AVQueueInfo info = {};
    MessageParcel parcel;
    info.MarshallingMessageParcel(parcel);
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    if (pixelMap == nullptr) {
        return;
    }
    uint8_t size = GetData<uint8_t>();
    if (size == 0) {
        size++;
    }
    std::vector<uint8_t> imgBuffer(size, '\0');
    pixelMap->SetInnerImgBuffer(imgBuffer);
    info.SetAVQueueImage(pixelMap);
    info.MarshallingQueueImage(parcel);
}

void CheckSystemPermissionByUidTest()
{
    int32_t uid = GetData<int32_t>();
    PermissionChecker::CheckSystemPermissionByUid(uid);
    PermissionChecker::CheckSystemPermissionByUid(MUSIC_UID);
}

void HashCalculatorTest()
{
    HashCalculator calc {};
    std::vector<uint8_t> value;
    calc.Update(value);
    calc.GetResult(value);
}

void AVSessionDynamicLoaderTest()
{
    std::unique_ptr<AVSessionDynamicLoader> dynamicLoader = std::make_unique<AVSessionDynamicLoader>();
    if (dynamicLoader == nullptr) {
        return;
    }
    dynamicLoader->GetFuntion(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, "StartAVPlaybackWithId");
    dynamicLoader->CloseDynamicHandle(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH);
}

static const std::array<TestFunc, 8> g_testFuncs = {
    CopyPixMapToDstTest,
    ConvertToInnerTest,
    ConvertToInnerWithLimitedSizeTest,
    ConvertToInnerWithMinSizeTest,
    AVQueueInfoMarshllingTest,
    CheckSystemPermissionByUidTest,
    HashCalculatorTest,
    AVSessionDynamicLoaderTest,
};

static void FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size > MAX_CODE_LEN) {
        return;
    }
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    size_t len = g_testFuncs.size();
    if (len > 0) {
        uint32_t index = static_cast<uint32_t>(code % len);
        if (g_testFuncs[index]) {
            g_testFuncs[index]();
        }
    } else {
        SLOGI("%{public}s: The len length is equal to 0", __func__);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }

    /* Run your code on data */
    FuzzTest(data, size);
    return 0;
}
} // namespace OHOS::AVSession
