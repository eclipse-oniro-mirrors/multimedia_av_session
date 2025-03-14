/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "avsession_pixel_map_adapter.h"
#include "avsession_log.h"
#include "securec.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVSessionPixelMapAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionPixelMapAdapterTest::SetUpTestCase()
{}

void AVSessionPixelMapAdapterTest::TearDownTestCase()
{}

void AVSessionPixelMapAdapterTest::SetUp()
{}

void AVSessionPixelMapAdapterTest::TearDown()
{}

/**
* @tc.name: OnPlaybackStateChange001
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionPixelMapAdapterTest, OnPlaybackStateChange001, TestSize.Level1)
{
    std::shared_ptr<AVSessionPixelMap> ptr = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {255, 255};
    ptr->SetInnerImgBuffer(vec);
    AVSessionPixelMapAdapter avsessionPixelMapAdapter;
    auto p = avsessionPixelMapAdapter.ConvertFromInner(ptr);
    EXPECT_EQ(p, nullptr);
}

/**
* @tc.name: OnPlaybackStateChange002
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionPixelMapAdapterTest, OnPlaybackStateChange002, TestSize.Level1)
{
    std::shared_ptr<AVSessionPixelMap> ptr = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {0, 0};
    ptr->SetInnerImgBuffer(vec);
    AVSessionPixelMapAdapter avsessionPixelMapAdapter;
    auto p = avsessionPixelMapAdapter.ConvertFromInner(ptr);
    EXPECT_EQ(p, nullptr);
}

/**
* @tc.name: CopyPixMapToDst001
* @tc.desc: test CopyPixMapToDst
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionPixelMapAdapterTest, CopyPixMapToDst001, TestSize.Level1)
{
    Media::PixelMap pixelMap;
    pixelMap.SetPixelsAddr(nullptr, nullptr, 10, Media::AllocatorType::DMA_ALLOC, nullptr);
    Media::PixelMap source;
    AVSessionPixelMapAdapter avsessionPixelMapAdapter;
    bool result = avsessionPixelMapAdapter.CopyPixMapToDst(source, nullptr, 10);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: AVSessionPixelMapAdapterTest_CleanAVSessionPixelMap_001
 * @tc.desc: Test CleanAVSessionPixelMap with a non-null innerPixelMap.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionPixelMapAdapterTest, CleanAVSessionPixelMap_001, TestSize.Level1)
{
    SLOGD("AVSessionPixelMapAdapterTest_CleanAVSessionPixelMap_001 begin!");
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {1, 2, 3, 4, 5};
    innerPixelMap->SetInnerImgBuffer(imgBuffer);
    AVSessionPixelMapAdapter adapter;
    adapter.CleanAVSessionPixelMap(innerPixelMap);
    EXPECT_TRUE(innerPixelMap->GetInnerImgBuffer().empty());
    SLOGD("AVSessionPixelMapAdapterTest_CleanAVSessionPixelMap_001 end!");
}


/**
 * @tc.name: CopyPixMapToDst_001
 * @tc.desc: Test CopyPixMapToDst with DMA allocator but no copy failure.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionPixelMapAdapterTest, CopyPixMapToDst_001, TestSize.Level1)
{
    SLOGD("CopyPixMapToDst_001 begin!");
    OHOS::Media::PixelMap source;
    OHOS::Media::ImageInfo imageInfo = {
        .size = {10, 10},
        .pixelFormat = OHOS::Media::PixelFormat::ARGB_8888,
        .colorSpace = OHOS::Media::ColorSpace::SRGB,
        .alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        .baseDensity = 0,
        .encodedFormat = ""
    };
    source.SetImageInfo(imageInfo);
    source.SetPixelsAddr(nullptr, nullptr, 10 * 10 * 4, OHOS::Media::AllocatorType::DMA_ALLOC, nullptr);
    uint32_t bufferSize = source.GetRowBytes() * source.GetHeight();
    std::vector<uint8_t> dstPixels(bufferSize);
    bool result = AVSessionPixelMapAdapter::CopyPixMapToDst(source, dstPixels.data(), bufferSize);
    EXPECT_FALSE(result);
    SLOGD("CopyPixMapToDst_001 end!");
}

/**
 * @tc.name: ConvertToInner_001
 * @tc.desc: Test ConvertToInner with CopyPixMapToDst failure due to insufficient buffer size.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionPixelMapAdapterTest, ConvertToInner_001, TestSize.Level1)
{
    SLOGD("ConvertToInner_001 begin!");
    OHOS::Media::PixelMap source;
    OHOS::Media::ImageInfo imageInfo = {
        .size = {10, 10},
        .pixelFormat = OHOS::Media::PixelFormat::ARGB_8888,
        .colorSpace = OHOS::Media::ColorSpace::SRGB,
        .alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        .baseDensity = 0,
        .encodedFormat = ""
    };
    source.SetImageInfo(imageInfo);
    source.SetPixelsAddr(nullptr, nullptr, 10 * 10 * 4, OHOS::Media::AllocatorType::DMA_ALLOC, nullptr);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::make_shared<OHOS::Media::PixelMap>(source);
    std::shared_ptr<AVSessionPixelMap> result = AVSessionPixelMapAdapter::ConvertToInner(pixelMap);
    EXPECT_EQ(result, nullptr);
    SLOGD("ConvertToInner_001 end!");
}

/**
 * @tc.name: ConvertToInnerWithMinSize_001
 * @tc.desc: Test ConvertToInnerWithMinSize with CopyPixMapToDst failure.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionPixelMapAdapterTest, ConvertToInnerWithMinSize_001, TestSize.Level1)
{
    SLOGD("ConvertToInnerWithMinSize_001 begin!");
    OHOS::Media::PixelMap source;
    OHOS::Media::ImageInfo imageInfo = {
        .size = {10, 10},
        .pixelFormat = OHOS::Media::PixelFormat::ARGB_8888,
        .colorSpace = OHOS::Media::ColorSpace::SRGB,
        .alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        .baseDensity = 0,
        .encodedFormat = ""
    };
    source.SetImageInfo(imageInfo);
    source.SetPixelsAddr(nullptr, nullptr, 10 * 10 * 4, OHOS::Media::AllocatorType::DMA_ALLOC, nullptr);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::make_shared<OHOS::Media::PixelMap>(source);
    std::shared_ptr<AVSessionPixelMap> result = AVSessionPixelMapAdapter::ConvertToInnerWithMinSize(pixelMap);
    EXPECT_EQ(result, nullptr);
    SLOGD("ConvertToInnerWithMinSize_001 end!");
}

/**
 * @tc.name: ConvertToInnerWithLimitedSize_001
 * @tc.desc: Test ConvertToInnerWithLimitedSize with CopyPixMapToDst failure.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVSessionPixelMapAdapterTest, ConvertToInnerWithLimitedSize_001, TestSize.Level1)
{
    SLOGD("ConvertToInnerWithLimitedSize_001 begin!");
    OHOS::Media::PixelMap source;
    OHOS::Media::ImageInfo imageInfo = {
        .size = {10, 10},
        .pixelFormat = OHOS::Media::PixelFormat::ARGB_8888,
        .colorSpace = OHOS::Media::ColorSpace::SRGB,
        .alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        .baseDensity = 0,
        .encodedFormat = ""
    };
    source.SetImageInfo(imageInfo);
    source.SetPixelsAddr(nullptr, nullptr, 10 * 10 * 4, OHOS::Media::AllocatorType::DMA_ALLOC, nullptr);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::make_shared<OHOS::Media::PixelMap>(source);
    std::shared_ptr<AVSessionPixelMap> result = AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    EXPECT_EQ(result, nullptr);
    SLOGD("ConvertToInnerWithLimitedSize_001 end!");
}
} // namespace AVSESSION
} // namespace OHOS