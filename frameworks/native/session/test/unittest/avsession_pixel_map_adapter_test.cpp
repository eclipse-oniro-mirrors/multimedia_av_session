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

} // namespace AVSESSION
} // namespace OHOS