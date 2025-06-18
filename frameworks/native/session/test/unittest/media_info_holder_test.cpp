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

#include "avsession_log.h"
#include "media_info_holder.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {

static constexpr int32_t TEST_NUM = 2000;
class MediaInfoHolderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void MediaInfoHolderTest::SetUpTestCase()
{}

void MediaInfoHolderTest::TearDownTestCase()
{}

void MediaInfoHolderTest::SetUp()
{}

void MediaInfoHolderTest::TearDown()
{}

/**
* @tc.name: SetAVCallState001
* @tc.desc: test SetAVCallState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MediaInfoHolderTest, SetAVCallState001, TestSize.Level0)
{
    MediaInfoHolder mediaInfoHolder;
    Parcel parcel;
    parcel.SetDataSize(0);
    parcel.GetDataCapacity();
    mediaInfoHolder.SetCurrentIndex(1);
    AVQueueItem avQueueItem;
    std::vector<AVQueueItem> playInfos = {avQueueItem};
    mediaInfoHolder.SetPlayInfos(playInfos);
    ASSERT_TRUE(mediaInfoHolder.Marshalling(parcel));
    MediaInfoHolder *result = mediaInfoHolder.Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
* @tc.name: SetAVCallState002
* @tc.desc: test SetAVCallState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(MediaInfoHolderTest, SetAVCallState002, TestSize.Level0)
{
    MediaInfoHolder mediaInfoHolder;
    Parcel parcel;
    mediaInfoHolder.SetCurrentIndex(1);
    std::vector<AVQueueItem> playInfos;
 
    for (int32_t i = 0; i < TEST_NUM; ++i) {
        AVQueueItem avQueueItem;
        playInfos.push_back(avQueueItem);
    }
    mediaInfoHolder.SetPlayInfos(playInfos);
    EXPECT_TRUE(mediaInfoHolder.Marshalling(parcel));
    MediaInfoHolder *result = mediaInfoHolder.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

} // namespace AVSession
} // namespace OHOS