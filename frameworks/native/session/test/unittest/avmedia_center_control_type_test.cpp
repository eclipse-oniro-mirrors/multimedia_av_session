/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "avmedia_center_control_type.h"

using namespace testing::ext;
namespace OHOS {
namespace AVSession {

class AVMediaCenterControlTypeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVMediaCenterControlTypeTest::SetUpTestCase()
{
}

void AVMediaCenterControlTypeTest::TearDownTestCase()
{
}

void AVMediaCenterControlTypeTest::SetUp()
{
}

void AVMediaCenterControlTypeTest::TearDown()
{
}

/**
 * @tc.name: MediaCenterTypesToNums001
 * @tc.desc: Test MediaCenterTypesToNums with valid strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVMediaCenterControlTypeTest, MediaCenterTypesToNums001, TestSize.Level1)
{
    std::vector<std::string> types = {"playNext", "playPrevious", "fastForward"};
    std::vector<int32_t> nums = MediaCenterTypesToNums(types);
    EXPECT_EQ(nums.size(), 3);
    EXPECT_EQ(nums[0], 0);
    EXPECT_EQ(nums[1], 1);
    EXPECT_EQ(nums[2], 2);
}

/**
 * @tc.name: MediaCenterTypesToNums002
 * @tc.desc: Test MediaCenterTypesToNums with empty array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVMediaCenterControlTypeTest, MediaCenterTypesToNums002, TestSize.Level1)
{
    std::vector<std::string> types = {};
    std::vector<int32_t> nums = MediaCenterTypesToNums(types);
    EXPECT_EQ(nums.size(), 0);
}

/**
 * @tc.name: MediaCenterTypesToNums003
 * @tc.desc: Test MediaCenterTypesToNums with invalid string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVMediaCenterControlTypeTest, MediaCenterTypesToNums003, TestSize.Level1)
{
    std::vector<std::string> types = {"playNext", "invalidType", "fastForward"};
    std::vector<int32_t> nums = MediaCenterTypesToNums(types);
    EXPECT_EQ(nums.size(), 2);
    EXPECT_EQ(nums[0], 0);
    EXPECT_EQ(nums[1], 2);
}

/**
 * @tc.name: MediaCenterTypesToStrs001
 * @tc.desc: Test MediaCenterTypesToStrs with valid nums
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVMediaCenterControlTypeTest, MediaCenterTypesToStrs001, TestSize.Level1)
{
    std::vector<int32_t> nums = {0, 1, 2, 3, 4, 5, 6};
    std::vector<std::string> types = MediaCenterTypesToStrs(nums);
    EXPECT_EQ(types.size(), 7);
    EXPECT_EQ(types[0], "playNext");
    EXPECT_EQ(types[1], "playPrevious");
    EXPECT_EQ(types[2], "fastForward");
    EXPECT_EQ(types[3], "rewind");
    EXPECT_EQ(types[4], "setSpeed");
    EXPECT_EQ(types[5], "setLoopMode");
    EXPECT_EQ(types[6], "toggleFavorite");
}

/**
 * @tc.name: MediaCenterTypesToStrs002
 * @tc.desc: Test MediaCenterTypesToStrs with empty array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVMediaCenterControlTypeTest, MediaCenterTypesToStrs002, TestSize.Level1)
{
    std::vector<int32_t> nums = {};
    std::vector<std::string> types = MediaCenterTypesToStrs(nums);
    EXPECT_EQ(types.size(), 0);
}

/**
 * @tc.name: MediaCenterTypesToStrs003
 * @tc.desc: Test MediaCenterTypesToStrs with invalid num
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVMediaCenterControlTypeTest, MediaCenterTypesToStrs003, TestSize.Level1)
{
    std::vector<int32_t> nums = {0, 100, 2};
    std::vector<std::string> types = MediaCenterTypesToStrs(nums);
    EXPECT_EQ(types.size(), 2);
    EXPECT_EQ(types[0], "playNext");
    EXPECT_EQ(types[1], "fastForward");
}

/**
 * @tc.name: GetMediaCenterTypeToStrMap001
 * @tc.desc: Test GetMediaCenterTypeToStrMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVMediaCenterControlTypeTest, GetMediaCenterTypeToStrMap001, TestSize.Level1)
{
    const auto& strMap = GetMediaCenterTypeToStrMap();
    EXPECT_EQ(strMap.size(), 7);
    EXPECT_EQ(strMap.find(0)->second, "playNext");
    EXPECT_EQ(strMap.find(6)->second, "toggleFavorite");
    EXPECT_EQ(strMap.find(100), strMap.end());
}

/**
 * @tc.name: GetMediaCenterTypeToNumMap001
 * @tc.desc: Test GetMediaCenterTypeToNumMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVMediaCenterControlTypeTest, GetMediaCenterTypeToNumMap001, TestSize.Level1)
{
    const auto& numMap = GetMediaCenterTypeToNumMap();
    EXPECT_EQ(numMap.size(), 7);
    EXPECT_EQ(numMap.find("playNext")->second, 0);
    EXPECT_EQ(numMap.find("toggleFavorite")->second, 6);
    EXPECT_EQ(numMap.find("invalid"), numMap.end());
}
} // namespace AVSession
} // namespace OHOS