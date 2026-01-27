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

#include <memory>
#include <gtest/gtest.h>
#include "OHAVUtils.h"
#include "avsession_log.h"
#include "OHAVSessionPlaybackState.h"

using namespace testing::ext;
namespace OHOS::AVSession {
class OHAVUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OHAVUtilsTest::SetUpTestCase(void)
{
}

void OHAVUtilsTest::TearDownTestCase(void)
{
}

void OHAVUtilsTest::SetUp()
{
}

void OHAVUtilsTest::TearDown()
{
}

/**
 * @tc.name: OH_AVUtils_WriteCallback_001
 * @tc.desc: Cover function branches
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVUtilsTest, OH_AVUtils_WriteCallback_001, TestSize.Level4)
{
    SLOGI("OH_AVUtils_WriteCallback_001 Begin");
    int32_t realsize = -1;
    std::vector<std::uint8_t> imgBuffer;
    uint8_t ptr[10] = { 0 };
    realsize = AVSessionNdkUtils::WriteCallback(nullptr, 0, 0, nullptr);
    EXPECT_EQ(realsize, 0);
    realsize = AVSessionNdkUtils::WriteCallback(ptr, 0, 0, nullptr);
    EXPECT_EQ(realsize, 0);
    realsize = AVSessionNdkUtils::WriteCallback(ptr, 1, 0, nullptr);
    EXPECT_EQ(realsize, 0);
    realsize = AVSessionNdkUtils::WriteCallback(ptr, 1, 2, nullptr);
    EXPECT_EQ(realsize, 0);
    realsize = AVSessionNdkUtils::WriteCallback(ptr, 1, 2, &imgBuffer);
    EXPECT_EQ(realsize, 2);
    SLOGI("OH_AVUtils_WriteCallback_001 End");
}

/**
 * @tc.name: OH_AVUtils_AVSessionDownloadPostTask_001
 * @tc.desc: Cover function branches
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVUtilsTest, OH_AVUtils_AVSessionDownloadPostTask_001, TestSize.Level4)
{
    SLOGI("OH_AVUtils_AVSessionDownloadPostTask_001 Begin");
    auto cb = [] {};
    std::string cbName = "unkonw";

    bool result = AVSessionDownloadHandler::GetInstance().AVSessionDownloadPostTask(cb, cbName);
    EXPECT_EQ(result, true);

    result = AVSessionDownloadHandler::GetInstance().AVSessionDownloadPostTask(cb, cbName);
    EXPECT_EQ(result, true);

    AVSessionDownloadHandler::GetInstance().AVSessionDownloadRemoveTask(cbName);
    AVSessionDownloadHandler::GetInstance().AVSessionDownloadRemoveHandler();
    AVSessionDownloadHandler::GetInstance().AVSessionDownloadRemoveTask(cbName);

    result = AVSessionDownloadHandler::GetInstance().AVSessionDownloadPostTask(cb, cbName);
    EXPECT_EQ(result, true);
    SLOGI("OH_AVUtils_AVSessionDownloadPostTask_001 End");
}

/**
 * @tc.name: OHAVSessionPlaybackState_ConvertFilter_001
 * @tc.desc: Cover function branches
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVUtilsTest, OHAVSessionPlaybackState_ConvertFilter_001, TestSize.Level4)
{
    SLOGI("OHAVSessionPlaybackState_ConvertFilter_001 Begin");
    int32_t filter1 = 0b1110;
    int32_t filter2 = 0b0001;
    AVPlaybackState::PlaybackStateMaskType playbackMask;

    playbackMask.reset();
    OHAVSessionPlaybackState::ConvertFilter(filter1, playbackMask);
    EXPECT_EQ(playbackMask[AVPlaybackState::PLAYBACK_KEY_STATE], false);
    EXPECT_EQ(playbackMask[AVPlaybackState::PLAYBACK_KEY_POSITION], true);
    EXPECT_EQ(playbackMask[AVPlaybackState::PLAYBACK_KEY_SPEED], true);
    EXPECT_EQ(playbackMask[AVPlaybackState::PLAYBACK_KEY_VOLUME], true);

    playbackMask.reset();
    OHAVSessionPlaybackState::ConvertFilter(filter2, playbackMask);
    EXPECT_EQ(playbackMask[AVPlaybackState::PLAYBACK_KEY_STATE], true);
    EXPECT_EQ(playbackMask[AVPlaybackState::PLAYBACK_KEY_POSITION], false);
    EXPECT_EQ(playbackMask[AVPlaybackState::PLAYBACK_KEY_SPEED], false);
    EXPECT_EQ(playbackMask[AVPlaybackState::PLAYBACK_KEY_VOLUME], false);
    SLOGI("OHAVSessionPlaybackState_ConvertFilter_001 End");
}
}