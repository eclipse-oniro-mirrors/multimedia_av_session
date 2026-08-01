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

#include <cmath>
#include <limits>

#include <gtest/gtest.h>

#include "avcast_control_command.h"
#include "avcontrol_command.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "avsession_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVCastControlCommandLoopModeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVCastControlCommandLoopModeTest::SetUpTestCase()
{}

void AVCastControlCommandLoopModeTest::TearDownTestCase()
{}

void AVCastControlCommandLoopModeTest::SetUp()
{}

void AVCastControlCommandLoopModeTest::TearDown()
{}

/**
 * @tc.name: SetLoopModeInvalidBelowRange001
 * @tc.desc: SetLoopMode with negative loop mode should return ERR_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(AVCastControlCommandLoopModeTest, SetLoopModeInvalidBelowRange001, TestSize.Level0)
{
    SLOGI("SetLoopModeInvalidBelowRange001 Begin");
    AVCastControlCommand command;
    EXPECT_EQ(command.SetLoopMode(-1), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetLoopMode(-2), ERR_INVALID_PARAM);
    SLOGI("SetLoopModeInvalidBelowRange001 End");
}

/**
 * @tc.name: SetLoopModeInvalidAboveRange002
 * @tc.desc: SetLoopMode with loop mode above LOOP_MODE_CUSTOM should return ERR_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(AVCastControlCommandLoopModeTest, SetLoopModeInvalidAboveRange002, TestSize.Level0)
{
    SLOGI("SetLoopModeInvalidAboveRange002 Begin");
    AVCastControlCommand command;
    EXPECT_EQ(command.SetLoopMode(5), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetLoopMode(999999), ERR_INVALID_PARAM);
    SLOGI("SetLoopModeInvalidAboveRange002 End");
}

/**
 * @tc.name: SetLoopModeValidBoundary003
 * @tc.desc: SetLoopMode with lower and upper boundary values should return AVSESSION_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(AVCastControlCommandLoopModeTest, SetLoopModeValidBoundary003, TestSize.Level0)
{
    SLOGI("SetLoopModeValidBoundary003 Begin");
    AVCastControlCommand command;
    EXPECT_EQ(command.SetLoopMode(AVPlaybackState::LOOP_MODE_SEQUENCE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetLoopMode(AVPlaybackState::LOOP_MODE_CUSTOM), AVSESSION_SUCCESS);
    SLOGI("SetLoopModeValidBoundary003 End");
}

/**
 * @tc.name: SetLoopModeValid004
 * @tc.desc: SetLoopMode with valid values should return AVSESSION_SUCCESS and round-trip via GetLoopMode
 * @tc.type: FUNC
 */
HWTEST_F(AVCastControlCommandLoopModeTest, SetLoopModeValid004, TestSize.Level0)
{
    SLOGI("SetLoopModeValid004 Begin");
    AVCastControlCommand command;
    EXPECT_EQ(command.SetLoopMode(AVPlaybackState::LOOP_MODE_SINGLE), AVSESSION_SUCCESS);
    int32_t loopMode = 0;
    EXPECT_EQ(command.GetLoopMode(loopMode), AVSESSION_SUCCESS);
    EXPECT_EQ(loopMode, AVPlaybackState::LOOP_MODE_SINGLE);

    EXPECT_EQ(command.SetLoopMode(AVPlaybackState::LOOP_MODE_SHUFFLE), AVSESSION_SUCCESS);
    loopMode = 0;
    EXPECT_EQ(command.GetLoopMode(loopMode), AVSESSION_SUCCESS);
    EXPECT_EQ(loopMode, AVPlaybackState::LOOP_MODE_SHUFFLE);
    SLOGI("SetLoopModeValid004 End");
}

class AVControlCommandSpeedTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVControlCommandSpeedTest::SetUpTestCase()
{}

void AVControlCommandSpeedTest::TearDownTestCase()
{}

void AVControlCommandSpeedTest::SetUp()
{}

void AVControlCommandSpeedTest::TearDown()
{}

/**
 * @tc.name: SetSpeedInvalidNaN001
 * @tc.desc: SetSpeed with NaN should return ERR_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(AVControlCommandSpeedTest, SetSpeedInvalidNaN001, TestSize.Level0)
{
    SLOGI("SetSpeedInvalidNaN001 Begin");
    AVControlCommand command;
    EXPECT_EQ(command.SetSpeed(std::numeric_limits<double>::quiet_NaN()), ERR_INVALID_PARAM);
    SLOGI("SetSpeedInvalidNaN001 End");
}

/**
 * @tc.name: SetSpeedInvalidInfinity002
 * @tc.desc: SetSpeed with positive or negative infinity should return ERR_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(AVControlCommandSpeedTest, SetSpeedInvalidInfinity002, TestSize.Level0)
{
    SLOGI("SetSpeedInvalidInfinity002 Begin");
    AVControlCommand command;
    EXPECT_EQ(command.SetSpeed(std::numeric_limits<double>::infinity()), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetSpeed(-std::numeric_limits<double>::infinity()), ERR_INVALID_PARAM);
    SLOGI("SetSpeedInvalidInfinity002 End");
}

/**
 * @tc.name: SetSpeedInvalidNonPositive003
 * @tc.desc: SetSpeed with zero or negative speed should return ERR_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(AVControlCommandSpeedTest, SetSpeedInvalidNonPositive003, TestSize.Level0)
{
    SLOGI("SetSpeedInvalidNonPositive003 Begin");
    AVControlCommand command;
    EXPECT_EQ(command.SetSpeed(0.0), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetSpeed(-1.0), ERR_INVALID_PARAM);
    SLOGI("SetSpeedInvalidNonPositive003 End");
}

/**
 * @tc.name: SetSpeedValid004
 * @tc.desc: SetSpeed with positive finite speed should return AVSESSION_SUCCESS and round-trip via GetSpeed
 * @tc.type: FUNC
 */
HWTEST_F(AVControlCommandSpeedTest, SetSpeedValid004, TestSize.Level0)
{
    SLOGI("SetSpeedValid004 Begin");
    AVControlCommand command;
    EXPECT_EQ(command.SetSpeed(1.0), AVSESSION_SUCCESS);
    double speed = 0.0;
    EXPECT_EQ(command.GetSpeed(speed), AVSESSION_SUCCESS);
    EXPECT_DOUBLE_EQ(speed, 1.0);

    EXPECT_EQ(command.SetSpeed(2.5), AVSESSION_SUCCESS);
    speed = 0.0;
    EXPECT_EQ(command.GetSpeed(speed), AVSESSION_SUCCESS);
    EXPECT_DOUBLE_EQ(speed, 2.5);
    SLOGI("SetSpeedValid004 End");
}
} // namespace AVSession
} // namespace OHOS
