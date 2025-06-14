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
#include "avsession_errors.h"
#include "timer.h"
#define private public
#define protected public
#include "command_send_limit.h"
#undef protected
#undef private

using namespace OHOS;
using namespace OHOS::AVSession;

class CommandSendLimitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CommandSendLimitTest::SetUpTestCase()
{
}

void CommandSendLimitTest::TearDownTestCase()
{
}

void CommandSendLimitTest::SetUp()
{
}

void CommandSendLimitTest::TearDown()
{
}

/**
 * @tc.name: IsCommandSendEnable001
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(CommandSendLimitTest, IsCommandSendEnable001, testing::ext::TestSize.Level0)
{
    SLOGI("StartAbilityByCall001 begin!");
    bool ret = CommandSendLimit::GetInstance().IsCommandSendEnable(0);
    EXPECT_EQ(ret, true);
    SLOGI("StartAbilityByCall001 end!");
}

/**
 * @tc.name: IsCommandSendEnable002
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(CommandSendLimitTest, IsCommandSendEnable002, testing::ext::TestSize.Level0)
{
    SLOGI("IsCommandSendEnable002 begin!");
    CommandSendLimit::GetInstance().timer_ = std::make_unique<OHOS::Utils::Timer>("EventStatisticTimer");
    bool ret = CommandSendLimit::GetInstance().IsCommandSendEnable(0);
    EXPECT_EQ(ret, true);
    SLOGI("IsCommandSendEnable002 end!");
}

/**
 * @tc.name: IsCommandSendEnable003
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(CommandSendLimitTest, IsCommandSendEnable003, testing::ext::TestSize.Level0)
{
    SLOGI("IsCommandSendEnable003 begin!");
    CommandSendLimit::GetInstance().commandLimits_[1] = 11;
    bool ret = CommandSendLimit::GetInstance().IsCommandSendEnable(1);
    EXPECT_EQ(ret, false);
    SLOGI("IsCommandSendEnable003 end!");
}

/**
 * @tc.name: IsCommandSendEnable004
 * @tc.desc: Test IsCommandSendEnable
 * @tc.type: FUNC
 */
static HWTEST_F(CommandSendLimitTest, IsCommandSendEnable004, testing::ext::TestSize.Level0)
{
    SLOGI("IsCommandSendEnable004 begin!");
    CommandSendLimit::GetInstance().commandLimits_[2] = 5;
    bool ret = CommandSendLimit::GetInstance().IsCommandSendEnable(2);
    EXPECT_EQ(ret, true);
    SLOGI("IsCommandSendEnable004 end!");
}

/**
 * @tc.name: StopTimer001
 * @tc.desc: Test StopTimer
 * @tc.type: FUNC
 */
static HWTEST_F(CommandSendLimitTest, StopTimer001, testing::ext::TestSize.Level0)
{
    SLOGI("StopTimer001 begin!");
    CommandSendLimit::GetInstance().timer_ = std::make_unique<OHOS::Utils::Timer>("EventStatisticTimer");
    EXPECT_TRUE(CommandSendLimit::GetInstance().timer_ != nullptr);
    CommandSendLimit::GetInstance().StopTimer();
    SLOGI("StopTimer001 end!");
}