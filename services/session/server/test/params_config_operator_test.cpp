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
#include "params_config_operator.h"
#undef protected
#undef private

using namespace OHOS;
using namespace OHOS::AVSession;

static std::string g_errLog;

void MyLogCallback(const LogType type, const LogLevel level,
    const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}

class ParamsConfigOperatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ParamsConfigOperatorTest::SetUpTestCase()
{
}

void ParamsConfigOperatorTest::TearDownTestCase()
{
}

void ParamsConfigOperatorTest::SetUp()
{
}

void ParamsConfigOperatorTest::TearDown()
{
}

/**
 * @tc.name: InitConfig001
 * @tc.desc: Test InitConfig
 * @tc.type: FUNC
 */
static HWTEST_F(ParamsConfigOperatorTest, InitConfig001, testing::ext::TestSize.Level1)
{
    SLOGI("InitConfig001 begin!");
    LOG_SetCallback(MyLogCallback);
    auto paramsConfigOperator = ParamsConfigOperator::GetInstance();
    paramsConfigOperator.InitConfig();
    EXPECT_TRUE(g_errLog.find("xxx") == std::string::npos);
    SLOGI("InitConfig001 end!");
}

/**
 * @tc.name: GetValueIntByKey001
 * @tc.desc: Test GetValueIntByKey
 * @tc.type: FUNC
 */
static HWTEST_F(ParamsConfigOperatorTest, GetValueIntByKey001, testing::ext::TestSize.Level1)
{
    SLOGI("GetValueIntByKey001 begin!");
    auto paramsConfigOperator = ParamsConfigOperator::GetInstance();
    int32_t *value = nullptr;
    int32_t ret = paramsConfigOperator.GetValueIntByKey("test1", value);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetValueIntByKey001 end!");
}

/**
 * @tc.name: GetValueIntByKey002
 * @tc.desc: Test GetValueIntByKey
 * @tc.type: FUNC
 */
static HWTEST_F(ParamsConfigOperatorTest, GetValueIntByKey002, testing::ext::TestSize.Level1)
{
    SLOGI("GetValueIntByKey002 begin!");
    auto paramsConfigOperator = ParamsConfigOperator::GetInstance();
    int32_t *value = nullptr;
    paramsConfigOperator.configStringParams["test2"] = "test2";
    int32_t ret = paramsConfigOperator.GetValueIntByKey("test2", value);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetValueIntByKey002 end!");
}
