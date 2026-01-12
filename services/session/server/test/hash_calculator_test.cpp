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

#include <memory.h>
#include "hash_calculator.h"

using namespace OHOS;
using namespace OHOS::AVSession;

class HashCalculatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HashCalculatorTest::SetUpTestCase()
{}

void HashCalculatorTest::TearDownTestCase()
{}

void HashCalculatorTest::SetUp()
{}

void HashCalculatorTest::TearDown()
{}

/**
* @tc.name: Update001
* @tc.desc: test Update
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(HashCalculatorTest, Update001, testing::ext::TestSize.Level0)
{
    HashCalculator hashCalculator;
    std::vector<uint8_t> vec;
    int32_t result = hashCalculator.Update(vec);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    result = hashCalculator.GetResult(vec);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
}