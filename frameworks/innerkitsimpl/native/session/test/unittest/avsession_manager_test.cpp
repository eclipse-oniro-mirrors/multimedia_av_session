/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "avsession_manager.h"
using namespace testing::ext;
using namespace OHOS::AVSession;
class AvsessionManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AvsessionManagerTest::SetUpTestCase(void)
{}

void AvsessionManagerTest::TearDownTestCase(void)
{}

void AvsessionManagerTest::SetUp(void)
{}

void AvsessionManagerTest::TearDown(void)
{}

/**
* @tc.name: testcase001
* @tc.desc: Creat a new session
* @tc.type: FUNC
* @tc.require: XXXX
*/
HWTEST_F(AvsessionManagerTest, CreatSession001, TestSize.Level0)
{
    ZLOGI("CreatSession001 begin.");
    std::shared_ptr<AVSession> avsession;
    avsession = AVSessionManager::CreateSession("Application A creat session");
    EXPECT_NE(avsession, nullptr);
}

