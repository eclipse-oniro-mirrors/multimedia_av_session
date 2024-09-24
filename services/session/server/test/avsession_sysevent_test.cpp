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

#include "avsession_sysevent.h"

using namespace OHOS;
using namespace OHOS::AVSession;

class AVsessionSyseventTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVsessionSyseventTest::SetUpTestCase()
{}

void AVsessionSyseventTest::TearDownTestCase()
{}

void AVsessionSyseventTest::SetUp()
{}

void AVsessionSyseventTest::TearDown()
{}

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
/**
* @tc.name: Regiter001
* @tc.desc: test Regiter
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVsessionSyseventTest, Regiter001, testing::ext::TestSize.Level1)
{
    AVSessionSysEvent::GetInstance().Unregister();
    EXPECT_EQ(AVSessionSysEvent::GetInstance().timer_, nullptr);
    AVSessionSysEvent::GetInstance().Regiter();
    AVSessionSysEvent::GetInstance().Regiter();
    AVSessionSysEvent::GetInstance().Unregister();
}
#endif