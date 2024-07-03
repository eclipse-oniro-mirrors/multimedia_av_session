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
#include "session_stack.h"
#include "avsession_log.h"
#include "system_ability_definition.h"

#define private public
#include "avsession_service.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AVSession;

class SessionStackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SessionStackTest::SetUpTestCase()
{}

void SessionStackTest::TearDownTestCase()
{}

void SessionStackTest::SetUp()
{}

void SessionStackTest::TearDown()
{}

/**
* @tc.name: RemoveSession001
* @tc.desc: verifying session stack remove session
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(SessionStackTest, RemoveSession001, TestSize.Level1)
{
    SLOGI("RemoveSession001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    AVSessionService* avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr <AVSessionItem> item =
        avSessionService_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    SLOGI("RemoveSession001 doSessionCreate done!");
    sleep(1);
    item->SetPid(1234);
    item->SetUid(1234);
    std::string sessionId = item->GetDescriptor().sessionId_;
    SessionStack sessionStack;
    sessionStack.AddSession(1234, elementName.GetAbilityName(), item);
    OHOS::sptr<AVSessionItem> actual = sessionStack.RemoveSession(sessionId);

    EXPECT_NE(actual, nullptr);
    SLOGI("RemoveSession001 end!");
}