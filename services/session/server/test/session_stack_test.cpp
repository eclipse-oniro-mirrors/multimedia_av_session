/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <utility>
#include "avsession_service.h"
#include "session_stack.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

namespace OHOS {
namespace AVSession {

class SessionStackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SessionStackTest::SetUpTestCase() {}
void SessionStackTest::TearDownTestCase() {}
void SessionStackTest::SetUp() {}
void SessionStackTest::TearDown() {}

/**
* @tc.name: RemoveSession001
* @tc.desc: verifying session stack remove session
* @tc.type: FUNC
*/
HWTEST_F(SessionStackTest, RemoveSession001, TestSize.Level1)
{
    AVSessionService* avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService_ != nullptr);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr <AVSessionItem> item =
        avSessionService_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);
    auto uid = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    item->SetPid(getpid());
    item->SetUid(uid);
    std::string sessionId = item->GetDescriptor().sessionId_;
    SessionStack sessionStack;
    sessionStack.AddSession(getpid(), elementName.GetAbilityName(), item);

    auto actual = sessionStack.RemoveSession("test");
    EXPECT_EQ(actual, nullptr);

    actual = sessionStack.RemoveSession(getpid(), "test");
    EXPECT_EQ(actual, nullptr);

    actual = sessionStack.RemoveSession(sessionId);
    EXPECT_NE(actual, nullptr);

    avSessionService_->HandleSessionRelease(sessionId);
}

/**
* @tc.name: RemoveSession002
* @tc.desc: verifying session stack remove session
* @tc.type: FUNC
*/
HWTEST_F(SessionStackTest, RemoveSession002, TestSize.Level1)
{
    AVSessionService* avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService_ != nullptr);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr <AVSessionItem> item =
        avSessionService_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);
    auto uid = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    item->SetPid(getpid());
    item->SetUid(uid);
    std::string sessionId = item->GetDescriptor().sessionId_;
    SessionStack sessionStack;
    sessionStack.AddSession(getpid(), elementName.GetAbilityName(), item);

    auto actual = sessionStack.RemoveSession(1);
    EXPECT_EQ(actual.size(), 0);

    actual = sessionStack.RemoveSession(getpid());
    EXPECT_NE(actual.size(), 0);

    avSessionService_->HandleSessionRelease(sessionId);
}

/**
* @tc.name: AddSession001
* @tc.desc: verifying session stack add session
* @tc.type: FUNC
*/
HWTEST_F(SessionStackTest, AddSession001, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName elementName;
    AVSessionService* avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService_ != nullptr);
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr <AVSessionItem> item =
        avSessionService_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);
    auto uid = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    item->SetPid(getpid());
    item->SetUid(uid);
    std::string sessionId = item->GetDescriptor().sessionId_;
    SessionStack sessionStack;
    for (auto i = 0; i < SessionContainer::SESSION_NUM_MAX; i++) {
        sessionStack.sessions_.insert(std::make_pair(std::make_pair(i, "test"), item));
    }
    auto ret = sessionStack.AddSession(getpid(), elementName.GetAbilityName(), item);
    EXPECT_EQ(ret, ERR_SESSION_EXCEED_MAX);

    avSessionService_->HandleSessionRelease(sessionId);
    sessionStack.sessions_.clear();
}

/**
* @tc.name: GetSession001
* @tc.desc: verifying session stack get session
* @tc.type: FUNC
*/
HWTEST_F(SessionStackTest, GetSession001, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName elementName;
    AVSessionService* avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService_ != nullptr);
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr <AVSessionItem> item =
        avSessionService_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);
    auto uid = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    item->SetPid(getpid());
    item->SetUid(uid);
    std::string sessionId = item->GetDescriptor().sessionId_;
    SessionStack sessionStack;
    auto ret = sessionStack.GetSession(getpid(), elementName.GetAbilityName());
    EXPECT_EQ(ret, nullptr);

    sessionStack.AddSession(getpid(), elementName.GetAbilityName(), item);

    ret = sessionStack.GetSession(getpid(), elementName.GetAbilityName());
    EXPECT_NE(ret, nullptr);

    avSessionService_->HandleSessionRelease(sessionId);
    sessionStack.sessions_.clear();
}

/**
* @tc.name: GetSessionById001
* @tc.desc: verifying session stack get session by id
* @tc.type: FUNC
*/
HWTEST_F(SessionStackTest, GetSessionById001, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName elementName;
    AVSessionService* avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService_ != nullptr);
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr <AVSessionItem> item =
        avSessionService_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);
    auto uid = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    item->SetPid(getpid());
    item->SetUid(uid);
    std::string sessionId = item->GetDescriptor().sessionId_;
    SessionStack sessionStack;
    sessionStack.AddSession(getpid(), elementName.GetAbilityName(), item);
    auto ret = sessionStack.GetSessionById("test");
    EXPECT_EQ(ret, nullptr);

    avSessionService_->HandleSessionRelease(sessionId);
    sessionStack.sessions_.clear();
}

/**
* @tc.name: UidHasSession001
* @tc.desc: verifying session stack UidHasSession
* @tc.type: FUNC
*/
HWTEST_F(SessionStackTest, UidHasSession001, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName elementName;
    AVSessionService* avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService_ != nullptr);
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr <AVSessionItem> item =
        avSessionService_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);
    auto uid = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    item->SetPid(getpid());
    item->SetUid(uid);
    std::string sessionId = item->GetDescriptor().sessionId_;
    SessionStack sessionStack;
    sessionStack.AddSession(getpid(), elementName.GetAbilityName(), item);
    auto ret = sessionStack.UidHasSession(-1);
    EXPECT_EQ(ret, false);
    ret = sessionStack.UidHasSession(uid);
    EXPECT_EQ(ret, true);

    avSessionService_->HandleSessionRelease(sessionId);
    sessionStack.sessions_.clear();
}

/**
* @tc.name: GetSessionByUid001
* @tc.desc: verifying session stack get session by uid
* @tc.type: FUNC
*/
HWTEST_F(SessionStackTest, GetSessionByUid001, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName elementName;
    AVSessionService* avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(avSessionService_ != nullptr);
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    OHOS::sptr <AVSessionItem> item =
        avSessionService_->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, false, elementName);
    ASSERT_TRUE(item != nullptr);
    auto uid = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    item->SetPid(getpid());
    item->SetUid(uid);
    std::string sessionId = item->GetDescriptor().sessionId_;
    SessionStack sessionStack;
    sessionStack.AddSession(getpid(), elementName.GetAbilityName(), item);
    auto ret = sessionStack.GetSessionByUid(-1);
    EXPECT_EQ(ret, nullptr);

    avSessionService_->HandleSessionRelease(sessionId);
    sessionStack.sessions_.clear();
}
} //AVSession
} //OHOS