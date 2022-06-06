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
#include "avsession_info.h"
#include "avsession_log.h"
#include "avsession_errors.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

static char TestSessionTag[] = "test";
static char TestBundleName[] = "test.ohos.avsession";
static char TestAbilityName[] = "test.ability";

class AVSessionManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionManagerTest::SetUpTestCase()
{}

void AVSessionManagerTest::TearDownTestCase()
{}

void AVSessionManagerTest::SetUp()
{}

void AVSessionManagerTest::TearDown()
{}

class TestSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}d created", descriptor.sessionId_);
        descriptor_ = descriptor;
    }

    void OnSessionRelease(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}d released", descriptor.sessionId_);
        descriptor_ = descriptor;
    }

    void OnTopSessionChanged(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}d be top session", descriptor.sessionId_);
    }

    int32_t GetSessionId() const
    {
        return descriptor_.sessionId_;
    }

private:
    AVSessionDescriptor descriptor_;
};

/**
* @tc.name: CreatSession001
* @tc.desc: invalid params
* @tc.type: FUNC
* @tc.require: AR000H31JC
*/
HWTEST_F(AVSessionManagerTest, CreatSession001, TestSize.Level1)
{
    SLOGI("CreatSession001 begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(TestBundleName);
    elementName.SetAbilityName(TestAbilityName);
    auto session = AVSessionManager::CreateSession("", AVSession::SESSION_TYPE_AUDIO, elementName);
    EXPECT_EQ(session, nullptr);

    session = AVSessionManager::CreateSession(TestSessionTag, ERANGE, elementName);
    EXPECT_EQ(session, nullptr);

    elementName.SetBundleName("");
    elementName.SetAbilityName(TestAbilityName);
    session = AVSessionManager::CreateSession(TestSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    EXPECT_EQ(session, nullptr);

    elementName.SetBundleName(TestBundleName);
    elementName.SetAbilityName("");
    session = AVSessionManager::CreateSession(TestSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    EXPECT_EQ(session, nullptr);
    SLOGI("CreatSession001 end");
}

/**
* @tc.name: CreatSession002
* @tc.desc: Creat a new session
* @tc.type: FUNC
* @tc.require: AR000H31JC
*/
HWTEST_F(AVSessionManagerTest, CreatSession002, TestSize.Level1)
{
    SLOGI("CreatSession002 begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(TestBundleName);
    elementName.SetAbilityName(TestAbilityName);
    auto session = AVSessionManager::CreateSession(TestSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    EXPECT_NE(session, nullptr);
    if (session != nullptr) {
        session->Release();
    }
    SLOGI("CreatSession002 end");
}

/**
* @tc.name: CreatSession003
* @tc.desc: One process can create only one session
* @tc.type: FUNC
* @tc.require: AR000H31JC
*/
HWTEST_F(AVSessionManagerTest, CreatSession003, TestSize.Level1)
{
    SLOGI("CreatSession003 begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(TestBundleName);
    elementName.SetAbilityName(TestAbilityName);
    auto session1 = AVSessionManager::CreateSession(TestSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    EXPECT_NE(session1, nullptr);

    auto session2 = AVSessionManager::CreateSession(TestSessionTag, AVSession::SESSION_TYPE_VIDEO, elementName);
    EXPECT_EQ(session2, nullptr);

    if (session1 != nullptr) {
        session1->Release();
    }
    SLOGI("CreatSession003 end");
}

/**
* @tc.name: GetAllSessionDescriptors001
* @tc.desc: Get all session descriptors
* @tc.type: FUNC
* @tc.require: AR000H31JC
*/
HWTEST_F(AVSessionManagerTest, GetAllSessionDescriptors001, TestSize.Level1)
{
    SLOGI("GetAllSessionDescriptors001 begin");
    auto descriptors = AVSessionManager::GetAllSessionDescriptors();
    EXPECT_EQ(descriptors.size(), 0);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(TestBundleName);
    elementName.SetAbilityName(TestAbilityName);
    auto session = AVSessionManager::CreateSession(TestSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    EXPECT_NE(session, nullptr);

    descriptors = AVSessionManager::GetAllSessionDescriptors();
    EXPECT_EQ(descriptors.size(), 1);
    EXPECT_EQ(descriptors[0].sessionTag_, TestSessionTag);
    EXPECT_EQ(descriptors[0].sessionType_, AVSession::SESSION_TYPE_AUDIO);
    EXPECT_EQ(descriptors[0].elementName_.GetBundleName(), TestBundleName);
    EXPECT_EQ(descriptors[0].elementName_.GetAbilityName(), TestAbilityName);
    EXPECT_EQ(descriptors[0].isActive_, false);

    if (session != nullptr) {
        session->Release();
    }
    SLOGI("GetAllSessionDescriptors001 end");
}

/**
* @tc.name: CreateController001
* @tc.desc: create session controller by wrong sessionId.
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionManagerTest, CreateController001, TestSize.Level1)
{
    SLOGI("CreateController001 begin");
    auto controller = AVSessionManager::CreateController(100);
    EXPECT_EQ(controller, nullptr);
    SLOGI("CreateController001 end");
}

/**
* @tc.name: CreateController002
* @tc.desc: create session controller
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionManagerTest, CreateController002, TestSize.Level1)
{
    SLOGI("CreateController002 begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(TestBundleName);
    elementName.SetAbilityName(TestAbilityName);
    auto session = AVSessionManager::CreateSession(TestSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    EXPECT_NE(session, nullptr);
    ASSERT_GE(session->GetSessionId(), 0);

    auto controller = AVSessionManager::CreateController(session->GetSessionId());
    EXPECT_NE(controller, nullptr);

    if (session != nullptr) {
        session->Release();
    }
    if (controller != nullptr) {
        controller->Release();
    }
    SLOGI("CreateController002 end");
}

/**
* @tc.name: RegisterSessionListener001
* @tc.desc: register nullptr listener
* @tc.type: FUNC
* @tc.require: AR000H31JD
*/
HWTEST_F(AVSessionManagerTest, RegisterSessionListener001, TestSize.Level1)
{
    SLOGI("RegisterSessionListener001 begin");
    std::shared_ptr<SessionListener> listener;
    auto result = AVSessionManager::RegisterSessionListener(listener);
    EXPECT_NE(result, AVSESSION_SUCCESS);
    SLOGI("RegisterSessionListener001 end");
}

/**
* @tc.name: RegisterSessionListener002
* @tc.desc: register listener
* @tc.type: FUNC
* @tc.require: AR000H31JD
*/
HWTEST_F(AVSessionManagerTest, RegisterSessionListener002, TestSize.Level1)
{
    SLOGI("RegisterSessionListener002 begin");
    std::shared_ptr<TestSessionListener> listener = std::make_shared<TestSessionListener>();
    auto result = AVSessionManager::RegisterSessionListener(listener);
    EXPECT_EQ(result, AVSESSION_SUCCESS);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(TestBundleName);
    elementName.SetAbilityName(TestAbilityName);
    auto session = AVSessionManager::CreateSession(TestSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);
    ASSERT_GE(session->GetSessionId(), 0);
    sleep(1);
    EXPECT_EQ(session->GetSessionId(), listener->GetSessionId());

    if (session != nullptr) {
        session->Release();
    }
    SLOGI("RegisterSessionListener001 end");
}

/**
* @tc.name: RegisterServiceDeathCallback001
* @tc.desc: register service death listener
* @tc.type: FUNC
* @tc.require: AR000H31JB
*/
HWTEST_F(AVSessionManagerTest, RegisterServiceDeathCallback001, TestSize.Level1)
{
    SLOGI("RegisterServiceDeathCallback001 begin");
    bool isDead = false;
    auto result = AVSessionManager::RegisterServiceDeathCallback([&isDead]() { isDead = true; });
    EXPECT_EQ(result, AVSESSION_SUCCESS);

    system("killall -9 avsession_servi");
    sleep(1);
    EXPECT_EQ(isDead, true);
    SLOGI("RegisterServiceDeathCallback001 end");
}

/**
* @tc.name: UnregisterServiceDeathCallback001
* @tc.desc: unregister service death listener
* @tc.type: FUNC
* @tc.require: AR000H31JB
*/
HWTEST_F(AVSessionManagerTest, UnregisterServiceDeathCallback001, TestSize.Level1)
{
    SLOGI("UnregisterServiceDeathCallback001 begin");
    bool isDead = false;
    auto result = AVSessionManager::RegisterServiceDeathCallback([&isDead]() { isDead = true; });
    EXPECT_EQ(result, AVSESSION_SUCCESS);

    result = AVSessionManager::UnregisterServiceDeathCallback();
    EXPECT_EQ(result, AVSESSION_SUCCESS);

    system("killall -9 avsession_servi");
    sleep(1);
    EXPECT_EQ(isDead, false);
    SLOGI("UnregisterServiceDeathCallback001 end");
}

/**
* @tc.name: SendSystemMediaKeyEvent001
* @tc.desc: invalid keyEvent
* @tc.type: FUNC
* @tc.require: AR000H31JB
*/
HWTEST_F(AVSessionManagerTest, SendSystemMediaKeyEvent001, TestSize.Level1)
{
    SLOGI("SendSystemMediaKeyEvent001 begin");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    auto result = AVSessionManager::SendSystemAVKeyEvent(*keyEvent);
    EXPECT_NE(result, AVSESSION_SUCCESS);
    SLOGI("SendSystemMediaKeyEvent001 end");
}

/**
* @tc.name: SendSystemMediaKeyEvent002
* @tc.desc: valid keyEvent
* @tc.type: FUNC
* @tc.require: AR000H31JB
*/
HWTEST_F(AVSessionManagerTest, SendSystemMediaKeyEvent002, TestSize.Level1)
{
    SLOGI("SendSystemMediaKeyEvent002 begin");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_MEDIA_PLAY);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(1000);
    auto keyItem = OHOS::MMI::KeyEvent::KeyItem();
    keyItem.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_MEDIA_PLAY);
    keyItem.SetDownTime(1000);
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    auto result = AVSessionManager::SendSystemAVKeyEvent(*keyEvent);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGI("SendSystemMediaKeyEvent002 end");
}

/**
* @tc.name: SendSystemControlCommand001
* @tc.desc: invalid command
* @tc.type: FUNC
* @tc.require: AR000H31JB
*/
HWTEST_F(AVSessionManagerTest, SendSystemControlCommand001, TestSize.Level1)
{
    SLOGI("SendSystemControlCommand001 begin");
    AVControlCommand command;
    auto result = AVSessionManager::SendSystemControlCommand(command);
    EXPECT_NE(result, AVSESSION_SUCCESS);
    SLOGI("SendSystemControlCommand001 end");
}

/**
* @tc.name: SendSystemControlCommand002
* @tc.desc: valid command
* @tc.type: FUNC
* @tc.require: AR000H31JB
*/
HWTEST_F(AVSessionManagerTest, SendSystemControlCommand002, TestSize.Level1)
{
    SLOGI("SendSystemControlCommand002 begin");
    AVControlCommand command;
    command.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    auto result = AVSessionManager::SendSystemControlCommand(command);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGI("SendSystemControlCommand002 end");
}