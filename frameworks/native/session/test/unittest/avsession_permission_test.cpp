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

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;

static HapInfoParams g_infoA = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demoA",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demoA"
};

static HapPolicyParams g_policyA = {
    .apl = APL_NORMAL,
    .domain = "test.domainA"
};

static HapInfoParams g_infoB = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demoB",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demoB"
};

static HapPolicyParams g_policyB = {
    .apl = APL_NORMAL,
    .domain = "test.domainB",
    .permList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .bundleName = "ohos.permission_test.demoB",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

class AVSessionPermissionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    uint64_t selfTokenId_ = 0;
    void AddPermission(const HapInfoParams &info, const HapPolicyParams &policy);
    void DeletePermission(const HapInfoParams &info);
};

void AVSessionPermissionTest::SetUpTestCase()
{}

void AVSessionPermissionTest::TearDownTestCase()
{}

void AVSessionPermissionTest::SetUp()
{}

void AVSessionPermissionTest::TearDown()
{}

void AVSessionPermissionTest::AddPermission(const HapInfoParams &info, const HapPolicyParams &policy)
{
    selfTokenId_ = GetSelfTokenID();
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(info, policy);
    SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID);
    SLOGI("selfTokenId_:%{public}" PRId64, selfTokenId_);
    SLOGI("GetSelfTokenID:%{public}" PRId64, GetSelfTokenID());
}

void AVSessionPermissionTest::DeletePermission(const HapInfoParams &info)
{
    SetSelfTokenID(selfTokenId_);
    auto tokenId = AccessTokenKit::GetHapTokenID(info.userID, info.bundleName, info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

class TestSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}s created", descriptor.sessionId_.c_str());
    }

    void OnSessionRelease(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}s released", descriptor.sessionId_.c_str());
    }

    void OnTopSessionChange(const AVSessionDescriptor &descriptor) override
    {
        SLOGI("sessionId=%{public}s be top session", descriptor.sessionId_.c_str());
    }
};

/**
* @tc.name: GetAllSessionDescriptorsWithNoPerm001
* @tc.desc: Get all session descriptors with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JQ
*/
HWTEST_F(AVSessionPermissionTest, GetAllSessionDescriptorsWithNoPerm001, TestSize.Level1)
{
    AddPermission(g_infoA, g_policyA);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto session = AVSessionManager::GetInstance().CreateSession("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);

    std::vector<AVSessionDescriptor> descriptors;
    auto ret = AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
    EXPECT_EQ(ret, ERR_NO_PERMISSION);
    if (session != nullptr) {
        session->Destroy();
    }
    DeletePermission(g_infoA);
}

/**
* @tc.name: GetActivatedSessionDescriptorsWithNoPerm001
* @tc.desc: Get all activated session descriptors with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, GetActivatedSessionDescriptorsWithNoPerm001, TestSize.Level1)
{
    AddPermission(g_infoA, g_policyA);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto session = AVSessionManager::GetInstance().CreateSession("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);
    session->Activate();

    std::vector<AVSessionDescriptor> descriptors;
    auto ret = AVSessionManager::GetInstance().GetActivatedSessionDescriptors(descriptors);
    EXPECT_EQ(ret, ERR_NO_PERMISSION);

    if (session != nullptr) {
        session->Destroy();
    }
    DeletePermission(g_infoA);
}

/**
* @tc.name: GetSessionDescriptorsBySessionIdWithNoPerm001
* @tc.desc: Get session descriptors by sessionId with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, GetSessionDescriptorsBySessionIdWithNoPerm001, TestSize.Level1)
{
    AddPermission(g_infoA, g_policyA);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto session = AVSessionManager::GetInstance().CreateSession("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);
    session->Activate();
    auto sessionId = session->GetSessionId();
    AVSessionDescriptor descriptor {};
    int32_t ret = AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(sessionId, descriptor);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(descriptor.sessionTag_, "test");
    EXPECT_EQ(descriptor.sessionType_, AVSession::SESSION_TYPE_AUDIO);
    EXPECT_EQ(descriptor.elementName_.GetBundleName(), "test.ohos.avsession");
    EXPECT_EQ(descriptor.elementName_.GetAbilityName(), "test.ability");
    EXPECT_EQ(descriptor.isActive_, true);
    if (session != nullptr) {
        session->Destroy();
    }
    DeletePermission(g_infoA);
}

/**
* @tc.name: CreateControllerWithNoPerm001
* @tc.desc: create session controller with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, CreateControllerWithNoPerm001, TestSize.Level1)
{
    AddPermission(g_infoA, g_policyA);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto session = AVSessionManager::GetInstance().CreateSession("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);

    std::shared_ptr<AVSessionController> controller;
    auto ret = AVSessionManager::GetInstance().CreateController(session->GetSessionId(), controller);
    EXPECT_EQ(ret, ERR_NO_PERMISSION);
    if (session != nullptr) {
        session->Destroy();
    }
    DeletePermission(g_infoA);
}

/**
* @tc.name: RegisterSessionListenerWithNoPerm001
* @tc.desc: register listener with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JQ
*/
HWTEST_F(AVSessionPermissionTest, RegisterSessionListenerWithNoPerm001, TestSize.Level1)
{
    AddPermission(g_infoA, g_policyA);
    std::shared_ptr<TestSessionListener> listener = std::make_shared<TestSessionListener>();
    auto result = AVSessionManager::GetInstance().RegisterSessionListener(listener);
    EXPECT_EQ(result, ERR_NO_PERMISSION);
    DeletePermission(g_infoA);
}

/**
* @tc.name: SendSystemMediaKeyEventWithNoPerm001
* @tc.desc: valid keyEvent with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, SendSystemMediaKeyEventWithNoPerm001, TestSize.Level1)
{
    AddPermission(g_infoA, g_policyA);
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

    auto result = AVSessionManager::GetInstance().SendSystemAVKeyEvent(*keyEvent);
    EXPECT_EQ(result, ERR_NO_PERMISSION);
    DeletePermission(g_infoA);
}

/**
* @tc.name: SendSystemControlCommandWithNoPerm001
* @tc.desc: valid command with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, SendSystemControlCommandWithNoPerm001, TestSize.Level1)
{
    AddPermission(g_infoA, g_policyA);
    AVControlCommand command;
    command.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    auto result = AVSessionManager::GetInstance().SendSystemControlCommand(command);
    EXPECT_EQ(result, ERR_NO_PERMISSION);
    DeletePermission(g_infoA);
}

/**
* @tc.name: GetAllSessionDescriptorsWithPerm001
* @tc.desc: Get all session descriptors with permission
* @tc.type: FUNC
* @tc.require: AR000H31JQ
*/
HWTEST_F(AVSessionPermissionTest, GetAllSessionDescriptorsWithPerm001, TestSize.Level1)
{
    AddPermission(g_infoB, g_policyB);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto session = AVSessionManager::GetInstance().CreateSession("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);

    std::vector<AVSessionDescriptor> descriptors;
    auto ret = AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(descriptors.size(), 1);
    if (session != nullptr) {
        session->Destroy();
    }
    DeletePermission(g_infoB);
}

/**
* @tc.name: GetActivatedSessionDescriptorsWithPerm001
* @tc.desc: Get all activated session descriptors with permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, GetActivatedSessionDescriptorsWithPerm001, TestSize.Level1)
{
    AddPermission(g_infoB, g_policyB);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto session = AVSessionManager::GetInstance().CreateSession("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);
    session->Activate();

    std::vector<AVSessionDescriptor> descriptors;
    auto ret = AVSessionManager::GetInstance().GetActivatedSessionDescriptors(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(descriptors.size(), 1);

    if (session != nullptr) {
        session->Destroy();
    }
    DeletePermission(g_infoB);
}

/**
* @tc.name: CreateControllerWithPerm001
* @tc.desc: create session controller with permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, CreateControllerWithPerm001, TestSize.Level1)
{
    AddPermission(g_infoB, g_policyB);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto session = AVSessionManager::GetInstance().CreateSession("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);

    std::shared_ptr<AVSessionController> controller;
    auto ret = AVSessionManager::GetInstance().CreateController(session->GetSessionId(), controller);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_NE(controller, nullptr);
    if (session != nullptr) {
        session->Destroy();
    }
    DeletePermission(g_infoB);
}

/**
* @tc.name: RegisterSessionListenerWithPerm001
* @tc.desc: register listener with permission
* @tc.type: FUNC
* @tc.require: AR000H31JQ
*/
HWTEST_F(AVSessionPermissionTest, RegisterSessionListenerWithPerm001, TestSize.Level1)
{
    AddPermission(g_infoB, g_policyB);
    std::shared_ptr<TestSessionListener> listener = std::make_shared<TestSessionListener>();
    auto result = AVSessionManager::GetInstance().RegisterSessionListener(listener);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    DeletePermission(g_infoB);
}

/**
* @tc.name: SendSystemMediaKeyEventWithPerm001
* @tc.desc: valid keyEvent with permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, SendSystemMediaKeyEventWithPerm001, TestSize.Level1)
{
    AddPermission(g_infoB, g_policyB);
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

    auto result = AVSessionManager::GetInstance().SendSystemAVKeyEvent(*keyEvent);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    DeletePermission(g_infoB);
}

/**
* @tc.name: SendSystemControlCommandWithPerm001
* @tc.desc: valid command with permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, SendSystemControlCommandWithPerm001, TestSize.Level1)
{
    AddPermission(g_infoB, g_policyB);
    AVControlCommand command;
    command.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    auto result = AVSessionManager::GetInstance().SendSystemControlCommand(command);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    DeletePermission(g_infoB);
}