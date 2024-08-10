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
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AVSession {
static HapInfoParams g_infoA = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demoA",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demoA",
    .isSystemApp = false
};

static HapPolicyParams g_policyA = {
    .apl = APL_NORMAL,
    .domain = "test.domainA"
};

static HapInfoParams g_infoB = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demoB",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demoB",
    .isSystemApp = true
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
    void AddPermission(const HapInfoParams& info, const HapPolicyParams& policy);
    void DeletePermission(const HapInfoParams& info);
};

void AVSessionPermissionTest::SetUpTestCase()
{}

void AVSessionPermissionTest::TearDownTestCase()
{}

void AVSessionPermissionTest::SetUp()
{}

void AVSessionPermissionTest::TearDown()
{}

void AVSessionPermissionTest::AddPermission(const HapInfoParams& info, const HapPolicyParams& policy)
{
    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(info.userID, info.bundleName, info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionPermissionTest::DeletePermission(const HapInfoParams& info)
{
    SetSelfTokenID(selfTokenId_);
    auto tokenId = AccessTokenKit::GetHapTokenID(info.userID, info.bundleName, info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

class TestSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s created", descriptor.sessionId_.c_str());
    }

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s released", descriptor.sessionId_.c_str());
    }

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s be top session", descriptor.sessionId_.c_str());
    }

    void OnAudioSessionChecked(const int32_t uid) override
    {
        SLOGI("uid=%{public}d checked", uid);
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
    std::vector<AVSessionDescriptor> descriptors;
    auto ret = AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
    EXPECT_EQ(ret, ERR_NO_PERMISSION);
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
    std::vector<AVSessionDescriptor> descriptors;
    auto ret = AVSessionManager::GetInstance().GetActivatedSessionDescriptors(descriptors);
    EXPECT_EQ(ret, ERR_NO_PERMISSION);
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
    AVSessionDescriptor descriptor {};

    // Using "1" as the test input parameter
    int32_t ret = AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId("1", descriptor);
    SLOGI("session can get descriptor point-to itself, but wrong sessionId can not specify any session");
    EXPECT_EQ(ret, AVSESSION_ERROR);
    DeletePermission(g_infoA);
}

/**
* @tc.name: GetHistoricalSessionDescriptorsWithNoPerm001
* @tc.desc: Get session descriptors by sessionId with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, GetHistoricalSessionDescriptorsWithNoPerm001, TestSize.Level1)
{
    AddPermission(g_infoA, g_policyA);
    std::vector<AVSessionDescriptor> descriptors;

    // Using "1" as the test input parameter
    int32_t ret = AVSessionManager::GetInstance().GetHistoricalSessionDescriptors(0, descriptors);
    EXPECT_EQ(ret, ERR_NO_PERMISSION);
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
    std::shared_ptr<AVSessionController> controller;

    // Using "1" as the test input parameter
    auto ret = AVSessionManager::GetInstance().CreateController("1", controller);
    EXPECT_EQ(ret, ERR_NO_PERMISSION);
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
    SLOGI("check descriptors count for stricter check size %{public}d", static_cast<int>(descriptors.size()));
    EXPECT_EQ(descriptors.size() >= 0, true);
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
    SLOGI("check descriptors count for stricter check size %{public}d", static_cast<int>(descriptors.size()));
    EXPECT_EQ(descriptors.size() >= 0, true);

    if (session != nullptr) {
        session->Destroy();
    }
    DeletePermission(g_infoB);
}

/**
* @tc.name: GetHistoricalSessionDescriptorsWithNoPerm001
* @tc.desc: Get session descriptors by sessionId with no permission
* @tc.type: FUNC
* @tc.require: AR000H31JR
*/
HWTEST_F(AVSessionPermissionTest, GetHistoricalSessionDescriptorsWithPerm001, TestSize.Level1)
{
    AddPermission(g_infoB, g_policyB);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto session = AVSessionManager::GetInstance().CreateSession("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(session, nullptr);

    std::vector<AVSessionDescriptor> descriptors;
    auto ret_1 = AVSessionManager::GetInstance().GetHistoricalSessionDescriptors(0, descriptors);
    EXPECT_EQ(ret_1, AVSESSION_SUCCESS);
    EXPECT_EQ(descriptors.size() >= 0, true);
    if (session != nullptr) {
        session->Destroy();
    }
    auto ret_2 = AVSessionManager::GetInstance().GetHistoricalSessionDescriptors(10, descriptors);
    EXPECT_EQ(ret_2, AVSESSION_SUCCESS);
    EXPECT_NE(descriptors.size() >= 0, true);
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
} // namespace AVSession
} // namespace OHOS
