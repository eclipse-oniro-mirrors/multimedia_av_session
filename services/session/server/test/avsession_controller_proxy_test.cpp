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
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "iservice_registry.h"
#include "avmedia_description.h"
#include "av_file_descriptor.h"
#include "system_ability_definition.h"
#include "avsession_controller_proxy.h"

using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;

static uint64_t g_selfTokenId = 0;
static HapInfoParams g_info = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demo",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demo",
    .isSystemApp = true
};

static HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .bundleName = "ohos.permission_test.demo",
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
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1}
        }
    }
};

class AVSessionControllerProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<AVSessionControllerProxy> aVSessionControllerProxyEmpty;
    OHOS::sptr<AVSessionControllerProxy> aVSessionControllerProxy;
};

void AVSessionControllerProxyTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionControllerProxyTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionControllerProxyTest::SetUp()
{
    OHOS::sptr<IRemoteObject> iRemoteObject;
    aVSessionControllerProxyEmpty = std::make_shared<AVSessionControllerProxy>(iRemoteObject);

    auto mgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGI("failed to get sa mgr");
        return;
    }
    auto object = mgr->GetSystemAbility(OHOS::AVSESSION_SERVICE_ID);
    if (object == nullptr) {
        SLOGI("failed to get service");
        return;
    }
    aVSessionControllerProxy = OHOS::iface_cast<AVSessionControllerProxy>(object);
}

void AVSessionControllerProxyTest::TearDown()
{
}

/**
 * @tc.name: GetAVCallState001
 * @tc.desc: Test GetAVCallState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVCallState001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVCallState001, start");
    AVCallState avCallState;
    int32_t ret = aVSessionControllerProxyEmpty->GetAVCallState(avCallState);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVCallState001, end");
}

/**
 * @tc.name: GetAVCallMetaData001
 * @tc.desc: Test GetAVCallMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVCallMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVCallMetaData001, start");
    AVCallMetaData avCallMetaData;
    int32_t ret = aVSessionControllerProxyEmpty->GetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVCallMetaData001, end");
}

/**
 * @tc.name: GetAVPlaybackState001
 * @tc.desc: Test GetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVPlaybackState001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVPlaybackState001, start");
    AVPlaybackState state;
    int32_t ret = aVSessionControllerProxyEmpty->GetAVPlaybackState(state);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVPlaybackState001, end");
}

/**
 * @tc.name: GetAVMetaData001
 * @tc.desc: Test GetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVMetaData001, start");
    AVMetaData data;
    int32_t ret = aVSessionControllerProxyEmpty->GetAVMetaData(data);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVMetaData001, end");
}

/**
 * @tc.name: SendAVKeyEvent001
 * @tc.desc: Test SendAVKeyEvent
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SendAVKeyEvent001, testing::ext::TestSize.Level1)
{
    SLOGI("SendAVKeyEvent001, start");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    int32_t ret = aVSessionControllerProxyEmpty->SendAVKeyEvent(*keyEvent);
    EXPECT_EQ(ret, ERR_COMMAND_NOT_SUPPORT);
    SLOGI("SendAVKeyEvent001, end");
}

/**
 * @tc.name: GetLaunchAbility001
 * @tc.desc: Test GetLaunchAbility
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetLaunchAbility001, testing::ext::TestSize.Level1)
{
    SLOGI("GetLaunchAbility001, start");
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    int32_t ret = aVSessionControllerProxyEmpty->GetLaunchAbility(ability);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetLaunchAbility001, end");
}

/**
 * @tc.name: GetValidCommands001
 * @tc.desc: Test GetValidCommands
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetValidCommands001, testing::ext::TestSize.Level1)
{
    SLOGI("GetValidCommands001, start");
    std::vector<int32_t> cmds = {0};
    int32_t ret = aVSessionControllerProxyEmpty->GetValidCommands(cmds);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetValidCommands001, end");
}

/**
 * @tc.name: IsSessionActive001
 * @tc.desc: Test IsSessionActive
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, IsSessionActive001, testing::ext::TestSize.Level1)
{
    SLOGI("IsSessionActive001, start");
    bool isActive = true;
    int32_t ret = aVSessionControllerProxyEmpty->IsSessionActive(isActive);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("IsSessionActive001, end");
}

/**
 * @tc.name: IsSessionActive002
 * @tc.desc: Test IsSessionActive
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, IsSessionActive002, testing::ext::TestSize.Level1)
{
    SLOGI("IsSessionActive002, start");
    bool isActive = false;
    int32_t ret = aVSessionControllerProxyEmpty->IsSessionActive(isActive);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("IsSessionActive002, end");
}

/**
 * @tc.name: SendControlCommand001
 * @tc.desc: Test SendControlCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SendControlCommand001, testing::ext::TestSize.Level1)
{
    SLOGI("SendControlCommand001, start");
    AVControlCommand cmd;
    int32_t ret = aVSessionControllerProxyEmpty->SendControlCommand(cmd);
    EXPECT_EQ(ret, ERR_COMMAND_NOT_SUPPORT);
    SLOGI("SendControlCommand001, end");
}

/**
 * @tc.name: SendCommonCommand001
 * @tc.desc: Test SendCommonCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SendCommonCommand001, testing::ext::TestSize.Level1)
{
    SLOGI("SendCommonCommand001, start");
    std::string commonCommand;
    OHOS::AAFwk::WantParams commandArgs;
    int32_t ret = aVSessionControllerProxyEmpty->SendCommonCommand(commonCommand, commandArgs);
    // return ERR_SERVICE_NOT_EXIST for remote not set
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SendCommonCommand001, end");
}

/**
 * @tc.name: RegisterCallback001
 * @tc.desc: Test RegisterCallback
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, RegisterCallback001, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterCallback001, start");
    std::shared_ptr<AVControllerCallback> callback;
    int32_t ret = aVSessionControllerProxyEmpty->RegisterCallback(callback);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("RegisterCallback001, end");
}

/**
 * @tc.name: SetAVCallMetaFilter001
 * @tc.desc: Test SetAVCallMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SetAVCallMetaFilter001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallMetaFilter001, start");
    AVCallMetaData::AVCallMetaMaskType filter;
    int32_t ret = aVSessionControllerProxyEmpty->SetAVCallMetaFilter(filter);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetAVCallMetaFilter001, end");
}

/**
 * @tc.name: SetAVCallStateFilter001
 * @tc.desc: Test SetAVCallStateFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SetAVCallStateFilter001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallStateFilter001, start");
    AVCallState::AVCallStateMaskType filter;
    int32_t ret = aVSessionControllerProxyEmpty->SetAVCallStateFilter(filter);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetAVCallStateFilter001, end");
}

/**
 * @tc.name: SetMetaFilter001
 * @tc.desc: Test SetMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SetMetaFilter001, testing::ext::TestSize.Level1)
{
    SLOGI("SetMetaFilter001, start");
    AVMetaData::MetaMaskType filter;
    int32_t ret = aVSessionControllerProxyEmpty->SetMetaFilter(filter);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetMetaFilter001, end");
}

/**
 * @tc.name: SetPlaybackFilter001
 * @tc.desc: Test SetPlaybackFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SetPlaybackFilter001, testing::ext::TestSize.Level1)
{
    SLOGI("SetPlaybackFilter001, start");
    AVPlaybackState::PlaybackStateMaskType filter;
    int32_t ret = aVSessionControllerProxyEmpty->SetPlaybackFilter(filter);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetPlaybackFilter001, end");
}

/**
 * @tc.name: GetAVQueueItems001
 * @tc.desc: Test GetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVQueueItems001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueItems001, start");
    std::vector<AVQueueItem> items = {};
    int32_t ret = aVSessionControllerProxyEmpty->GetAVQueueItems(items);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVQueueItems001, end");
}

/**
 * @tc.name: GetAVQueueTitle001
 * @tc.desc: Test GetAVQueueTitle
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVQueueTitle001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueTitle001, start");
    std::string title = "title";
    int32_t ret = aVSessionControllerProxyEmpty->GetAVQueueTitle(title);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVQueueTitle001, end");
}

/**
 * @tc.name: SkipToQueueItem001
 * @tc.desc: Test SkipToQueueItem
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SkipToQueueItem001, testing::ext::TestSize.Level1)
{
    SLOGI("SkipToQueueItem001, start");
    int32_t itemId = 0;
    int32_t ret = aVSessionControllerProxyEmpty->SkipToQueueItem(itemId);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SkipToQueueItem001, end");
}

/**
 * @tc.name: GetExtras001
 * @tc.desc: Test GetExtras
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetExtras001, testing::ext::TestSize.Level1)
{
    SLOGI("GetExtras001, start");
    OHOS::AAFwk::WantParams extras;
    int32_t ret = aVSessionControllerProxyEmpty->GetExtras(extras);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetExtras001, end");
}

/**
 * @tc.name: GetSessionId001
 * @tc.desc: Test GetSessionId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetSessionId001, testing::ext::TestSize.Level1)
{
    SLOGI("GetSessionId001, start");
    std::string id = aVSessionControllerProxyEmpty->GetSessionId();
    EXPECT_EQ(id, "");
    SLOGI("GetSessionId001, end");
}

/**
 * @tc.name: GetRealPlaybackPosition001
 * @tc.desc: Test GetRealPlaybackPosition
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetRealPlaybackPosition001, testing::ext::TestSize.Level1)
{
    SLOGI("GetRealPlaybackPosition001, start");
    int64_t ret = aVSessionControllerProxyEmpty->GetRealPlaybackPosition();
    EXPECT_EQ(ret, 0);
    SLOGI("GetRealPlaybackPosition001, end");
}

/**
 * @tc.name: IsDestroy001
 * @tc.desc: Test IsDestroy
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, IsDestroy001, testing::ext::TestSize.Level1)
{
    SLOGI("IsDestroy001, start");
    bool ret = aVSessionControllerProxy->IsDestroy();
    EXPECT_EQ(ret, false);
    SLOGI("IsDestroy001, end");
}

/**
 * @tc.name: Destroy001
 * @tc.desc: Test Destroy
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, Destroy001, testing::ext::TestSize.Level1)
{
    SLOGI("Destroy001, start");
    bool ret = aVSessionControllerProxy->Destroy();
    EXPECT_EQ(ret, true);
    SLOGI("Destroy001, end");
}

/**
 * @tc.name: IsDestroy002
 * @tc.desc: Test IsDestroy
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, IsDestroy002, testing::ext::TestSize.Level1)
{
    SLOGI("IsDestroy002, start");
    bool ret = aVSessionControllerProxy->IsDestroy();
    EXPECT_EQ(ret, false);
    SLOGI("IsDestroy002, end");
}

/**
 * @tc.name: GetAVCallState002
 * @tc.desc: Test GetAVCallState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVCallState002, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVCallState002, start");
    AVCallState avCallState;
    int32_t ret = aVSessionControllerProxy->GetAVCallState(avCallState);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetAVCallState002, end");
}

/**
 * @tc.name: GetAVCallMetaData002
 * @tc.desc: Test GetAVCallMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVCallMetaData002, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVCallMetaData002, start");
    AVCallMetaData avCallMetaData;
    int32_t ret = aVSessionControllerProxy->GetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetAVCallMetaData002, end");
}

/**
 * @tc.name: GetAVPlaybackState002
 * @tc.desc: Test GetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVPlaybackState002, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVPlaybackState002, start");
    AVPlaybackState state;
    int32_t ret = aVSessionControllerProxy->GetAVPlaybackState(state);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetAVPlaybackState002, end");
}

/**
 * @tc.name: GetAVMetaData002
 * @tc.desc: Test GetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVMetaData002, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVMetaData002, start");
    AVMetaData data;
    int32_t ret = aVSessionControllerProxy->GetAVMetaData(data);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetAVMetaData002, end");
}

/**
 * @tc.name: SendAVKeyEvent002
 * @tc.desc: Test SendAVKeyEvent
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SendAVKeyEvent002, testing::ext::TestSize.Level1)
{
    SLOGI("SendAVKeyEvent002, start");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    int32_t ret = aVSessionControllerProxy->SendAVKeyEvent(*keyEvent);
    EXPECT_EQ(ret, ERR_COMMAND_NOT_SUPPORT);
    SLOGI("SendAVKeyEvent002, end");
}

/**
 * @tc.name: GetLaunchAbility002
 * @tc.desc: Test GetLaunchAbility
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetLaunchAbility002, testing::ext::TestSize.Level1)
{
    SLOGI("GetLaunchAbility002, start");
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    int32_t ret = aVSessionControllerProxy->GetLaunchAbility(ability);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetLaunchAbility002, end");
}

/**
 * @tc.name: GetValidCommands002
 * @tc.desc: Test GetValidCommands
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetValidCommands002, testing::ext::TestSize.Level1)
{
    SLOGI("GetValidCommands002, start");
    std::vector<int32_t> cmds = {0};
    int32_t ret = aVSessionControllerProxy->GetValidCommands(cmds);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetValidCommands002, end");
}

/**
 * @tc.name: IsSessionActive003
 * @tc.desc: Test IsSessionActive
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, IsSessionActive003, testing::ext::TestSize.Level1)
{
    SLOGI("IsSessionActive003, start");
    bool isActive = true;
    int32_t ret = aVSessionControllerProxy->IsSessionActive(isActive);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("IsSessionActive003, end");
}

/**
 * @tc.name: IsSessionActive004
 * @tc.desc: Test IsSessionActive
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, IsSessionActive004, testing::ext::TestSize.Level1)
{
    SLOGI("IsSessionActive004, start");
    bool isActive = false;
    int32_t ret = aVSessionControllerProxy->IsSessionActive(isActive);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("IsSessionActive004, end");
}

/**
 * @tc.name: SendControlCommand002
 * @tc.desc: Test SendControlCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SendControlCommand002, testing::ext::TestSize.Level1)
{
    SLOGI("SendControlCommand002, start");
    AVControlCommand cmd;
    int32_t ret = aVSessionControllerProxy->SendControlCommand(cmd);
    EXPECT_EQ(ret, ERR_COMMAND_NOT_SUPPORT);
    SLOGI("SendControlCommand002, end");
}

/**
 * @tc.name: SendCommonCommand002
 * @tc.desc: Test SendCommonCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SendCommonCommand002, testing::ext::TestSize.Level1)
{
    SLOGI("SendCommonCommand002, start");
    std::string commonCommand;
    OHOS::AAFwk::WantParams commandArgs;
    int32_t ret = aVSessionControllerProxy->SendCommonCommand(commonCommand, commandArgs);
    // return ERR_IPC_SEND_REQUEST for ipc disable when controller not init
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("SendCommonCommand002, end");
}

/**
 * @tc.name: RegisterCallback002
 * @tc.desc: Test RegisterCallback
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, RegisterCallback002, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterCallback002, start");
    std::shared_ptr<AVControllerCallback> callback;
    int32_t ret = aVSessionControllerProxy->RegisterCallback(callback);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("RegisterCallback002, end");
}

/**
 * @tc.name: SetAVCallMetaFilter002
 * @tc.desc: Test SetAVCallMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SetAVCallMetaFilter002, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallMetaFilter002, start");
    AVCallMetaData::AVCallMetaMaskType filter;
    int32_t ret = aVSessionControllerProxy->SetAVCallMetaFilter(filter);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("SetAVCallMetaFilter002, end");
}

/**
 * @tc.name: SetAVCallStateFilter002
 * @tc.desc: Test SetAVCallStateFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SetAVCallStateFilter002, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallStateFilter002, start");
    AVCallState::AVCallStateMaskType filter;
    int32_t ret = aVSessionControllerProxy->SetAVCallStateFilter(filter);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("SetAVCallStateFilter002, end");
}

/**
 * @tc.name: SetMetaFilter002
 * @tc.desc: Test SetMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SetMetaFilter002, testing::ext::TestSize.Level1)
{
    SLOGI("SetMetaFilter002, start");
    AVMetaData::MetaMaskType filter;
    int32_t ret = aVSessionControllerProxy->SetMetaFilter(filter);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("SetMetaFilter002, end");
}

/**
 * @tc.name: SetPlaybackFilter002
 * @tc.desc: Test SetPlaybackFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SetPlaybackFilter002, testing::ext::TestSize.Level1)
{
    SLOGI("SetPlaybackFilter002, start");
    AVPlaybackState::PlaybackStateMaskType filter;
    int32_t ret = aVSessionControllerProxy->SetPlaybackFilter(filter);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("SetPlaybackFilter002, end");
}

/**
 * @tc.name: GetAVQueueItems002
 * @tc.desc: Test GetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVQueueItems002, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueItems002, start");
    std::vector<AVQueueItem> items = {};
    int32_t ret = aVSessionControllerProxy->GetAVQueueItems(items);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetAVQueueItems002, end");
}

/**
 * @tc.name: GetAVQueueTitle002
 * @tc.desc: Test GetAVQueueTitle
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetAVQueueTitle002, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueTitle002, start");
    std::string title = "title";
    int32_t ret = aVSessionControllerProxy->GetAVQueueTitle(title);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetAVQueueTitle002, end");
}

/**
 * @tc.name: SkipToQueueItem002
 * @tc.desc: Test SkipToQueueItem
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, SkipToQueueItem002, testing::ext::TestSize.Level1)
{
    SLOGI("SkipToQueueItem002, start");
    int32_t itemId = 0;
    int32_t ret = aVSessionControllerProxy->SkipToQueueItem(itemId);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("SkipToQueueItem002, end");
}

/**
 * @tc.name: GetExtras002
 * @tc.desc: Test GetExtras
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetExtras002, testing::ext::TestSize.Level1)
{
    SLOGI("GetExtras002, start");
    OHOS::AAFwk::WantParams extras;
    int32_t ret = aVSessionControllerProxy->GetExtras(extras);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetExtras002, end");
}

/**
 * @tc.name: GetSessionId002
 * @tc.desc: Test GetSessionId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetSessionId002, testing::ext::TestSize.Level1)
{
    SLOGI("GetSessionId002, start");
    std::string id = aVSessionControllerProxy->GetSessionId();
    EXPECT_EQ(id, "");
    SLOGI("GetSessionId002, end");
}

/**
 * @tc.name: GetRealPlaybackPosition002
 * @tc.desc: Test GetRealPlaybackPosition
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetRealPlaybackPosition002, testing::ext::TestSize.Level1)
{
    SLOGI("GetRealPlaybackPosition002, start");
    int64_t ret = aVSessionControllerProxy->GetRealPlaybackPosition();
    EXPECT_EQ(ret, 0);
    SLOGI("GetRealPlaybackPosition002, end");
}

/**
 * @tc.name: GetLaunchAbilityInner001
 * @tc.desc: Test GetLaunchAbilityInner
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerProxyTest, GetLaunchAbilityInner001, testing::ext::TestSize.Level1)
{
    SLOGI("GetLaunchAbilityInner001, start");
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    OHOS::AbilityRuntime::WantAgent::WantAgent * abilityPtr = &ability;
    int64_t ret = aVSessionControllerProxy->GetLaunchAbilityInner(abilityPtr);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetLaunchAbilityInner001, end");
}