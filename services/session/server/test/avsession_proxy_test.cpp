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

#define private public
#define protected public
#include "avsession_proxy.h"
#undef protected
#undef private

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
class AVSessionProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<AVSessionProxy> aVSessionProxy;
    OHOS::sptr<AVSessionProxy> aVSessionProxySys;
};

void AVSessionProxyTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionProxyTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionProxyTest::SetUp()
{
    OHOS::sptr<IRemoteObject> iRemoteObject;
    aVSessionProxy = std::make_shared<AVSessionProxy>(iRemoteObject);

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
    aVSessionProxySys = OHOS::iface_cast<AVSessionProxy>(object);
}

void AVSessionProxyTest::TearDown()
{
}

static const int32_t DURATION_TIME = 40000;
OHOS::AVSession::AVMetaData GetAVMetaData()
{
    OHOS::AVSession::AVMetaData g_metaData;
    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(DURATION_TIME);
    g_metaData.SetMediaImageUri("xxxxx");
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("xxxxx");
    return g_metaData;
}

/**
 * @tc.name: GetSessionId001
 * @tc.desc: Test GetSessionId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetSessionId001, testing::ext::TestSize.Level1)
{
    SLOGI("GetSessionId001, start");
    std::string id = aVSessionProxy->GetSessionId();
    EXPECT_EQ(id, "");
    SLOGI("GetSessionId001, end");
}

/**
 * @tc.name: GetSessionType001
 * @tc.desc: Test GetSessionType
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetSessionType001, testing::ext::TestSize.Level1)
{
    SLOGI("GetSessionType001, start");
    std::string type = aVSessionProxy->GetSessionType();
    EXPECT_EQ(type, "");
    SLOGI("GetSessionType001, end");
}

/**
 * @tc.name: SetAVCallMetaData001
 * @tc.desc: Test SetAVCallMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVCallMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallMetaData001, start");
    AVCallMetaData avCallMetaData;
    int32_t ret = aVSessionProxy->SetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("SetAVCallMetaData001, end");
}

/**
 * @tc.name: SetAVCallMetaData002
 * @tc.desc: Test SetAVCallMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVCallMetaData002, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallMetaData002, start");
    AVCallMetaData avCallMetaData;
    avCallMetaData.SetName("name");
    avCallMetaData.SetPhoneNumber("number");
    int32_t ret = aVSessionProxy->SetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetAVCallMetaData002, end");
}

/**
 * @tc.name: SetAVCallState001
 * @tc.desc: Test SetAVCallState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVCallState001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallState001, start");
    AVCallState avCallState;
    int32_t ret = aVSessionProxy->SetAVCallState(avCallState);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetAVCallState001, end");
}

/**
 * @tc.name: SetAVCallState002
 * @tc.desc: Test SetAVCallState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVCallState002, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVCallState002, start");
    AVCallState avCallState;
    avCallState.SetAVCallState(-1);
    int32_t ret = aVSessionProxy->SetAVCallState(avCallState);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("SetAVCallState002, end");
}

/**
 * @tc.name: SetAVMetaData001
 * @tc.desc: Test SetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVMetaData001, start");
    AVMetaData meta;
    int32_t ret = aVSessionProxy->SetAVMetaData(meta);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetAVMetaData001, end");
}

/**
 * @tc.name: SetAVMetaData002
 * @tc.desc: Test SetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVMetaData002, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVMetaData002, start");
    AVMetaData meta;
    int32_t ret = aVSessionProxySys->SetAVMetaData(meta);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetAVMetaData002, end");
}

/**
 * @tc.name: SetAVMetaData003
 * @tc.desc: Test SetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVMetaData003, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVMetaData003, start");
    AVMetaData meta = GetAVMetaData();
    int32_t ret = aVSessionProxySys->SetAVMetaData(meta);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("SetAVMetaData003, end");
}

/**
 * @tc.name: GetPixelMapBuffer001
 * @tc.desc: Test GetPixelMapBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetPixelMapBuffer001, testing::ext::TestSize.Level1)
{
    SLOGI("GetPixelMapBuffer001, start");
    OHOS::AVSession::AVMetaData metaData;
    OHOS::MessageParcel parcel;
    int32_t ret = aVSessionProxySys->GetPixelMapBuffer(metaData, parcel);
    EXPECT_EQ(ret, 0);
    SLOGI("GetPixelMapBuffer001, end");
}

/**
 * @tc.name: GetPixelMapBuffer002
 * @tc.desc: Test GetPixelMapBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetPixelMapBuffer002, testing::ext::TestSize.Level1)
{
    SLOGI("GetPixelMapBuffer002, start");
    OHOS::AVSession::AVMetaData metaData = GetAVMetaData();
    OHOS::MessageParcel parcel;
    int32_t ret = aVSessionProxySys->GetPixelMapBuffer(metaData, parcel);
    EXPECT_EQ(ret, 0);
    SLOGI("GetPixelMapBuffer002, end");
}

/**
 * @tc.name: GetAVMetaData001
 * @tc.desc: Test GetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVMetaData001, start");
    AVMetaData meta;
    int32_t ret = aVSessionProxy->GetAVMetaData(meta);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVMetaData001, end");
}

/**
 * @tc.name: GetAVPlaybackState001
 * @tc.desc: Test GetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVPlaybackState001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVPlaybackState001, start");
    AVPlaybackState state;
    int32_t ret = aVSessionProxy->GetAVPlaybackState(state);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVPlaybackState001, end");
}

/**
 * @tc.name: SetAVPlaybackState001
 * @tc.desc: Test SetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVPlaybackState001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVPlaybackState001, start");
    AVPlaybackState state;
    int32_t ret = aVSessionProxy->SetAVPlaybackState(state);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetAVPlaybackState001, end");
}

/**
 * @tc.name: GetAVQueueItems001
 * @tc.desc: Test GetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVQueueItems001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueItems001, start");
    std::vector<AVQueueItem> items = {};
    int32_t ret = aVSessionProxy->GetAVQueueItems(items);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVQueueItems001, end");
}

/**
 * @tc.name: SetAVQueueItems001
 * @tc.desc: Test SetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVQueueItems001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVQueueItems001, start");
    std::vector<AVQueueItem> items = {};
    int32_t ret = aVSessionProxy->SetAVQueueItems(items);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetAVQueueItems001, end");
}

/**
 * @tc.name: GetAVQueueTitle001
 * @tc.desc: Test GetAVQueueTitle
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetAVQueueTitle001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAVQueueTitle001, start");
    std::string title;
    int32_t ret = aVSessionProxy->GetAVQueueTitle(title);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetAVQueueTitle001, end");
}

/**
 * @tc.name: SetAVQueueTitle001
 * @tc.desc: Test SetAVQueueTitle
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetAVQueueTitle001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVQueueTitle001, start");
    std::string title = "title";
    int32_t ret = aVSessionProxy->SetAVQueueTitle(title);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetAVQueueTitle001, end");
}

/**
 * @tc.name: SetLaunchAbility001
 * @tc.desc: Test SetLaunchAbility
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetLaunchAbility001, testing::ext::TestSize.Level1)
{
    SLOGI("SetLaunchAbility001, start");
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    int32_t ret = aVSessionProxy->SetLaunchAbility(ability);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetLaunchAbility001, end");
}

/**
 * @tc.name: GetExtras001
 * @tc.desc: Test GetExtras
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetExtras001, testing::ext::TestSize.Level1)
{
    SLOGI("GetExtras001, start");
    OHOS::AAFwk::WantParams extras;
    int32_t ret = aVSessionProxy->GetExtras(extras);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("GetExtras001, end");
}

/**
 * @tc.name: SetExtras001
 * @tc.desc: Test SetExtras
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetExtras001, testing::ext::TestSize.Level1)
{
    SLOGI("SetExtras001, start");
    OHOS::AAFwk::WantParams extras;
    int32_t ret = aVSessionProxy->SetExtras(extras);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetExtras001, end");
}

/**
 * @tc.name: GetController001
 * @tc.desc: Test GetController
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, GetController001, testing::ext::TestSize.Level1)
{
    SLOGI("GetController001, start");
    std::shared_ptr<AVSessionController> ret = aVSessionProxy->GetController();
    SLOGI("GetController001, end");
}

/**
 * @tc.name: RegisterCallback001
 * @tc.desc: Test RegisterCallback
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, RegisterCallback001, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterCallback001, start");
    std::shared_ptr<AVSessionCallback> callback;
    int32_t ret = aVSessionProxy->RegisterCallback(callback);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("RegisterCallback001, end");
}

/**
 * @tc.name: Activate001
 * @tc.desc: Test Activate
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, Activate001, testing::ext::TestSize.Level1)
{
    SLOGI("Activate001, start");
    int32_t ret = aVSessionProxy->Activate();
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("Activate001, end");
}

/**
 * @tc.name: IsActive001
 * @tc.desc: Test IsActive
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, IsActive001, testing::ext::TestSize.Level1)
{
    SLOGI("IsActive001, start");
    bool ret = aVSessionProxy->IsActive();
    EXPECT_EQ(ret, true);
    SLOGI("IsActive001, end");
}

/**
 * @tc.name: Deactivate001
 * @tc.desc: Test Deactivate
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, Deactivate001, testing::ext::TestSize.Level1)
{
    SLOGI("Deactivate001, start");
    int32_t ret = aVSessionProxy->Deactivate();
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("Deactivate001, end");
}

/**
 * @tc.name: AddSupportCommand001
 * @tc.desc: Test AddSupportCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, AddSupportCommand001, testing::ext::TestSize.Level1)
{
    SLOGI("AddSupportCommand001, start");
    int32_t cmd = 0;
    int32_t ret = aVSessionProxy->AddSupportCommand(cmd);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("AddSupportCommand001, end");
}

/**
 * @tc.name: DeleteSupportCommand001
 * @tc.desc: Test DeleteSupportCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, DeleteSupportCommand001, testing::ext::TestSize.Level1)
{
    SLOGI("DeleteSupportCommand001, start");
    int32_t cmd = 0;
    int32_t ret = aVSessionProxy->DeleteSupportCommand(cmd);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("DeleteSupportCommand001, end");
}

/**
 * @tc.name: SetSessionEvent001
 * @tc.desc: Test SetSessionEvent
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, SetSessionEvent001, testing::ext::TestSize.Level1)
{
    SLOGI("SetSessionEvent001, start");
    std::string event;
    OHOS::AAFwk::WantParams args;
    int32_t ret = aVSessionProxy->SetSessionEvent(event, args);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("SetSessionEvent001, end");
}

/**
 * @tc.name: Destroy001
 * @tc.desc: Test Destroy
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, Destroy001, testing::ext::TestSize.Level1)
{
    SLOGI("Destroy001, start");
    int32_t ret = aVSessionProxy->Destroy();
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("Destroy001, end");
}

/**
 * @tc.name: RegisterCallback002
 * @tc.desc: Test RegisterCallback
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionProxyTest, RegisterCallback002, testing::ext::TestSize.Level1)
{
    SLOGI("RegisterCallback002, start");
    std::shared_ptr<AVSessionCallback> callback;
    int32_t ret = aVSessionProxy->RegisterCallback(callback);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("RegisterCallback002, end");
}