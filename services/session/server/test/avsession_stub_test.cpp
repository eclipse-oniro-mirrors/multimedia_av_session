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
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"

#define private public
#define protected public
#include "avsession_stub.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AVSession;

static int32_t MAX_IMAGE_SIZE = 10 * 1024 * 1024;
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

class AVSessionStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionStubTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionStubTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionStubTest::SetUp()
{
}

void AVSessionStubTest::TearDown()
{
}

class AVSessionStubDemo : public AVSessionStub {
public:
    std::string GetSessionId() override { return ""; };
    std::string GetSessionType() override { return ""; };
    int32_t GetAVMetaData(AVMetaData &meta) override { return 0; };
    int32_t SetAVMetaData(const AVMetaData &meta) override { return 0; };
    int32_t SetAVCallMetaData(const AVCallMetaData &meta) override { return 0; };
    int32_t SetAVCallState(const AVCallState &avCallState) override { return 0; };
    int32_t GetAVPlaybackState(AVPlaybackState &state) override { return 0; };
    int32_t SetAVPlaybackState(const AVPlaybackState &state) override { return 0; };
    int32_t GetAVQueueItems(std::vector<AVQueueItem> &items) override { return 0; };
    int32_t SetAVQueueItems(const std::vector<AVQueueItem> &items) override { return 0; };
    int32_t GetAVQueueTitle(std::string &title) override { return 0; };
    int32_t SetAVQueueTitle(const std::string &title) override { return 0; };
    int32_t SetLaunchAbility(const OHOS::AbilityRuntime::WantAgent::WantAgent &ability) override { return 0; };
    int32_t GetExtras(OHOS::AAFwk::WantParams &extras) override { return 0; };
    int32_t SetExtras(const OHOS::AAFwk::WantParams &extras) override { return 0; };
    std::shared_ptr<AVSessionController> GetController() override { return nullptr; };
    int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback> &callback) override { return 0; };
    int32_t Activate() override { return 0; };
    int32_t Deactivate() override { return 0; };
    bool IsActive() override { return true; };
    int32_t Destroy() override { return 0; };
    int32_t AddSupportCommand(const int32_t cmd) override { return 0; };
    int32_t DeleteSupportCommand(const int32_t cmd) override { return 0; };
    int32_t SetSessionEvent(const std::string &event, const OHOS::AAFwk::WantParams &args) override { return 0; };

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> GetAVCastController() override { return nullptr; };
    int32_t ReleaseCast(bool continuePlay = false) override { return 0; };
    int32_t StartCastDisplayListener() override { return 0; };
    int32_t StopCastDisplayListener() override { return 0; };
    int32_t GetAllCastDisplays(std::vector<CastDisplayInfo> &castDisplays) override { return 0; };
#endif

protected:
    int32_t RegisterCallbackInner(const OHOS::sptr<IAVSessionCallback> &callback) override { return 0; };
    OHOS::sptr<IRemoteObject> GetControllerInner() override { return nullptr; };

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::sptr<IRemoteObject> GetAVCastControllerInner() override { return nullptr; };
#endif
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, OnRemoteRequest001, TestSize.Level1)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = 0;
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("OnRemoteRequest001 end!");
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, OnRemoteRequest002, TestSize.Level1)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = 25;
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("OnRemoteRequest002 end!");
}

/**
 * @tc.name: HandleRegisterCallbackInner001
 * @tc.desc: Test HandleRegisterCallbackInner
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleRegisterCallbackInner001, TestSize.Level1)
{
    SLOGI("HandleRegisterCallbackInner001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleRegisterCallbackInner(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleRegisterCallbackInner001 end!");
}

/**
 * @tc.name: HandleSetAVCallMetaData001
 * @tc.desc: Test HandleSetAVCallMetaData
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetAVCallMetaData001, TestSize.Level1)
{
    SLOGI("HandleSetAVCallMetaData001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetAVCallMetaData(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetAVCallMetaData001 end!");
}

/**
 * @tc.name: HandleSetAVCallState001
 * @tc.desc: Test HandleSetAVCallState
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetAVCallState001, TestSize.Level1)
{
    SLOGI("HandleSetAVCallState001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetAVCallState(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetAVCallState001 end!");
}

/**
 * @tc.name: HandleSetAVPlaybackState001
 * @tc.desc: Test HandleSetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetAVPlaybackState001, TestSize.Level1)
{
    SLOGI("HandleSetAVPlaybackState001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetAVPlaybackState(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetAVPlaybackState001 end!");
}

/**
 * @tc.name: HandleSetLaunchAbility001
 * @tc.desc: Test HandleSetLaunchAbility
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetLaunchAbility001, TestSize.Level1)
{
    SLOGI("HandleSetLaunchAbility001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetLaunchAbility(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetLaunchAbility001 end!");
}

/**
 * @tc.name: HandleSetAVQueueItems001
 * @tc.desc: Test HandleSetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetAVQueueItems001, TestSize.Level1)
{
    SLOGI("HandleSetAVQueueItems001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetAVQueueItems(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetAVQueueItems001 end!");
}

/**
 * @tc.name: HandleSetExtras001
 * @tc.desc: Test HandleSetExtras
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetExtras001, TestSize.Level1)
{
    SLOGI("HandleSetExtras001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetExtras(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetExtras001 end!");
}

/**
 * @tc.name: HandleSetSessionEvent001
 * @tc.desc: Test HandleSetSessionEvent
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetSessionEvent001, TestSize.Level1)
{
    SLOGI("HandleSetSessionEvent001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetSessionEvent(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetSessionEvent001 end!");
}

/**
 * @tc.name: HandleGetController001
 * @tc.desc: Test HandleGetController
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleGetController001, TestSize.Level1)
{
    SLOGI("HandleGetController001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleGetController(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleGetController001 end!");
}

/**
 * @tc.name: HandleGetAVMetaData001
 * @tc.desc: Test HandleGetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleGetAVMetaData001, TestSize.Level1)
{
    SLOGI("HandleGetAVMetaData001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleGetAVMetaData(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleGetAVMetaData001 end!");
}

/**
 * @tc.name: HandleSetAVMetaData001
 * @tc.desc: Test HandleSetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetAVMetaData001, TestSize.Level1)
{
    SLOGI("HandleSetAVMetaData001 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSession::GetDescriptor());
    data.WriteInt32(-1);
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetAVMetaData(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetAVMetaData001 end!");
}

/**
 * @tc.name: HandleSetAVMetaData002
 * @tc.desc: Test HandleSetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetAVMetaData002, TestSize.Level1)
{
    SLOGI("HandleSetAVMetaData002 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSession::GetDescriptor());
    data.WriteInt32(MAX_IMAGE_SIZE + 1);
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetAVMetaData(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetAVMetaData002 end!");
}

/**
 * @tc.name: HandleSetAVMetaData003
 * @tc.desc: Test HandleSetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST(AVSessionStubTest, HandleSetAVMetaData003, TestSize.Level1)
{
    SLOGI("HandleSetAVMetaData003 begin!");
    AVSessionStubDemo avSessionStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSession::GetDescriptor());
    data.WriteInt32(MAX_IMAGE_SIZE - 1);
    OHOS::MessageParcel reply;
    int ret = avSessionStub.HandleSetAVMetaData(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("HandleSetAVMetaData003 end!");
}