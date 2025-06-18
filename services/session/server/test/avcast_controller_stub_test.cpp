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
#include "accesstoken_kit.h"
#include "avcast_controller_stub.h"
#include "avsession_service.h"
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AVSession {

static std::shared_ptr<AVSessionService> g_AVSessionService;
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

class AVCastControllerStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVCastControllerStubTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);

    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
}

void AVCastControllerStubTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVCastControllerStubTest::SetUp()
{}

void AVCastControllerStubTest::TearDown()
{}

class AVCastControllerStubDemo : public AVCastControllerStub {
public:
    int32_t SendControlCommand(const AVCastControlCommand& cmd) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t Start(const AVQueueItem& avQueueItem) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t Prepare(const AVQueueItem& avQueueItem) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t RegisterCallback(const std::shared_ptr<AVCastControllerCallback>& callback) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t GetDuration(int32_t& duration) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t GetCastAVPlaybackState(AVPlaybackState& avPlaybackState) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t GetSupportedDecoders(std::vector<std::string>& decoderTypes) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t GetRecommendedResolutionLevel(std::string& decoderType, ResolutionLevel& resolutionLevel) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t GetSupportedHdrCapabilities(std::vector<HDRFormat>& hdrFormats) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t GetSupportedPlaySpeeds(std::vector<float>& playSpeeds) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t GetCurrentItem(AVQueueItem& currentItem) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t GetValidCommands(std::vector<int32_t>& cmds) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t SetDisplaySurface(std::string& surfaceId) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t SetCastPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t ProcessMediaKeyResponse(const std::string& assetId, const std::vector<uint8_t>& response) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t AddAvailableCommand(const int32_t cmd) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t RemoveAvailableCommand(const int32_t cmd) override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    int32_t Destroy() override
        { return isSuccess ? AVSESSION_SUCCESS : AVSESSION_ERROR; }

    bool isSuccess;

protected:
    int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) override { return 0; }
};

/**
* @tc.name: OnRemoteRequestCode0_1
* @tc.desc: test HandleSendControlCommand
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode0_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode0_1 begin");
    uint32_t code = 0;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode0_1 end");
}

/**
* @tc.name: OnRemoteRequestCode0_2
* @tc.desc: test HandleSendControlCommand
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode0_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode0_2 begin");
    uint32_t code = 0;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    sptr<AVCastControlCommand> cmd = new AVCastControlCommand();
    data.WriteParcelable(cmd);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode0_2 end");
}

/**
* @tc.name: OnRemoteRequestCode1_1
* @tc.desc: test HandleStart
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode1_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode1_1 begin");
    uint32_t code = 1;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode1_1 end");
}

/**
* @tc.name: OnRemoteRequestCode1_2
* @tc.desc: test HandleStart
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode1_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode1_2 begin");
    uint32_t code = 1;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    sptr<AVQueueItem> avQueueItem = new AVQueueItem();
    data.WriteParcelable(avQueueItem);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode1_2 end");
}

/**
* @tc.name: OnRemoteRequestCode2_1
* @tc.desc: test HandlePrepare
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode2_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode2_1 begin");
    uint32_t code = 2;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode2_1 end");
}

/**
* @tc.name: OnRemoteRequestCode2_2
* @tc.desc: test HandlePrepare
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode2_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode2_2 begin");
    uint32_t code = 2;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    sptr<AVQueueItem> avQueueItem = new AVQueueItem();
    data.WriteParcelable(avQueueItem);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode2_2 end");
}

/**
* @tc.name: OnRemoteRequestCode3_1
* @tc.desc: test HandleGetDuration
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode3_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode3_1 begin");
    uint32_t code = 3;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode3_1 end");
}

/**
* @tc.name: OnRemoteRequestCode3_2
* @tc.desc: test HandleGetDuration
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode3_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode3_2 begin");
    uint32_t code = 3;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode3_2 end");
}

/**
* @tc.name: OnRemoteRequestCode4_1
* @tc.desc: test HandleGetCastAVPlayBackState
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode4_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode4_1 begin");
    uint32_t code = 4;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode4_1 end");
}

/**
* @tc.name: OnRemoteRequestCode4_2
* @tc.desc: test HandleGetCastAVPlayBackState
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode4_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode4_2 begin");
    uint32_t code = 4;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode4_2 end");
}

/**
* @tc.name: OnRemoteRequestCode5_1
* @tc.desc: test HandleGetCurrentItem
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode5_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode5_1 begin");
    uint32_t code = 5;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode5_1 end");
}

/**
* @tc.name: OnRemoteRequestCode5_2
* @tc.desc: test HandleGetCurrentItem
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode5_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode5_2 begin");
    uint32_t code = 5;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode5_2 end");
}

/**
* @tc.name: OnRemoteRequestCode6_1
* @tc.desc: test HandleGetValidCommands
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode6_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode6_1 begin");
    uint32_t code = 6;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode6_1 end");
}

/**
* @tc.name: OnRemoteRequestCode6_2
* @tc.desc: test HandleGetValidCommands
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode6_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode6_2 begin");
    uint32_t code = 6;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode6_2 end");
}

/**
* @tc.name: OnRemoteRequestCode7_1
* @tc.desc: test HandleSetDisplaySurface
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode7_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode7_1 begin");
    uint32_t code = 7;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    SLOGI("OnRemoteRequestCode7_1 ret with %{public}d", ret);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode7_1 end");
}

/**
* @tc.name: OnRemoteRequestCode7_2
* @tc.desc: test HandleSetDisplaySurface
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode7_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode7_2 begin");
    uint32_t code = 7;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    
    std::string deviceId = "deviceId";
    std::string bundleName = "test.ohos.avsession";
    std::string abilityName = "test.ability";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    sptr<IRemoteObject> obj = g_AVSessionService->CreateSessionInner("test",
        AVSession::SESSION_TYPE_AUDIO, elementName);
    data.WriteRemoteObject(obj);

    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    SLOGI("OnRemoteRequestCode7_2 ret with %{public}d", ret);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode7_2 end");
}

/**
* @tc.name: OnRemoteRequestCode8_1
* @tc.desc: test HandleSetCastPlaybackFilter
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode8_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode0_1 begin");
    uint32_t code = 8;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode0_1 end");
}

/**
* @tc.name: OnRemoteRequestCode8_2
* @tc.desc: test HandleSetCastPlaybackFilter
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode8_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode8_2 begin");
    uint32_t code = 8;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    std::string str(14, 'a');
    data.WriteString(str);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode8_2 end");
}

/**
* @tc.name: OnRemoteRequestCode8_3
* @tc.desc: test HandleSetCastPlaybackFilter
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode8_3, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode8_3 begin");
    uint32_t code = 8;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    std::string str{"01010101010101"};
    data.WriteString(str);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("OnRemoteRequestCode8_3 end");
}

/**
* @tc.name: OnRemoteRequestCode9_1
* @tc.desc: test HandleProcessMediaKeyResponse
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode9_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode9_1 begin");
    uint32_t code = 9;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    data.WriteInt32(0);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode9_1 end");
}

/**
* @tc.name: OnRemoteRequestCode9_2
* @tc.desc: test HandleProcessMediaKeyResponse
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode9_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode9_2 begin");
    uint32_t code = 9;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    data.WriteInt32(4);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode9_2 end");
}

/**
* @tc.name: OnRemoteRequestCode9_3
* @tc.desc: test HandleProcessMediaKeyResponse
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode9_3, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode9_3 begin");
    uint32_t code = 9;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    data.WriteInt32(4);
    std::string str{"****"};
    data.WriteString(str.c_str());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode9_3 end");
}

/**
* @tc.name: OnRemoteRequestCode10_1
* @tc.desc: test HandleRegisterCallbackInner
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode10_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode10_1 begin");
    uint32_t code = 10;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;

    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    std::string deviceId = "deviceId";
    std::string bundleName = "test.ohos.avsession";
    std::string abilityName = "test.ability";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    sptr<IRemoteObject> obj = g_AVSessionService->CreateSessionInner("test",
        AVSession::SESSION_TYPE_AUDIO, elementName);
    data.WriteRemoteObject(obj);

    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode10_1 end");
}

/**
* @tc.name: OnRemoteRequestCode10_2
* @tc.desc: test HandleRegisterCallbackInner
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode10_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode10_2 begin");
    uint32_t code = 10;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode10_2 end");
}

/**
* @tc.name: OnRemoteRequestCode11_1
* @tc.desc: test HandleDestroy
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode11_1, TestSize.Level1)
{
    SLOGI("OnRemoteRequestCode11_1 begin");
    uint32_t code = 11;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    SLOGI("OnRemoteRequestCode11_1 end");
}

/**
* @tc.name: OnRemoteRequestCode11_2
* @tc.desc: test HandleDestroy
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode11_2, TestSize.Level1)
{
    SLOGI("OnRemoteRequestCode11_2 begin");
    uint32_t code = 11;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    SLOGI("OnRemoteRequestCode11_2 end");
}

/**
* @tc.name: OnRemoteRequestCode12_1
* @tc.desc: test HandleAddAvailableCommand
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode12_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode12_1 begin");
    uint32_t code = 12;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode12_1 end");
}

/**
* @tc.name: OnRemoteRequestCode12_2
* @tc.desc: test HandleAddAvailableCommand
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode12_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode12_2 begin");
    uint32_t code = 12;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode12_2 end");
}

/**
* @tc.name: OnRemoteRequestCode13_1
* @tc.desc: test HandleRemoveAvailableCommand
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode13_1, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode13_1 begin");
    uint32_t code = 13;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = true;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode13_1 end");
}

/**
* @tc.name: OnRemoteRequestCode13_2
* @tc.desc: test HandleRemoveAvailableCommand
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode13_2, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode13_2 begin");
    uint32_t code = 13;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    SLOGI("OnRemoteRequestCode13_2 end");
}

/**
* @tc.name: OnRemoteRequestCode14
* @tc.desc: test OnRemoteRequest
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode14, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode14 begin");
    uint32_t code = 0;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("OnRemoteRequestCode14 end");
}

/**
* @tc.name: OnRemoteRequestCode15
* @tc.desc: test OnRemoteRequest
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerStubTest, OnRemoteRequestCode15, TestSize.Level0)
{
    SLOGI("OnRemoteRequestCode15 begin");
    uint32_t code = 1000;
    AVCastControllerStubDemo aVCastControllerStubDemo;
    aVCastControllerStubDemo.isSuccess = false;
    OHOS::MessageParcel data;
    auto localDescriptor = IAVCastController::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = aVCastControllerStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
    SLOGI("OnRemoteRequestCode15 end");
}

} // namespace OHOS
} // namespace AVSession