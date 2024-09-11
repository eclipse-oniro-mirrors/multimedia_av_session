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
#include "avsession_pixel_map.h"
#include "avsession_pixel_map_adapter.h"

#define private public
#define protected public
#include "avsession_controller_stub.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AVSession;
using namespace OHOS::Media;
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

static std::shared_ptr<PixelMap> CreatePixelMap()
{
    int32_t pixelMapWidth = 4;
    int32_t pixelMapHeight = 3;
    const std::shared_ptr<PixelMap> &pixelMap = std::make_shared<PixelMap>();
    ImageInfo info;
    info.size.width = pixelMapWidth;
    info.size.height = pixelMapHeight;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);
    int32_t rowDataSize = pixelMapWidth;
    uint32_t bufferSize = rowDataSize * pixelMapHeight;
    if (bufferSize <= 0) {
        return pixelMap;
    }

    std::vector<std::uint8_t> buffer(bufferSize, 0x03);
    pixelMap->SetPixelsAddr(buffer.data(), nullptr, bufferSize, AllocatorType::CUSTOM_ALLOC, nullptr);

    return pixelMap;
}

static const int32_t DURATION_TIME = 40000;
static AVMetaData GetAVMetaData()
{
    AVMetaData g_metaData;
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
    g_metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    return g_metaData;
}

class AVSessionControllerStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionControllerStubTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionControllerStubTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionControllerStubTest::SetUp()
{
}

void AVSessionControllerStubTest::TearDown()
{
}

class AVSessionControllerStubDemo : public AVSessionControllerStub {
public:
    int32_t GetAVCallState(AVCallState &avCallState) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t GetAVCallMetaData(AVCallMetaData &avCallMetaData) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t GetAVPlaybackState(AVPlaybackState &state) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t GetAVMetaData(AVMetaData &data) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t SendAVKeyEvent(const OHOS::MMI::KeyEvent &keyEvent) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t GetLaunchAbility(OHOS::AbilityRuntime::WantAgent::WantAgent &ability) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    int32_t GetValidCommands(std::vector<int32_t> &cmds) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t IsSessionActive(bool &isActive) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t SendControlCommand(const AVControlCommand &cmd) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t SendCommonCommand(const std::string &commonCommand, const OHOS::AAFwk::WantParams &commandArgs) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback> &callback) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    int32_t SetAVCallMetaFilter(const AVCallMetaData::AVCallMetaMaskType &filter) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    int32_t SetAVCallStateFilter(const AVCallState::AVCallStateMaskType &filter) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    int32_t SetMetaFilter(const AVMetaData::MetaMaskType &filter) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    int32_t SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType &filter) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    int32_t GetAVQueueItems(std::vector<AVQueueItem> &items) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t GetAVQueueTitle(std::string &title) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t SkipToQueueItem(int32_t &itemId) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t GetExtras(OHOS::AAFwk::WantParams &extras) override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    int32_t Destroy() override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    std::string GetSessionId() override { return ""; };
    int64_t GetRealPlaybackPosition() override { return isSuccess ? AVSESSION_SUCCESS : 0; };
    bool IsDestroy() override { return true; };
    int32_t RegisterCallbackInner(const OHOS::sptr<IRemoteObject> &callback) override
    {
        return isSuccess ? AVSESSION_SUCCESS : 0;
    };
    bool isSuccess = true;
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest001, TestSize.Level1)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = 0;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("OnRemoteRequest001 end!");
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest002, TestSize.Level1)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = 0;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest002 end!");
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest003, TestSize.Level1)
{
    SLOGI("OnRemoteRequest003 begin!");
    uint32_t code = 0;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest003 end!");
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest004, TestSize.Level1)
{
    SLOGI("OnRemoteRequest004 begin!");
    uint32_t code = 2;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest004 end!");
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest005, TestSize.Level1)
{
    SLOGI("OnRemoteRequest005 begin!");
    uint32_t code = 2;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest005 end!");
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest006, TestSize.Level1)
{
    SLOGI("OnRemoteRequest006 begin!");
    uint32_t code = 3;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest006 end!");
}

/**
 * @tc.name: OnRemoteRequest007
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest007, TestSize.Level1)
{
    SLOGI("OnRemoteRequest007 begin!");
    uint32_t code = 3;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest007 end!");
}

/**
 * @tc.name: OnRemoteRequest008
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest008, TestSize.Level1)
{
    SLOGI("OnRemoteRequest008 begin!");
    uint32_t code = 4;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest008 end!");
}

/**
 * @tc.name: OnRemoteRequest009
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest009, TestSize.Level1)
{
    SLOGI("OnRemoteRequest009 begin!");
    uint32_t code = 4;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest009 end!");
}

/**
 * @tc.name: OnRemoteRequest010
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest010, TestSize.Level1)
{
    SLOGI("OnRemoteRequest010 begin!");
    uint32_t code = 5;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest010 end!");
}

/**
 * @tc.name: OnRemoteRequest011
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest011, TestSize.Level1)
{
    SLOGI("OnRemoteRequest011 begin!");
    uint32_t code = 5;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest011 end!");
}

/**
 * @tc.name: OnRemoteRequest012
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest012, TestSize.Level1)
{
    SLOGI("OnRemoteRequest012 begin!");
    uint32_t code = 6;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest012 end!");
}

/**
 * @tc.name: OnRemoteRequest013
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest013, TestSize.Level1)
{
    SLOGI("OnRemoteRequest013 begin!");
    uint32_t code = 6;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest013 end!");
}

/**
 * @tc.name: OnRemoteRequest014
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest014, TestSize.Level1)
{
    SLOGI("OnRemoteRequest014 begin!");
    uint32_t code = 7;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest014 end!");
}

/**
 * @tc.name: OnRemoteRequest015
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest015, TestSize.Level1)
{
    SLOGI("OnRemoteRequest015 begin!");
    uint32_t code = 7;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest015 end!");
}

/**
 * @tc.name: OnRemoteRequest016
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest016, TestSize.Level1)
{
    SLOGI("OnRemoteRequest016 begin!");
    uint32_t code = 8;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest016 end!");
}

/**
 * @tc.name: OnRemoteRequest017
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest017, TestSize.Level1)
{
    SLOGI("OnRemoteRequest017 begin!");
    uint32_t code = 8;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest017 end!");
}

/**
 * @tc.name: OnRemoteRequest018
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest018, TestSize.Level1)
{
    SLOGI("OnRemoteRequest018 begin!");
    uint32_t code = 9;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest018 end!");
}

/**
 * @tc.name: OnRemoteRequest019
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest019, TestSize.Level1)
{
    SLOGI("OnRemoteRequest019 begin!");
    uint32_t code = 9;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest019 end!");
}

/**
 * @tc.name: OnRemoteRequest019_1
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest019_1, TestSize.Level1)
{
    SLOGI("OnRemoteRequest019_1 begin!");
    uint32_t code = 9;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("222222");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest019_1 end!");
}

/**
 * @tc.name: OnRemoteRequest019_2
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest019_2, TestSize.Level1)
{
    SLOGI("OnRemoteRequest019_2 begin!");
    uint32_t code = 9;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("01010101");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest019_2 end!");
}

/**
 * @tc.name: OnRemoteRequest020
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest020, TestSize.Level1)
{
    SLOGI("OnRemoteRequest020 begin!");
    uint32_t code = 10;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest020 end!");
}

/**
 * @tc.name: OnRemoteRequest021
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest021, TestSize.Level1)
{
    SLOGI("OnRemoteRequest021 begin!");
    uint32_t code = 10;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest021 end!");
}

/**
 * @tc.name: OnRemoteRequest021_1
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest021_1, TestSize.Level1)
{
    SLOGI("OnRemoteRequest021_1 begin!");
    uint32_t code = 10;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("222222");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest021_1 end!");
}

/**
 * @tc.name: OnRemoteRequest021_2
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest021_2, TestSize.Level1)
{
    SLOGI("OnRemoteRequest021_2 begin!");
    uint32_t code = 10;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("01010101");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest021_2 end!");
}

/**
 * @tc.name: OnRemoteRequest022
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest022, TestSize.Level1)
{
    SLOGI("OnRemoteRequest022 begin!");
    uint32_t code = 11;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest022 end!");
}

/**
 * @tc.name: OnRemoteRequest023
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest023, TestSize.Level1)
{
    SLOGI("OnRemoteRequest023 begin!");
    uint32_t code = 11;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest023 end!");
}

/**
 * @tc.name: OnRemoteRequest024
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest024, TestSize.Level1)
{
    SLOGI("OnRemoteRequest024 begin!");
    uint32_t code = 13;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest024 end!");
}

/**
 * @tc.name: OnRemoteRequest025
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest025, TestSize.Level1)
{
    SLOGI("OnRemoteRequest025 begin!");
    uint32_t code = 13;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest025 end!");
}

/**
 * @tc.name: OnRemoteRequest026
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest026, TestSize.Level1)
{
    SLOGI("OnRemoteRequest026 begin!");
    uint32_t code = 14;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest026 end!");
}

/**
 * @tc.name: OnRemoteRequest027
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest027, TestSize.Level1)
{
    SLOGI("OnRemoteRequest027 begin!");
    uint32_t code = 14;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest027 end!");
}

/**
 * @tc.name: OnRemoteRequest028
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest028, TestSize.Level1)
{
    SLOGI("OnRemoteRequest028 begin!");
    uint32_t code = 15;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest028 end!");
}

/**
 * @tc.name: OnRemoteRequest029
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest029, TestSize.Level1)
{
    SLOGI("OnRemoteRequest029 begin!");
    uint32_t code = 15;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest029 end!");
}

/**
 * @tc.name: OnRemoteRequest030
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest030, TestSize.Level1)
{
    SLOGI("OnRemoteRequest030 begin!");
    uint32_t code = 16;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest030 end!");
}

/**
 * @tc.name: OnRemoteRequest031
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest031, TestSize.Level1)
{
    SLOGI("OnRemoteRequest031 begin!");
    uint32_t code = 16;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest031 end!");
}

/**
 * @tc.name: OnRemoteRequest032
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest032, TestSize.Level1)
{
    SLOGI("OnRemoteRequest032 begin!");
    uint32_t code = 17;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest032 end!");
}

/**
 * @tc.name: OnRemoteRequest033
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest033, TestSize.Level1)
{
    SLOGI("OnRemoteRequest033 begin!");
    uint32_t code = 17;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest033 end!");
}

/**
 * @tc.name: OnRemoteRequest034
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest034, TestSize.Level1)
{
    SLOGI("OnRemoteRequest034 begin!");
    uint32_t code = 18;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest034 end!");
}

/**
 * @tc.name: OnRemoteRequest035
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest035, TestSize.Level1)
{
    SLOGI("OnRemoteRequest035 begin!");
    uint32_t code = 18;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest035 end!");
}

/**
 * @tc.name: OnRemoteRequest035_1
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest035_1, TestSize.Level1)
{
    SLOGI("OnRemoteRequest035_1 begin!");
    uint32_t code = 18;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("222222");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest035_1 end!");
}

/**
 * @tc.name: OnRemoteRequest035_2
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest035_2, TestSize.Level1)
{
    SLOGI("OnRemoteRequest035_2 begin!");
    uint32_t code = 18;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("0101010");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest035_2 end!");
}

/**
 * @tc.name: OnRemoteRequest036
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest036, TestSize.Level1)
{
    SLOGI("OnRemoteRequest036 begin!");
    uint32_t code = 19;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest036 end!");
}

/**
 * @tc.name: OnRemoteRequest037
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest037, TestSize.Level1)
{
    SLOGI("OnRemoteRequest037 begin!");
    uint32_t code = 19;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest037 end!");
}

/**
 * @tc.name: OnRemoteRequest038
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest038, TestSize.Level1)
{
    SLOGI("OnRemoteRequest038 begin!");
    uint32_t code = 20;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest038 end!");
}

/**
 * @tc.name: OnRemoteRequest039
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest039, TestSize.Level1)
{
    SLOGI("OnRemoteRequest039 begin!");
    uint32_t code = 20;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest039 end!");
}

/**
 * @tc.name: OnRemoteRequest039_1
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest039_1, TestSize.Level1)
{
    SLOGI("OnRemoteRequest039_1 begin!");
    uint32_t code = 20;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("222222");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest039_1 end!");
}

/**
 * @tc.name: OnRemoteRequest039_2
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest039_2, TestSize.Level1)
{
    SLOGI("OnRemoteRequest039_2 begin!");
    uint32_t code = 20;
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("01010101");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("OnRemoteRequest039_2 end!");
}

/**
 * @tc.name: OnRemoteRequest040
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, OnRemoteRequest040, TestSize.Level1)
{
    SLOGI("OnRemoteRequest040 begin!");
    uint32_t code = 25;
    AVSessionControllerStubDemo avSessionControllerStub;
    avSessionControllerStub.isSuccess = false;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(IAVSessionController::GetDescriptor());
    data.WriteString("test");
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avSessionControllerStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, 305);
    SLOGI("OnRemoteRequest040 end!");
}

/**
 * @tc.name: DoMetadataGetReplyInStub001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, DoMetadataGetReplyInStub001, TestSize.Level1)
{
    SLOGI("DoMetadataGetReplyInStub001 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    AVMetaData data;
    OHOS::MessageParcel reply;
    int ret = avSessionControllerStub.DoMetadataGetReplyInStub(data, reply);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
    SLOGI("DoMetadataGetReplyInStub001 end!");
}

/**
 * @tc.name: DoMetadataGetReplyInStub002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, DoMetadataGetReplyInStub002, TestSize.Level1)
{
    SLOGI("DoMetadataGetReplyInStub002 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    AVMetaData data = GetAVMetaData();
    OHOS::MessageParcel reply;
    int ret = avSessionControllerStub.DoMetadataGetReplyInStub(data, reply);
    EXPECT_NE(ret, AVSESSION_ERROR);
    SLOGI("DoMetadataGetReplyInStub002 end!");
}

/**
 * @tc.name: DoMetadataImgCleanInStub001
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, DoMetadataImgCleanInStub001, TestSize.Level1)
{
    SLOGI("DoMetadataImgCleanInStub001 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    AVMetaData data = GetAVMetaData();
    avSessionControllerStub.DoMetadataImgCleanInStub(data);
    SLOGI("DoMetadataImgCleanInStub001 end!");
}

/**
 * @tc.name: DoMetadataImgCleanInStub002
 * @tc.desc: Test OnRemoteRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, DoMetadataImgCleanInStub002, TestSize.Level1)
{
    SLOGI("DoMetadataImgCleanInStub002 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    AVMetaData data = GetAVMetaData();
    avSessionControllerStub.DoMetadataImgCleanInStub(data);
}

/**
 * @tc.name: HandleSetAVCallMetaFilter001
 * @tc.desc: Test HandleSetAVCallMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetAVCallMetaFilter001, TestSize.Level1)
{
    SLOGI("HandleSetAVCallMetaFilter001 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("1111111");
    avSessionControllerStub.HandleSetAVCallMetaFilter(data, reply);
    SLOGI("HandleSetAVCallMetaFilter001 end!");
}

/**
 * @tc.name: HandleSetAVCallMetaFilter002
 * @tc.desc: Test HandleSetAVCallMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetAVCallMetaFilter002, TestSize.Level1)
{
    SLOGI("HandleSetAVCallMetaFilter002 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("2222");
    avSessionControllerStub.HandleSetAVCallMetaFilter(data, reply);
    SLOGI("HandleSetAVCallMetaFilter002 end!");
}

/**
 * @tc.name: HandleSetAVCallMetaFilter003
 * @tc.desc: Test HandleSetAVCallMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetAVCallMetaFilter003, TestSize.Level1)
{
    SLOGI("HandleSetAVCallMetaFilter003 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("1010");
    avSessionControllerStub.HandleSetAVCallMetaFilter(data, reply);
    SLOGI("HandleSetAVCallMetaFilter003 end!");
}

/**
 * @tc.name: HandleSetAVCallStateFilter001
 * @tc.desc: Test HandleSetAVCallStateFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetAVCallStateFilter001, TestSize.Level1)
{
    SLOGI("HandleSetAVCallStateFilter001 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("1111111");
    avSessionControllerStub.HandleSetAVCallStateFilter(data, reply);
    SLOGI("HandleSetAVCallStateFilter001 end!");
}

/**
 * @tc.name: HandleSetAVCallStateFilter002
 * @tc.desc: Test HandleSetAVCallStateFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetAVCallStateFilter002, TestSize.Level1)
{
    SLOGI("HandleSetAVCallStateFilter002 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("2222");
    avSessionControllerStub.HandleSetAVCallStateFilter(data, reply);
    SLOGI("HandleSetAVCallStateFilter002 end!");
}

/**
 * @tc.name: HandleSetAVCallStateFilter003
 * @tc.desc: Test HandleSetAVCallStateFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetAVCallStateFilter003, TestSize.Level1)
{
    SLOGI("HandleSetAVCallStateFilter003 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("1010");
    avSessionControllerStub.HandleSetAVCallStateFilter(data, reply);
    SLOGI("HandleSetAVCallStateFilter003 end!");
}

/**
 * @tc.name: HandleSetMetaFilter001
 * @tc.desc: Test HandleSetMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetMetaFilter001, TestSize.Level1)
{
    SLOGI("HandleSetMetaFilter001 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("1111111");
    avSessionControllerStub.HandleSetMetaFilter(data, reply);
    SLOGI("HandleSetMetaFilter001 end!");
}

/**
 * @tc.name: HandleSetMetaFilter002
 * @tc.desc: Test HandleSetMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetMetaFilter002, TestSize.Level1)
{
    SLOGI("HandleSetMetaFilter002 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("2222");
    avSessionControllerStub.HandleSetMetaFilter(data, reply);
    SLOGI("HandleSetMetaFilter002 end!");
}

/**
 * @tc.name: HandleSetMetaFilter003
 * @tc.desc: Test HandleSetMetaFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetMetaFilter003, TestSize.Level1)
{
    SLOGI("HandleSetMetaFilter003 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("1010");
    avSessionControllerStub.HandleSetMetaFilter(data, reply);
    SLOGI("HandleSetMetaFilter003 end!");
}

/**
 * @tc.name: HandleSetPlaybackFilter001
 * @tc.desc: Test HandleSetPlaybackFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetPlaybackFilter001, TestSize.Level1)
{
    SLOGI("HandleSetPlaybackFilter001 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("1111111");
    avSessionControllerStub.HandleSetPlaybackFilter(data, reply);
    SLOGI("HandleSetPlaybackFilter001 end!");
}

/**
 * @tc.name: HandleSetPlaybackFilter002
 * @tc.desc: Test HandleSetPlaybackFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetPlaybackFilter002, TestSize.Level1)
{
    SLOGI("HandleSetPlaybackFilter002 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("2222");
    avSessionControllerStub.HandleSetPlaybackFilter(data, reply);
    SLOGI("HandleSetPlaybackFilter002 end!");
}

/**
 * @tc.name: HandleSetPlaybackFilter003
 * @tc.desc: Test HandleSetPlaybackFilter
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionControllerStubTest, HandleSetPlaybackFilter003, TestSize.Level1)
{
    SLOGI("HandleSetPlaybackFilter003 begin!");
    AVSessionControllerStubDemo avSessionControllerStub;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    data.WriteString("1010");
    avSessionControllerStub.HandleSetPlaybackFilter(data, reply);
    SLOGI("HandleSetPlaybackFilter003 end!");
}