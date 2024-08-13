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
#include "avsession_pixel_map.h"
#include "avsession_pixel_map_adapter.h"
#define private public
#define protected public
#include "avcontroller_callback_proxy.h"
#undef protected
#undef private

using namespace OHOS::AVSession;
using namespace OHOS::Media;
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

class AVControllerCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    OHOS::sptr<AVControllerCallbackProxy> aVControllerCallbackProxy;
};

void AVControllerCallbackProxyTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVControllerCallbackProxyTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVControllerCallbackProxyTest::SetUp()
{
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
    aVControllerCallbackProxy = OHOS::iface_cast<AVControllerCallbackProxy>(object);
}

void AVControllerCallbackProxyTest::TearDown()
{
}

std::shared_ptr<PixelMap> CreatePixelMap()
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
    g_metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    return g_metaData;
}

/**
 * @tc.name: OnSessionDestroy001
 * @tc.desc: Test OnSessionDestroy
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnSessionDestroy001, testing::ext::TestSize.Level1)
{
    SLOGI("OnSessionDestroy001, start");
    aVControllerCallbackProxy->OnSessionDestroy();
    SLOGI("OnSessionDestroy001, end");
}

/**
 * @tc.name: OnAVCallMetaDataChange001
 * @tc.desc: Test OnAVCallMetaDataChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnAVCallMetaDataChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnAVCallMetaDataChange001, start");
    OHOS::AVSession::AVCallMetaData data;
    aVControllerCallbackProxy->OnAVCallMetaDataChange(data);
    SLOGI("OnAVCallMetaDataChange001, end");
}

/**
 * @tc.name: OnAVCallStateChange001
 * @tc.desc: Test OnAVCallStateChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnAVCallStateChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnAVCallStateChange001, start");
    OHOS::AVSession::AVCallState data;
    aVControllerCallbackProxy->OnAVCallStateChange(data);
    SLOGI("OnAVCallStateChange001, end");
}

/**
 * @tc.name: OnPlaybackStateChange001
 * @tc.desc: Test OnPlaybackStateChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnPlaybackStateChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnAVCallStateChange001, start");
    OHOS::AVSession::AVPlaybackState data;
    aVControllerCallbackProxy->OnPlaybackStateChange(data);
    SLOGI("OnAVCallStateChange001, end");
}

/**
 * @tc.name: OnMetaDataChange001
 * @tc.desc: Test OnMetaDataChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnMetaDataChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnMetaDataChange001, start");
    OHOS::AVSession::AVMetaData data;
    aVControllerCallbackProxy->OnMetaDataChange(data);
    SLOGI("OnMetaDataChange001, end");
}

/**
 * @tc.name: OnMetaDataChange001
 * @tc.desc: Test OnMetaDataChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnMetaDataChange002, testing::ext::TestSize.Level1)
{
    SLOGI("OnMetaDataChange002, start");
    OHOS::AVSession::AVMetaData data = GetAVMetaData();
    aVControllerCallbackProxy->OnMetaDataChange(data);
    SLOGI("OnMetaDataChange002, end");
}

/**
 * @tc.name: GetPixelMapBuffer001
 * @tc.desc: Test GetPixelMapBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, GetPixelMapBuffer001, testing::ext::TestSize.Level1)
{
    SLOGI("GetPixelMapBuffer001, start");
    OHOS::AVSession::AVMetaData metaData;
    OHOS::MessageParcel parcel;
    int32_t ret = aVControllerCallbackProxy->GetPixelMapBuffer(metaData, parcel);
    EXPECT_EQ(ret, 0);
    SLOGI("GetPixelMapBuffer001, end");
}

/**
 * @tc.name: GetPixelMapBuffer002
 * @tc.desc: Test GetPixelMapBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, GetPixelMapBuffer002, testing::ext::TestSize.Level1)
{
    SLOGI("GetPixelMapBuffer002, start");
    OHOS::AVSession::AVMetaData metaData = GetAVMetaData();
    OHOS::MessageParcel parcel;
    int32_t ret = aVControllerCallbackProxy->GetPixelMapBuffer(metaData, parcel);
    EXPECT_EQ(ret, 78);
    SLOGI("GetPixelMapBuffer002, end");
}

/**
 * @tc.name: GetPixelMapBuffer003
 * @tc.desc: Test GetPixelMapBuffer
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, GetPixelMapBuffer003, testing::ext::TestSize.Level1)
{
    SLOGI("GetPixelMapBuffer003, start");
    OHOS::AVSession::AVMetaData metaData = GetAVMetaData();
    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> imgBuffer = {0, 1, 0, 1};
    avQueuePixelMap->SetInnerImgBuffer(imgBuffer);
    metaData.SetAVQueueImage(avQueuePixelMap);
    OHOS::MessageParcel parcel;
    int32_t ret = aVControllerCallbackProxy->GetPixelMapBuffer(metaData, parcel);
    EXPECT_EQ(ret, 82);
    SLOGI("GetPixelMapBuffer003, end");
}

/**
 * @tc.name: OnActiveStateChange001
 * @tc.desc: Test OnActiveStateChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnActiveStateChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnActiveStateChange001, start");
    bool isActive = true;
    aVControllerCallbackProxy->OnActiveStateChange(isActive);
    SLOGI("OnActiveStateChange001, end");
}

/**
 * @tc.name: OnActiveStateChange002
 * @tc.desc: Test OnActiveStateChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnActiveStateChange002, testing::ext::TestSize.Level1)
{
    SLOGI("OnActiveStateChange002, start");
    bool isActive = false;
    aVControllerCallbackProxy->OnActiveStateChange(isActive);
    SLOGI("OnActiveStateChange002, end");
}

/**
 * @tc.name: OnValidCommandChange001
 * @tc.desc: Test OnValidCommandChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnValidCommandChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnValidCommandChange001, start");
    std::vector<int32_t> cmds = {0};
    aVControllerCallbackProxy->OnValidCommandChange(cmds);
    SLOGI("OnValidCommandChange001, end");
}

/**
 * @tc.name: OnOutputDeviceChange001
 * @tc.desc: Test OnOutputDeviceChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnOutputDeviceChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnOutputDeviceChange001, start");
    int32_t connectionState = 0;
    OHOS::AVSession::OutputDeviceInfo outputDeviceInfo;
    aVControllerCallbackProxy->OnOutputDeviceChange(connectionState, outputDeviceInfo);
    SLOGI("OnOutputDeviceChange001, end");
}

/**
 * @tc.name: OnSessionEventChange001
 * @tc.desc: Test OnSessionEventChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnSessionEventChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnSessionEventChange001, start");
    std::string event = "";
    OHOS::AAFwk::WantParams args;
    aVControllerCallbackProxy->OnSessionEventChange(event, args);
    SLOGI("OnSessionEventChange001, end");
}

/**
 * @tc.name: OnQueueItemsChange001
 * @tc.desc: Test OnQueueItemsChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnQueueItemsChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnQueueItemsChange001, start");
    std::vector<AVQueueItem> items = {};
    aVControllerCallbackProxy->OnQueueItemsChange(items);
    SLOGI("OnQueueItemsChange001, end");
}

/**
 * @tc.name: OnQueueTitleChange001
 * @tc.desc: Test OnQueueTitleChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnQueueTitleChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnQueueTitleChange001, start");
    std::string title = "title";
    aVControllerCallbackProxy->OnQueueTitleChange(title);
    SLOGI("OnQueueTitleChange001, end");
}

/**
 * @tc.name: OnExtrasChange001
 * @tc.desc: Test OnExtrasChange
 * @tc.type: FUNC
 */
static HWTEST_F(AVControllerCallbackProxyTest, OnExtrasChange001, testing::ext::TestSize.Level1)
{
    SLOGI("OnExtrasChange001, start");
    OHOS::AAFwk::WantParams extras;
    aVControllerCallbackProxy->OnExtrasChange(extras);
    SLOGI("OnExtrasChange001, end");
}