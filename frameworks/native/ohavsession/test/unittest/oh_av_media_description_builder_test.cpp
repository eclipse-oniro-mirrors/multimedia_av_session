/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "OHAVMediaDescriptionBuilder.h"
#include "OHAVMediaDescription.h"
#include "avmedia_description.h"
#include "avsession_log.h"
#include "pixelmap_native_impl.h"
#include "native_avqueueitem.h"

using namespace testing::ext;

namespace OHOS::AVSession {

static char* g_assetId = nullptr;
static char* g_title = nullptr;
static char* g_subtitle = nullptr;
static char* g_artist = nullptr;
static char* g_albumCoverUri = nullptr;
static char* g_mediaType = nullptr;
static char* g_lyricContent = nullptr;
static int32_t g_duration = 0;
static char* g_mediaUri = nullptr;
static int32_t g_startPosition = 0;
static int32_t g_mediaSize = 0;
static char* g_albumTitle = nullptr;
static char* g_appName = nullptr;
static OHAVMediaDescriptionBuilder g_ohAVMediaDescriptionBuilder;
constexpr int DURATION = 40000;

class OHAVMediaDescriptionBuilderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<OHOS::Media::PixelMap> CreateTestPixelMap();
};

void OHAVMediaDescriptionBuilderTest::SetUpTestCase()
{
}

void OHAVMediaDescriptionBuilderTest::TearDownTestCase()
{
}

void OHAVMediaDescriptionBuilderTest::SetUp()
{
    g_assetId = nullptr;
    g_title = nullptr;
    g_subtitle = nullptr;
    g_artist = nullptr;
    g_albumCoverUri = nullptr;
    g_mediaType = nullptr;
    g_lyricContent = nullptr;
    g_duration = 0;
    g_mediaUri = nullptr;
    g_startPosition = 0;
    g_mediaSize = 0;
    g_albumTitle = nullptr;
    g_appName = nullptr;
}

void OHAVMediaDescriptionBuilderTest::TearDown()
{
}

std::shared_ptr<OHOS::Media::PixelMap> OHAVMediaDescriptionBuilderTest::CreateTestPixelMap()
    {
        int32_t pixelMapWidth = 4;
        int32_t pixelMapHeight = 3;
        auto pixelMap = std::make_shared<OHOS::Media::PixelMap>();
        OHOS::Media::ImageInfo info;
        info.size.width = pixelMapWidth;
        info.size.height = pixelMapHeight;
        info.pixelFormat = OHOS::Media::PixelFormat::RGB_888;
        info.colorSpace = OHOS::Media::ColorSpace::SRGB;
        pixelMap->SetImageInfo(info);
        int32_t rowDataSize = pixelMapWidth;
        uint32_t bufferSize = rowDataSize * pixelMapHeight;
        if (bufferSize <= 0) {
            return pixelMap;
        }
        std::vector<std::uint8_t> buffer(bufferSize, 0x03);
        pixelMap->SetPixelsAddr(buffer.data(), nullptr, bufferSize, OHOS::Media::AllocatorType::CUSTOM_ALLOC, nullptr);
        return pixelMap;
    }

/**
 * @tc.name: SetAVMediaDescription001
 * @tc.desc: set av media description by class
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVMediaDescriptionBuilderTest, SetAVMediaDescription001, TestSize.Level0)
{
    const std::shared_ptr<OHOS::Media::PixelMap>& pixelMap = CreateTestPixelMap();

    OHAVMediaDescription* ohMediaDescription = new OHAVMediaDescription();
    g_ohAVMediaDescriptionBuilder.SetAssetId("assetId");
    g_ohAVMediaDescriptionBuilder.SetTitle("title");
    g_ohAVMediaDescriptionBuilder.SetSubtitle("subtitle");
    g_ohAVMediaDescriptionBuilder.SetArtist("artist");
    g_ohAVMediaDescriptionBuilder.SetAlbumCoverUri("albumcoverUri");
    g_ohAVMediaDescriptionBuilder.SetMediaType("mediaType");
    g_ohAVMediaDescriptionBuilder.SetLyricContent("lyricContent");
    g_ohAVMediaDescriptionBuilder.SetDuration(DURATION);
    g_ohAVMediaDescriptionBuilder.SetMediaUri("mediaUri");
    g_ohAVMediaDescriptionBuilder.SetStartPosition(100);
    g_ohAVMediaDescriptionBuilder.SetMediaSize(1000);
    g_ohAVMediaDescriptionBuilder.SetAlbumTitle("albumTitle");
    g_ohAVMediaDescriptionBuilder.SetAppName("appName");

    g_ohAVMediaDescriptionBuilder.GenerateAVMediaDescription(&ohMediaDescription);
    ASSERT_NE(ohMediaDescription, nullptr) << "ohMediaDescription is nullptr";

    EXPECT_EQ(ohMediaDescription->GetAssetId(), "assetId");
    EXPECT_EQ(ohMediaDescription->GetTitle(), "title");
    EXPECT_EQ(ohMediaDescription->GetSubtitle(), "subtitle");
    EXPECT_EQ(ohMediaDescription->GetArtist(), "artist");
    EXPECT_EQ(ohMediaDescription->GetAlbumCoverUri(), "albumcoverUri");
    EXPECT_EQ(ohMediaDescription->GetMediaType(), "mediaType");
    EXPECT_EQ(ohMediaDescription->GetLyricContent(), "lyricContent");
    EXPECT_EQ(ohMediaDescription->GetDuration(), DURATION);
    EXPECT_EQ(ohMediaDescription->GetMediaUri(), "mediaUri");
    EXPECT_EQ(ohMediaDescription->GetStartPosition(), 100);
    EXPECT_EQ(ohMediaDescription->GetMediaSize(), 1000);
    EXPECT_EQ(ohMediaDescription->GetAlbumTitle(), "albumTitle");
    EXPECT_EQ(ohMediaDescription->GetAppName(), "appName");

    delete ohMediaDescription;
    ohMediaDescription = nullptr;
}

/**
 * @tc.name: SetAVMediaDescription002
 * @tc.desc: set av media description by func
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVMediaDescriptionBuilderTest, SetAVMediaDescription002, TestSize.Level0)
{
    OH_AVSession_AVMediaDescriptionBuilder *builder = nullptr;
    OH_AVSession_AVMediaDescription* ohMediaDescription = nullptr;
    const std::shared_ptr<OHOS::Media::PixelMap>& pixelMap = CreateTestPixelMap();

    OH_AVSession_AVMediaDescriptionBuilder_Create(&builder);

    OH_AVSession_AVMediaDescriptionBuilder_SetAssetId(builder, "assetId");
    OH_AVSession_AVMediaDescriptionBuilder_SetTitle(builder, "title");
    OH_AVSession_AVMediaDescriptionBuilder_SetSubTitle(builder, "subtitle");
    OH_AVSession_AVMediaDescriptionBuilder_SetArtist(builder, "artist");
    OH_AVSession_AVMediaDescriptionBuilder_SetAlbumCoverUri(builder, "albumCoverUri");
    OH_AVSession_AVMediaDescriptionBuilder_SetMediaType(builder, "mediaType");
    OH_AVSession_AVMediaDescriptionBuilder_SetLyricContent(builder, "lyricContent");
    OH_AVSession_AVMediaDescriptionBuilder_SetDuration(builder, DURATION);
    OH_AVSession_AVMediaDescriptionBuilder_SetMediaUri(builder, "mediaUri");
    OH_AVSession_AVMediaDescriptionBuilder_SetStartPosition(builder, 100);
    OH_AVSession_AVMediaDescriptionBuilder_SetMediaSize(builder, 1000);
    OH_AVSession_AVMediaDescriptionBuilder_SetAlbumTitle(builder, "albumTitle");
    OH_AVSession_AVMediaDescriptionBuilder_SetAppName(builder, "appName");

    OH_AVSession_AVMediaDescriptionBuilder_GenerateAVMediaDescription(builder, &ohMediaDescription);
    OHAVMediaDescription* OhAvMediaDescription = reinterpret_cast<OHAVMediaDescription*>(ohMediaDescription);

    EXPECT_EQ(OhAvMediaDescription->GetAssetId(), "assetId");
    EXPECT_EQ(OhAvMediaDescription->GetTitle(), "title");
    EXPECT_EQ(OhAvMediaDescription->GetSubtitle(), "subtitle");
    EXPECT_EQ(OhAvMediaDescription->GetArtist(), "artist");
    EXPECT_EQ(OhAvMediaDescription->GetAlbumCoverUri(), "albumCoverUri");
    EXPECT_EQ(OhAvMediaDescription->GetMediaType(), "mediaType");
    EXPECT_EQ(OhAvMediaDescription->GetLyricContent(), "lyricContent");
    EXPECT_EQ(OhAvMediaDescription->GetDuration(), DURATION);
    EXPECT_EQ(OhAvMediaDescription->GetMediaUri(), "mediaUri");
    EXPECT_EQ(OhAvMediaDescription->GetStartPosition(), 100);
    EXPECT_EQ(OhAvMediaDescription->GetMediaSize(), 1000);
    EXPECT_EQ(OhAvMediaDescription->GetAlbumTitle(), "albumTitle");
    EXPECT_EQ(OhAvMediaDescription->GetAppName(), "appName");

    OH_AVSession_AVMediaDescriptionBuilder_Destroy(builder);
    OH_AVSession_AVMediaDescription_Destroy(ohMediaDescription);
}

/**
 * @tc.name: SetAVMediaDescription003
 * @tc.desc: set av media description by func
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVMediaDescriptionBuilderTest, SetAVMediaDescription003, TestSize.Level0)
{
    OH_AVSession_AVMediaDescriptionBuilder *builder = nullptr;
    OH_AVSession_AVMediaDescription* ohMediaDescription = nullptr;
    const std::shared_ptr<OHOS::Media::PixelMap>& pixelMap = CreateTestPixelMap();
    OH_AVSession_AVMediaDescriptionBuilder_Create(&builder);
    OH_AVSession_AVMediaDescriptionBuilder_SetAssetId(builder, "assetId");
    OH_AVSession_AVMediaDescriptionBuilder_SetTitle(builder, "title");
    OH_AVSession_AVMediaDescriptionBuilder_SetSubTitle(builder, "subtitle");
    OH_AVSession_AVMediaDescriptionBuilder_SetArtist(builder, "artist");
    OH_AVSession_AVMediaDescriptionBuilder_SetAlbumCoverUri(builder, "albumCoverUri");
    OH_AVSession_AVMediaDescriptionBuilder_SetMediaType(builder, "mediaType");
    OH_AVSession_AVMediaDescriptionBuilder_SetLyricContent(builder, "lyricContent");
    OH_AVSession_AVMediaDescriptionBuilder_SetDuration(builder, DURATION);
    OH_AVSession_AVMediaDescriptionBuilder_SetMediaUri(builder, "mediaUri");
    OH_AVSession_AVMediaDescriptionBuilder_SetStartPosition(builder, 100);
    OH_AVSession_AVMediaDescriptionBuilder_SetMediaSize(builder, 1000);
    OH_AVSession_AVMediaDescriptionBuilder_SetAlbumTitle(builder, "albumTitle");
    OH_AVSession_AVMediaDescriptionBuilder_SetAppName(builder, "appName");
    OH_AVSession_AVMediaDescriptionBuilder_GenerateAVMediaDescription(builder, &ohMediaDescription);
    OH_AVSession_AVMediaDescription_GetAssetId(ohMediaDescription, &g_assetId);
    OH_AVSession_AVMediaDescription_GetTitle(ohMediaDescription, &g_title);
    OH_AVSession_AVMediaDescription_GetSubtitle(ohMediaDescription, &g_subtitle);
    OH_AVSession_AVMediaDescription_GetArtist(ohMediaDescription, &g_artist);
    OH_AVSession_AVMediaDescription_GetAlbumCoverUri(ohMediaDescription, &g_albumCoverUri);
    OH_AVSession_AVMediaDescription_GetMediaType(ohMediaDescription, &g_mediaType);
    OH_AVSession_AVMediaDescription_GetLyricContent(ohMediaDescription, &g_lyricContent);
    OH_AVSession_AVMediaDescription_GetDuration(ohMediaDescription, &g_duration);
    OH_AVSession_AVMediaDescription_GetMediaUri(ohMediaDescription, &g_mediaUri);
    OH_AVSession_AVMediaDescription_GetStartPosition(ohMediaDescription, &g_startPosition);
    OH_AVSession_AVMediaDescription_GetMediaSize(ohMediaDescription, &g_mediaSize);
    OH_AVSession_AVMediaDescription_GetAlbumTitle(ohMediaDescription, &g_albumTitle);
    OH_AVSession_AVMediaDescription_GetAppName(ohMediaDescription, &g_appName);
    EXPECT_STREQ(g_assetId, "assetId");
    EXPECT_STREQ(g_title, "title");
    EXPECT_STREQ(g_subtitle, "subtitle");
    EXPECT_STREQ(g_artist, "artist");
    EXPECT_STREQ(g_albumCoverUri, "albumCoverUri");
    EXPECT_STREQ(g_mediaType, "mediaType");
    EXPECT_STREQ(g_lyricContent, "lyricContent");
    EXPECT_EQ(g_duration, DURATION);
    EXPECT_STREQ(g_mediaUri, "mediaUri");
    EXPECT_EQ(g_startPosition, 100);
    EXPECT_EQ(g_mediaSize, 1000);
    EXPECT_STREQ(g_albumTitle, "albumTitle");
    EXPECT_STREQ(g_appName, "appName");
    OH_AVSession_AVMediaDescriptionBuilder_Destroy(builder);
    OH_AVSession_AVMediaDescription_Destroy(ohMediaDescription);
}
}   // namespace OHOS::AVSession