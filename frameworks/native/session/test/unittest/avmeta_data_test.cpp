/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "avmeta_data.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "av_session.h"
#include "avsession_errors.h"
#include "avsession_pixel_map_adapter.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace AVSession {
namespace {
    constexpr int64_t DURATION = 40000;
    constexpr int64_t DURATION_PLAYBACK_SCENE_LIVE = -1;
    constexpr int64_t DURATION_PLAYBACK_SCENE_INVALID = -2;
    constexpr double PUBLISHDATE = 886291200000;
    constexpr double PUBLISHDATE_INVALID_DATE = -1;
}

static AVMetaData g_metaDataCloneTest;
static AVMetaData g_metaData;
static OHOS::Parcel g_parcel;

class AVMetaDataTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<OHOS::Media::PixelMap> CreatePixelMap();
};

void AVMetaDataTest::SetUpTestCase()
{
}

void AVMetaDataTest::TearDownTestCase()
{
}

void AVMetaDataTest::SetUp()
{
    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(DURATION);
    g_metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    g_metaData.SetMediaImageUri("xxxxx");
    g_metaData.SetPublishDate(PUBLISHDATE);
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("xxxxx");
}

void AVMetaDataTest::TearDown()
{
}

std::shared_ptr<OHOS::Media::PixelMap> AVMetaDataTest::CreatePixelMap()
{
    int32_t pixelMapWidth = 4;
    int32_t pixelMapHeight = 3;
    const std::shared_ptr<OHOS::Media::PixelMap>& pixelMap = std::make_shared<OHOS::Media::PixelMap>();
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

/**
* @tc.name: SetAVMetaData001
* @tc.desc: set av meta data
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, SetAVMetaData001, TestSize.Level0)
{
    SLOGI("SetAVMetaData001 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    SLOGI("SetAVMetaData001 End");
}

/**
* @tc.name: SetAVMetaData002
* @tc.desc: set av meta data boundary duration
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, SetAVMetaData002, TestSize.Level0)
{
    SLOGI("SetAVMetaData002 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetDuration(DURATION_PLAYBACK_SCENE_LIVE);
    EXPECT_EQ(DURATION_PLAYBACK_SCENE_LIVE, metaData.GetDuration());
    SLOGI("SetAVMetaData002 End");
}

/**
* @tc.name: SetAVMetaData003
* @tc.desc: set av meta data error duration
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, SetAVMetaData003, TestSize.Level0)
{
    SLOGI("SetAVMetaData003 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetDuration(DURATION_PLAYBACK_SCENE_INVALID);
    EXPECT_EQ(DURATION_PLAYBACK_SCENE_INVALID, metaData.GetDuration());
    SLOGI("SetAVMetaData003 End");
}

/**
* @tc.name: SetAVMetaData004
* @tc.desc: set av meta data error publish date
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, SetAVMetaData004, TestSize.Level0)
{
    SLOGI("SetAVMetaData004 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetPublishDate(PUBLISHDATE_INVALID_DATE);
    EXPECT_EQ(PUBLISHDATE_INVALID_DATE, metaData.GetPublishDate());
    SLOGI("SetAVMetaData004 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test001, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test001 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    EXPECT_EQ("111", metaData.GetAssetId());

    SLOGI("SetAVMetaData_sequence_test001 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test002, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test002 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetTitle("Black Myth");
    EXPECT_EQ("Black Myth", metaData.GetTitle());

    SLOGI("SetAVMetaData_sequence_test002 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test003, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test003 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetArtist("zhoujielun1");
    EXPECT_EQ("zhoujielun1", metaData.GetArtist());

    SLOGI("SetAVMetaData_sequence_test003 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test004, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test004 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAuthor("zhoujielun1");
    EXPECT_EQ("zhoujielun1", metaData.GetAuthor());

    SLOGI("SetAVMetaData_sequence_test004 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test005, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test005 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAlbum("Jay1");
    EXPECT_EQ("Jay1", metaData.GetAlbum());

    SLOGI("SetAVMetaData_sequence_test005 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test006, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test006 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetWriter("zhoujielun");
    EXPECT_EQ("zhoujielun", metaData.GetWriter());

    SLOGI("SetAVMetaData_sequence_test006 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test007, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test007 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetComposer("zhoujielun1");
    EXPECT_EQ("zhoujielun1", metaData.GetComposer());

    SLOGI("SetAVMetaData_sequence_test007 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test008, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test008 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    int64_t DURATION1 = 60000;
    metaData.SetDuration(DURATION1);
    EXPECT_EQ(DURATION1, metaData.GetDuration());

    SLOGI("SetAVMetaData_sequence_test008 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test009, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test009 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetMediaImageUri("xxxxx_new");
    EXPECT_NE(nullptr, metaData.GetMediaImage());

    SLOGI("SetAVMetaData_sequence_test009 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test010, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test010 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    SLOGI("SetAVMetaData_sequence_test010 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test011, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test011 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetSubTitle("fac1");
    EXPECT_EQ("fac1", metaData.GetSubTitle());

    SLOGI("SetAVMetaData_sequence_test011 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test012, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test012 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetDescription("for friends1");
    EXPECT_EQ("for friends1", metaData.GetDescription());

    SLOGI("SetAVMetaData_sequence_test012 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test013, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test013 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetLyric("xxxxx_new");
    EXPECT_EQ("xxxxx_new", metaData.GetLyric());

    SLOGI("SetAVMetaData_sequence_test013 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test014, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test014 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetPublishDate(PUBLISHDATE_INVALID_DATE);
    EXPECT_EQ(PUBLISHDATE_INVALID_DATE, metaData.GetPublishDate());

    SLOGI("SetAVMetaData_sequence_test014 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test015, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test015 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("1234");
    metaData.SetTitle("Black Humor1");
    EXPECT_EQ("Black Humor1", metaData.GetTitle());

    SLOGI("SetAVMetaData_sequence_test015 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test016, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test016 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("1234");
    metaData.SetArtist("zhoujielun1");
    EXPECT_EQ("zhoujielun1", metaData.GetArtist());

    SLOGI("SetAVMetaData_sequence_test016 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test017, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test017 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetAuthor("zhoujielun1");
    EXPECT_EQ("zhoujielun1", metaData.GetAuthor());

    SLOGI("SetAVMetaData_sequence_test017 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test018, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test018 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetAlbum("Jay1");
    EXPECT_EQ("Jay1", metaData.GetAlbum());

    SLOGI("SetAVMetaData_sequence_test018 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test019, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test019 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetWriter("zhoujielun1");
    EXPECT_EQ("zhoujielun1", metaData.GetWriter());

    SLOGI("SetAVMetaData_sequence_test019 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test020, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test020 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetComposer("zhoujielun1");
    EXPECT_EQ("zhoujielun1", metaData.GetComposer());

    SLOGI("SetAVMetaData_sequence_test020 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test021, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test021 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    int64_t DURATION1 = 60000;
    metaData.SetDuration(DURATION1);
    EXPECT_EQ(DURATION1, metaData.GetDuration());

    SLOGI("SetAVMetaData_sequence_test021 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test022, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test022 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetMediaImageUri("xxxxx_new");
    EXPECT_EQ("xxxxx_new", metaData.GetMediaImageUri());

    SLOGI("SetAVMetaData_sequence_test022 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test023, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test023 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetPublishDate(PUBLISHDATE_INVALID_DATE);
    EXPECT_EQ(PUBLISHDATE_INVALID_DATE, metaData.GetPublishDate());

    SLOGI("SetAVMetaData_sequence_test023 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test024, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test024 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetSubTitle("fac1");
    EXPECT_EQ("fac1", metaData.GetSubTitle());

    SLOGI("SetAVMetaData_sequence_test024 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test025, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test025 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetDescription("for friends1");
    EXPECT_EQ("for friends1", metaData.GetDescription());

    SLOGI("SetAVMetaData_sequence_test025 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test026, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test026 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("111");
    metaData.SetLyric("xxxxx_new");
    EXPECT_EQ("xxxxx_new", metaData.GetLyric());

    SLOGI("SetAVMetaData_sequence_test026 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test027, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test027 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetArtist("zhoujielun1");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("zhoujielun1", metaData.GetArtist());

    SLOGI("SetAVMetaData_sequence_test027 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test028, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test028 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetAuthor("zhoujielun1");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("zhoujielun1", metaData.GetAuthor());

    SLOGI("SetAVMetaData_sequence_test028 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test029, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test029 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetWriter("zhoujielun1");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("zhoujielun1", metaData.GetWriter());

    SLOGI("SetAVMetaData_sequence_test029 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test030, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test030 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetComposer("zhoujielun1");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("zhoujielun1", metaData.GetComposer());

    SLOGI("SetAVMetaData_sequence_test030 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test031, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test031 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetAlbum("Jay1");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("Jay1", metaData.GetAlbum());

    SLOGI("SetAVMetaData_sequence_test031 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test032, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test032 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    int64_t DURATION1 = 60000;
    metaData.SetDuration(DURATION1);

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ(DURATION1, metaData.GetDuration());

    SLOGI("SetAVMetaData_sequence_test032 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test033, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test033 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetMediaImageUri("xxxxx_new");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("xxxxx_new", metaData.GetMediaImageUri());

    SLOGI("SetAVMetaData_sequence_test033 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test034, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test034 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetPublishDate(PUBLISHDATE_INVALID_DATE);

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ(PUBLISHDATE_INVALID_DATE, metaData.GetPublishDate());

    SLOGI("SetAVMetaData_sequence_test034 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test035, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test035 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetSubTitle("fac1");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("fac1", metaData.GetSubTitle());

    SLOGI("SetAVMetaData_sequence_test035 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test036, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test036 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetDescription("for friends1");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("for friends1", metaData.GetDescription());

    SLOGI("SetAVMetaData_sequence_test036 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test037, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test037 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetLyric("xxxxx_new");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("xxxxx_new", metaData.GetLyric());

    SLOGI("SetAVMetaData_sequence_test037 End");
}

/**
 * @tc.name: SetAVMetaData_sequence_test
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(AVMetaDataTest, SetAVMetaData_sequence_test038, TestSize.Level0)
{
    SLOGI("SetAVMetaData_sequence_test038 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(DURATION);
    metaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");

    EXPECT_EQ("123", metaData.GetAssetId());
    EXPECT_EQ("Black Humor", metaData.GetTitle());
    EXPECT_EQ("zhoujielun", metaData.GetArtist());
    EXPECT_EQ("zhoujielun", metaData.GetAuthor());
    EXPECT_EQ("Jay", metaData.GetAlbum());
    EXPECT_EQ("zhoujielun", metaData.GetWriter());
    EXPECT_EQ("zhoujielun", metaData.GetComposer());
    EXPECT_EQ("xxxxx", metaData.GetMediaImageUri());

    EXPECT_EQ(DURATION, metaData.GetDuration());
    EXPECT_EQ(PUBLISHDATE, metaData.GetPublishDate());

    EXPECT_NE(nullptr, metaData.GetMediaImage());

    EXPECT_EQ("fac", metaData.GetSubTitle());
    EXPECT_EQ("for friends", metaData.GetDescription());
    EXPECT_EQ("xxxxx", metaData.GetLyric());

    metaData.SetAssetId("112");
    metaData.SetTitle("Black Humor1");
    metaData.SetArtist("zhoujielun1");

    EXPECT_EQ("Black Humor1", metaData.GetTitle());
    EXPECT_EQ("zhoujielun1", metaData.GetArtist());

    SLOGI("SetAVMetaData_sequence_test038 End");
}

/**
* @tc.name: GetAVMetaData001
* @tc.desc: get av meta data result
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, GetAVMetaData001, TestSize.Level0)
{
    SLOGI("GetAVMetaData001 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.CopyFrom(g_metaData);
    EXPECT_EQ(metaData.GetAssetId(), g_metaData.GetAssetId());
    std::string title1 = metaData.GetTitle();
    SLOGI("title1 %{public}s", title1.c_str());
    std::string title2 = g_metaData.GetTitle();
    SLOGI("title2 %{public}s", title2.c_str());
    EXPECT_EQ(title1, title2);
    EXPECT_EQ(metaData.GetTitle(), g_metaData.GetTitle());
    EXPECT_EQ(metaData.GetArtist(), g_metaData.GetArtist());
    EXPECT_EQ(metaData.GetAuthor(), g_metaData.GetAuthor());
    EXPECT_EQ(metaData.GetAlbum(), g_metaData.GetAlbum());
    EXPECT_EQ(metaData.GetWriter(), g_metaData.GetWriter());
    EXPECT_EQ(metaData.GetComposer(), g_metaData.GetComposer());
    EXPECT_EQ(metaData.GetDuration(), g_metaData.GetDuration());
    EXPECT_EQ(metaData.GetMediaImage(), g_metaData.GetMediaImage());
    EXPECT_EQ(metaData.GetMediaImageUri(), g_metaData.GetMediaImageUri());
    EXPECT_EQ(metaData.GetPublishDate(), g_metaData.GetPublishDate());
    EXPECT_EQ(metaData.GetSubTitle(), g_metaData.GetSubTitle());
    EXPECT_EQ(metaData.GetDescription(), g_metaData.GetDescription());
    EXPECT_EQ(metaData.GetLyric(), g_metaData.GetLyric());
    SLOGI("GetAVMetaData001 End");
}

/**
 * @tc.name: AVMetaDataMarshalling001
 * @tc.desc: metadata marshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataMarshalling001, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshalling001 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto ret = g_metaData.Marshalling(parcel);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataMarshalling001 End");
}

/**
 * @tc.name: AVMetaDataMarshalling002
 * @tc.desc: metadata marshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataMarshalling002, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshalling002 Begin");
    OHOS::Parcel& parcel = g_parcel;
    g_metaData.SetAVQueueImage(nullptr);
    auto ret = g_metaData.Marshalling(parcel);
    EXPECT_EQ(ret, false);
    OHOS::MessageParcel& m_parcel = static_cast<MessageParcel&>(g_parcel);
    g_metaData.WriteDrmSchemes(m_parcel);
    g_metaData.ReadDrmSchemes(m_parcel);
    SLOGI("AVMetaDataMarshalling002 End");
}

/**
 * @tc.name: AVMetaDataMarshalling003
 * @tc.desc: metadata marshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataMarshalling003, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshalling003 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    g_metaData.SetAVQueueImage(pixelMap);
    auto ret = g_metaData.Marshalling(parcel);
    EXPECT_EQ(ret, false);
    OHOS::MessageParcel& m_parcel = static_cast<MessageParcel&>(g_parcel);
    g_metaData.WriteDrmSchemes(m_parcel);
    g_metaData.ReadDrmSchemes(m_parcel);
    SLOGI("AVMetaDataMarshalling002 End");
}

/**
 * @tc.name: AVMetaDataMarshalling004
 * @tc.desc: metadata marshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataMarshalling004, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshalling004 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(vec);
    g_metaData.SetMediaImage(pixelMap);
    g_metaData.SetAVQueueImage(pixelMap);
    auto ret = g_metaData.Marshalling(parcel);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataMarshalling004 End");
}

/**
 * @tc.name: AVMetaDataMarshalling005
 * @tc.desc: metadata marshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataMarshalling005, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshalling005 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(vec);
    g_metaData.SetMediaImage(pixelMap);
    g_metaData.SetAVQueueImage(nullptr);
    auto ret = g_metaData.Marshalling(parcel);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataMarshalling005 End");
}

/**
 * @tc.name: AVMetaDataMarshalling006
 * @tc.desc: metadata marshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataMarshalling006, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshalling006 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(vec);
    g_metaData.SetMediaImage(nullptr);
    g_metaData.SetAVQueueImage(pixelMap);
    auto ret = g_metaData.Marshalling(parcel);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataMarshalling006 End");
}

/**
 * @tc.name: AVMetaDataUnmarshalling001
 * @tc.desc: metadata unmarshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataUnmarshalling001, TestSize.Level0)
{
    SLOGI("AVMetaDataUnmarshalling001 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto unmarshallingPtr = g_metaData.Unmarshalling(parcel);
    EXPECT_NE(unmarshallingPtr, nullptr);
    SLOGI("AVMetaDataUnmarshalling001 End");
}

/**
 * @tc.name: AVMetaDataReadFromParcel001
 * @tc.desc: metadata ReadFromParcel test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataReadFromParcel001, TestSize.Level0)
{
    SLOGI("AVMetaDataReadFromParcel001 Begin");
    OHOS::MessageParcel& parcel = static_cast<MessageParcel&>(g_parcel);
    int32_t twoImageLength = 10;
    g_metaData.SetMediaLength(5);
    bool ret = g_metaData.ReadFromParcel(parcel, twoImageLength);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataReadFromParcel001 End");
}

/**
 * @tc.name: AVMetaDataReadFromParcel002
 * @tc.desc: metadata ReadFromParcel test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataReadFromParcel002, TestSize.Level0)
{
    SLOGI("AVMetaDataReadFromParcel002 Begin");
    OHOS::MessageParcel& parcel = static_cast<MessageParcel&>(g_parcel);
    int32_t twoImageLength = 10;
    g_metaData.SetMediaLength(10);
    bool ret = g_metaData.ReadFromParcel(parcel, twoImageLength);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataReadFromParcel002 End");
}

/**
 * @tc.name: AVMetaDataGetMask001
 * @tc.desc: get meta mask
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataGetMask001, TestSize.Level0)
{
    SLOGI("AVMetaDataGetMask001 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    EXPECT_NE(metaData.GetMetaMask().to_string(), "");
    SLOGI("AVMetaDataGetMask001 End");
}

/**
 * @tc.name: AVMetaDataCopyDataFrom001
 * @tc.desc: copy meta item from @metaIn according to set bit of @metaIn meta mask
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataCopyDataFromMetaIn001, TestSize.Level0)
{
    SLOGI("AVMetaDataCopyDataFromMetaIn001 Begin");
    AVMetaData metaData;
    g_metaDataCloneTest.SetAssetId("1118");
    g_metaDataCloneTest.SetWriter("Jay Chou");
    g_metaDataCloneTest.SetDuration(DURATION);
    auto ret = metaData.CopyFrom(g_metaDataCloneTest);

    EXPECT_EQ(ret, true);
    EXPECT_EQ(metaData.GetAssetId(), g_metaDataCloneTest.GetAssetId());
    EXPECT_EQ(metaData.GetWriter(), g_metaDataCloneTest.GetWriter());
    EXPECT_EQ(metaData.GetDuration(), g_metaDataCloneTest.GetDuration());
    SLOGI("AVMetaDataCopyDataFromMetaIn001 End");
}

/**
 * @tc.name: AVMetaDataCopyDataByMask001
 * @tc.desc: copy meta item to @metaOut according to intersection of meta mask.
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataCopyDataByMask001, TestSize.Level0)
{
    SLOGI("AVMetaDataCopyDataByMask001 Begin");
    AVMetaData metaOut;
    metaOut.SetAssetId("a");
    metaOut.SetWriter("b");
    metaOut.SetDuration(0);
    AVMetaData::MetaMaskType mask = metaOut.GetMetaMask();

    auto ret = g_metaDataCloneTest.CopyToByMask(mask, metaOut);
    EXPECT_EQ(ret, true);

    EXPECT_EQ(metaOut.GetAssetId(), g_metaDataCloneTest.GetAssetId());
    EXPECT_EQ(metaOut.GetWriter(), g_metaDataCloneTest.GetWriter());
    EXPECT_EQ(metaOut.GetDuration(), g_metaDataCloneTest.GetDuration());
    SLOGI("AVMetaDataCopyDataByMask001 End");
}

/**
 * @tc.name: AVMetaDataGetChangedDataMask001
 * @tc.desc: get changed data mask.
 * @tc.type: FUNC
 * @tc.require: 1810
 */
HWTEST_F(AVMetaDataTest, AVMetaDataGetChangedDataMask001, TestSize.Level4)
{
    SLOGI("AVMetaDataCopyChangeDataToByMask001 Begin");
    AVMetaData newData;
    newData.SetAssetId("a");
    newData.SetWriter("b");
    newData.SetDuration(1);

    g_metaDataCloneTest.SetAssetId("1118");
    g_metaDataCloneTest.SetWriter("Jay Chou");
    g_metaDataCloneTest.SetDuration(1);
    AVMetaData metaOut;
    AVMetaData::MetaMaskType mask = newData.GetMetaMask();

    auto changedMask = g_metaDataCloneTest.GetChangedDataMask(mask, newData);
    EXPECT_EQ(changedMask.test(AVMetaData::META_KEY_ASSET_ID), true);
    EXPECT_EQ(changedMask.test(AVMetaData::META_KEY_WRITER), true);
    EXPECT_EQ(changedMask.test(AVMetaData::META_KEY_DURATION), false);
    SLOGI("AVMetaDataGetChangedDataMask001 End");
}

/**
 * @tc.name: SetPreviousAssetId001
 * @tc.desc: set previous asset id.
 * @tc.type: FUNC
 * @tc.require: I5YMXD
 */
HWTEST_F(AVMetaDataTest, SetPreviousAssetId001, TestSize.Level0)
{
    SLOGI("SetPreviousAssetId001 Begin");
    AVMetaData metaOut;
    metaOut.SetPreviousAssetId("123");

    EXPECT_EQ("123", metaOut.GetPreviousAssetId());
    SLOGI("SetPreviousAssetId001 End");
}

/**
 * @tc.name: SetNextAssetId001
 * @tc.desc: set next asset id.
 * @tc.type: FUNC
 * @tc.require: I5YMXD
 */
HWTEST_F(AVMetaDataTest, SetNextAssetId001, TestSize.Level0)
{
    SLOGI("SetNextAssetId001 Begin");
    AVMetaData metaOut;
    metaOut.SetNextAssetId("123");

    EXPECT_EQ("123", metaOut.GetNextAssetId());
    SLOGI("SetNextAssetId001 End");
}

/**
* @tc.name: IsValid001
* @tc.desc: Return is avmetadata IsValid success
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVMetaDataTest, IsValid001, TestSize.Level0)
{
    SLOGI("IsValid001 Begin");
    AVMetaData metaOut;
    metaOut.SetAssetId("a");
    metaOut.SetWriter("b");
    metaOut.SetDuration(0);
    metaOut.SetPublishDate(0);

    EXPECT_EQ(metaOut.IsValid(), true);
    SLOGI("IsValid001 End");
}

/**
* @tc.name: IsValid002
* @tc.desc: Return is avmetadata IsValid failed
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVMetaDataTest, IsValid002, TestSize.Level0)
{
    SLOGI("IsValid002 Begin");
    AVMetaData metaOut;
    metaOut.SetAssetId("a");
    metaOut.SetWriter("b");
    metaOut.SetDuration(-2);
    metaOut.SetPublishDate(0);

    EXPECT_EQ(metaOut.IsValid(), false);
    SLOGI("IsValid002 End");
}

/**
* @tc.name: UnmarshallingExceptImg001
* @tc.desc: the size of string is zero
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVMetaDataTest, UnmarshallingExceptImg001, TestSize.Level0)
{
    MessageParcel data;
    data.WriteString("");
    AVMetaData metaOut;
    bool ret = metaOut.UnmarshallingExceptImg(data);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: UnmarshallingExceptImg002
* @tc.desc: the size of string bigger than META_KEY_MAX
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVMetaDataTest, UnmarshallingExceptImg002, TestSize.Level0)
{
    std::string test = std::string(30, '*');
    MessageParcel data;
    data.WriteString(test);
    AVMetaData metaOut;
    bool ret = metaOut.UnmarshallingExceptImg(data);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: UnmarshallingExceptImg003
* @tc.desc: the size of string is valid but metaOut.metaMask_ is empty
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVMetaDataTest, UnmarshallingExceptImg003, TestSize.Level0)
{
    std::string test = "test1111";
    MessageParcel data;
    data.WriteString(test);
    OHOS::sptr pixelMap = new AVSessionPixelMap();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(vec);
    data.WriteParcelable(pixelMap);
    AVMetaData metaOut;
    bool ret = metaOut.UnmarshallingExceptImg(data);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: UnmarshallingExceptImg004
* @tc.desc: the size of string is valid but metaOut.bundleIcon_ is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVMetaDataTest, UnmarshallingExceptImg004, TestSize.Level0)
{
    std::string test = "test1111";
    MessageParcel data;
    data.WriteString(test);
    AVMetaData metaOut;
    std::string bitStr = std::string(26, '1');
    std::bitset<26> bits(bitStr);
    metaOut.metaMask_ = bits;
    bool ret = metaOut.UnmarshallingExceptImg(data);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: UnmarshallingExceptImg005
* @tc.desc: the size of string is valid and metaOut is valid
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVMetaDataTest, UnmarshallingExceptImg005, TestSize.Level0)
{
    std::string test = "test1111";
    MessageParcel data;
    data.WriteString(test);
    OHOS::sptr pixelMap = new AVSessionPixelMap();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(vec);
    data.WriteParcelable(pixelMap);
    AVMetaData metaOut;
    std::string bitStr = std::string(26, '1');
    std::bitset<26> bits(bitStr);
    metaOut.metaMask_ = bits;
    bool ret = metaOut.UnmarshallingExceptImg(data);
    EXPECT_TRUE(ret != false);
}

/**
 * @tc.name: AVMetaDataCheckMediaImageChange001
 * @tc.desc: Test CheckMediaImageChange function
 * @tc.type: FUNC
 * @tc.require: 1810
 */
HWTEST_F(AVMetaDataTest, AVMetaDataCheckMediaImageChange001, TestSize.Level4)
{
    SLOGI("AVMetaDataCheckMediaImageChange001 Begin");
    AVMetaData newData;
    newData.SetAssetId("a");
    newData.SetWriter("b");
    newData.SetMediaImage(nullptr);
    AVMetaData oldData;
    oldData.SetAssetId("a");
    oldData.SetWriter("b");
    oldData.SetMediaImage(nullptr);
    bool ret = AVMetaData::CheckMediaImageChange(newData, oldData);
    EXPECT_EQ(ret, false);

    std::shared_ptr<AVSessionPixelMap> pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(vec);
    newData.SetMediaImage(pixelMap);
    ret = AVMetaData::CheckMediaImageChange(newData, oldData);
    EXPECT_EQ(ret, true);

    ret = AVMetaData::CheckMediaImageChange(oldData, newData);
    EXPECT_EQ(ret, true);

    oldData.SetMediaImage(pixelMap);
    ret = AVMetaData::CheckMediaImageChange(oldData, newData);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataCheckMediaImageChange001 End");
}

/**
 * @tc.name: AVMetaDataCheckAVQueueIdChange001
 * @tc.desc: Test CheckAVQueueIdChange function
 * @tc.type: FUNC
 * @tc.require: 1810
 */
HWTEST_F(AVMetaDataTest, AVMetaDataCheckAVQueueImageChange001, TestSize.Level4)
{
    SLOGI("AVMetaDataCheckAVQueueImageChange001 Begin");
    AVMetaData newData;
    newData.SetAssetId("a");
    newData.SetWriter("b");
    newData.SetAVQueueImage(nullptr);
    AVMetaData oldData;
    oldData.SetAssetId("a");
    oldData.SetWriter("b");
    oldData.SetAVQueueImage(nullptr);
    bool ret = AVMetaData::CheckAVQueueImageChange(newData, oldData);
    EXPECT_EQ(ret, false);

    std::shared_ptr<AVSessionPixelMap> pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(vec);
    newData.SetAVQueueImage(pixelMap);
    ret = AVMetaData::CheckAVQueueImageChange(newData, oldData);
    EXPECT_EQ(ret, true);

    ret = AVMetaData::CheckAVQueueImageChange(oldData, newData);
    EXPECT_EQ(ret, true);

    oldData.SetAVQueueImage(pixelMap);
    ret = AVMetaData::CheckAVQueueImageChange(oldData, newData);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataCheckAVQueueImageChange001 End");
}

/**
 * @tc.name: AVMetaDataCheckBundleIconChange001
 * @tc.desc: Test CheckBundleIconChange function
 * @tc.type: FUNC
 * @tc.require: 1810
 */
HWTEST_F(AVMetaDataTest, AVMetaDataCheckBundleIconChange001, TestSize.Level4)
{
    SLOGI("AVMetaDataCheckBundleIconChange001 Begin");
    AVMetaData newData;
    newData.SetAssetId("a");
    newData.SetWriter("b");
    newData.SetBundleIcon(nullptr);
    AVMetaData oldData;
    oldData.SetAssetId("a");
    oldData.SetWriter("b");
    oldData.SetBundleIcon(nullptr);
    bool ret = AVMetaData::CheckBundleIconChange(newData, oldData);
    EXPECT_EQ(ret, false);

    std::shared_ptr<AVSessionPixelMap> pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> vec = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(vec);
    newData.SetBundleIcon(pixelMap);
    ret = AVMetaData::CheckBundleIconChange(newData, oldData);
    EXPECT_EQ(ret, true);

    ret = AVMetaData::CheckBundleIconChange(oldData, newData);
    EXPECT_EQ(ret, true);

    oldData.SetBundleIcon(pixelMap);
    ret = AVMetaData::CheckBundleIconChange(oldData, newData);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataCheckBundleIconChange001 End");
}
} // namespace AVSession
} // namespace OHOS