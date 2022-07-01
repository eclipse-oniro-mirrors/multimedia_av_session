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
#include "avmeta_data.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "av_session.h"
#include "avsession_errors.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::Media;

static AVMetaData g_metaDataCloneTest;
static AVMetaData g_metaData;
static OHOS::Parcel g_parcel;
constexpr int64_t DURATION = 40000;
constexpr int64_t DURATION_PLAYBACK_SCENE_LIVE = -1;
constexpr int64_t DURATION_PLAYBACK_SCENE_INVALID = -2;
constexpr double PUBLISHDATE = 886291200000;
constexpr double PUBLISHDATE_INVALID_DATE = -1;
static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";

class AVMetaDataTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AVSession> avsession_ = nullptr;
};

void AVMetaDataTest::SetUpTestCase()
{
}

void AVMetaDataTest::TearDownTestCase()
{
}

void AVMetaDataTest::SetUp()
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
        return;
    }
    void *buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        return;
    }
    char *ch = reinterpret_cast<char *>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = (char)i;
    }

    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(DURATION);
    g_metaData.SetMediaImage(pixelMap);
    g_metaData.SetMediaImageUri("https://baidu.yinyue.com");
    g_metaData.SetPublishDate(PUBLISHDATE);
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("https://baidu.yinyue.com");

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    avsession_ = AVSessionManager::CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    EXPECT_EQ(avsession_->SetAVMetaData(g_metaData), AVSESSION_SUCCESS);
}

void AVMetaDataTest::TearDown()
{
    if (avsession_ != nullptr) {
        ASSERT_EQ(AVSESSION_SUCCESS, avsession_->Destroy());
    }
}

/**
* @tc.name: SetAVMetaData001
* @tc.desc: set av meta data
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, SetAVMetaData001, TestSize.Level1)
{
    SLOGE("SetAVMetaData001 Begin");
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
        return;
    }
    void *buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        return;
    }
    char *ch = reinterpret_cast<char *>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = (char)i;
    }

    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);

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
    metaData.SetMediaImage(pixelMap);
    metaData.SetMediaImageUri("https://baidu.yinyue.com");
    metaData.SetPublishDate(PUBLISHDATE);
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("https://baidu.yinyue.com");
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    SLOGE("SetAVMetaData001 End");
}

/**
* @tc.name: SetAVMetaData002
* @tc.desc: set av meta data boundary duration
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, SetAVMetaData002, TestSize.Level1)
{
    SLOGE("SetAVMetaData002 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetDuration(DURATION_PLAYBACK_SCENE_LIVE);

    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    SLOGE("SetAVMetaData002 End");
}

/**
* @tc.name: SetAVMetaData003
* @tc.desc: set av meta data error duration
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, SetAVMetaData003, TestSize.Level1)
{
    SLOGE("SetAVMetaData003 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetDuration(DURATION_PLAYBACK_SCENE_INVALID);

    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    SLOGE("SetAVMetaData003 End");
}

/**
* @tc.name: SetAVMetaData004
* @tc.desc: set av meta data error publish date
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, SetAVMetaData004, TestSize.Level1)
{
    SLOGE("SetAVMetaData004 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetPublishDate(PUBLISHDATE_INVALID_DATE);

    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    SLOGE("SetAVMetaData004 End");
}
/**
* @tc.name: GetAVMetaData001
* @tc.desc: get av meta data result
* @tc.type: FUNC
* @tc.require: AR000H31JO
*/
HWTEST_F(AVMetaDataTest, GetAVMetaData001, TestSize.Level1)
{
    SLOGE("GetAVMetaData001 Begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.CopyFrom(g_metaData);
    EXPECT_EQ(metaData.GetAssetId(), g_metaData.GetAssetId());
    std::string title1 = metaData.GetTitle();
    SLOGE("title1 %{public}s", title1.c_str());
    std::string title2 = g_metaData.GetTitle();
    SLOGE("title2 %{public}s", title2.c_str());
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
    SLOGE("GetAVMetaData001 End");
}

/**
 * @tc.name: AVMetaDataMarshalling001
 * @tc.desc: metadata marshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataMarshalling001, TestSize.Level1)
{
    SLOGI("AVMetaDataMarshalling001 end");
    OHOS::Parcel& parcel = g_parcel;
    auto ret = g_metaData.Marshalling(parcel);
    EXPECT_EQ(ret, true);
    SLOGI("AVMetaDataMarshalling001 end");
}

/**
 * @tc.name: AVMetaDataUnmarshalling001
 * @tc.desc: metadata unmarshalling test
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataUnmarshalling001, TestSize.Level1)
{
    SLOGI("AVMetaDataUnmarshalling001 begin");
    OHOS::Parcel& parcel = g_parcel;
    auto unmarshallingPtr = g_metaData.Unmarshalling(parcel);
    EXPECT_NE(unmarshallingPtr, nullptr);
    SLOGI("AVMetaDataUnmarshalling001 end");
}

/**
 * @tc.name: AVMetaDataGetMask001
 * @tc.desc: get meta mask
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataGetMask001, TestSize.Level1)
{
    SLOGI("AVMetaDataGetMask001 begin");
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    EXPECT_NE(metaData.GetMetaMask().to_string(), "");
    SLOGI("AVMetaDataGetMask001 end");
}

/**
 * @tc.name: AVMetaDataCopyDataFrom001
 * @tc.desc: copy meta item from @metaIn according to set bit of @metaIn meta mask
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataCopyDataFromMetaIn001, TestSize.Level1)
{
    SLOGI("AVMetaDataCopyDataFromMetaIn001 begin");
    AVMetaData metaData;
    g_metaDataCloneTest.SetAssetId("1118");
    g_metaDataCloneTest.SetWriter("Jay Chou");
    g_metaDataCloneTest.SetDuration(DURATION);
    auto ret = metaData.CopyFrom(g_metaDataCloneTest);
    EXPECT_EQ(ret, true);
    SLOGI("AVMetaDataCopyDataFromMetaIn001 end");
}

/**
 * @tc.name: AVMetaDataCopyDataByMask001
 * @tc.desc: copy meta item to @metaOut according to intersection of meta mask.
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST_F(AVMetaDataTest, AVMetaDataCopyDataByMask001, TestSize.Level1)
{
    SLOGI("AVMetaDataCopyDataByMask001 begin");
    AVMetaData metaOut;
    metaOut.SetAssetId("a");
    metaOut.SetWriter("b");
    metaOut.SetDuration(0);
    AVMetaData::MetaMaskType mask = metaOut.GetMetaMask();
    g_metaDataCloneTest.CopyToByMask(mask, metaOut);
    EXPECT_EQ(metaOut.GetAssetId(), g_metaDataCloneTest.GetAssetId());
    EXPECT_EQ(metaOut.GetWriter(), g_metaDataCloneTest.GetWriter());
    EXPECT_EQ(metaOut.GetDuration(), g_metaDataCloneTest.GetDuration());
    SLOGI("AVMetaDataCopyDataByMask001 end");
}