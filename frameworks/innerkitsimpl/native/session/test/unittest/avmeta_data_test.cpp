/*
 * Copyright (c) 2022 XXXX Device Co., Ltd.
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
#include "av_session.h"
#include "avsession_errors.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

AVMetaData g_metaDataCloneTest;
AVMetaData g_metaData;
OHOS::Parcel g_parcel;

class AVMetaDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<AVSession> avsession_ = nullptr;
};

void AVMetaDataTest::SetUpTestCase(void)
{

}

void AVMetaDataTest::TearDownTestCase(void)
{

}

void AVMetaDataTest::SetUp(void)
{
    g_metaData.Reset();
    g_metaData.SetAssetId("123");
    g_metaData.SetTitle("Black Humor");
    g_metaData.SetArtist("zhoujielun");
    g_metaData.SetAuthor("zhoujielun");
    g_metaData.SetAlbum("Jay");
    g_metaData.SetWriter("zhoujielun");
    g_metaData.SetComposer("zhoujielun");
    g_metaData.SetDuration(40000);
    g_metaData.SetMediaImageUri("https://baidu.yinyue.com");
    g_metaData.SetSubTitle("fac");
    g_metaData.SetDescription("for friends");
    g_metaData.SetLyric("https://baidu.yinyue.com");
    EXPECT_EQ(avsession_->SetAVMetaData(g_metaData), AVSESSION_SUCCESS);
}

void AVMetaDataTest::TearDown(void)
{
    if (avsession_ != nullptr) {
        ASSERT_EQ(AVSESSION_SUCCESS, avsession_->Release());
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
    AVMetaData metaData;
    metaData.Reset();

    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(40000);
    metaData.SetMediaImageUri("https://baidu.yinyue.com");
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("https://baidu.yinyue.com");
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    SLOGE("SetAVMetaData001 End");
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
    EXPECT_EQ(metaData.GetMediaImageUri(), g_metaData.GetMediaImageUri());
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
HWTEST(AVMetaDataTest, AVMetaDataMarshalling001, TestSize.Level1)
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
HWTEST(AVMetaDataTest, AVMetaDataUnmarshalling001, TestSize.Level1)
{
    SLOGI("AVMetaDataUnmarshalling001 begin");

    OHOS::Parcel& parcel = g_parcel;
    auto unmarshallingPtr = g_metaData.Unmarshalling(parcel);

    EXPECT_EQ(unmarshallingPtr, nullptr);

    SLOGI("AVMetaDataUnmarshalling001 end");
}

/**
 * @tc.name: AVMetaDataGetMask001
 * @tc.desc: get meta mask
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST(AVMetaDataTest, AVMetaDataGetMask001, TestSize.Level1)
{
    SLOGI("AVMetaDataGetMask001 begin");

    AVMetaData metaData;
    auto ret = metaData.GetMetaMask();


    EXPECT_EQ(g_metaData.GetMetaMask().to_string(), ret.to_string());

    SLOGI("AVMetaDataGetMask001 end");
}

/**
 * @tc.name: AVMetaDataCopyDataFrom001
 * @tc.desc: copy meta item from @metaIn according to set bit of @metaIn meta mask
 * @tc.type: FUNC
 * @tc.require:AR000H31JO
 */
HWTEST(AVMetaDataTest, AVMetaDataCopyDataFromMetaIn001, TestSize.Level1)
{
    SLOGI("AVMetaDataCopyDataFromMetaIn001 begin");

    AVMetaData metaData;

    g_metaDataCloneTest.SetAssetId("1118");
    g_metaDataCloneTest.SetWriter("Jay Chou");
    g_metaDataCloneTest.SetDuration(40000);

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
HWTEST(AVMetaDataTest, AVMetaDataCopyDataByMask001, TestSize.Level1)
{
    SLOGI("AVMetaDataCopyDataByMask001 begin");

    AVMetaData metaOut;
    metaOut.GetMetaMask().set(AVMetaData::META_KEY_ASSET_ID);
    metaOut.GetMetaMask().set(AVMetaData::META_KEY_WRITER);
    metaOut.GetMetaMask().set(AVMetaData::META_KEY_DURATION);
    AVMetaData::MetaMaskType mask = metaOut.GetMetaMask();
    metaOut.CopyToByMask(mask, metaOut);

    EXPECT_EQ(metaOut.GetAssetId(), g_metaDataCloneTest.GetAssetId());
    EXPECT_EQ(metaOut.GetWriter(), g_metaDataCloneTest.GetWriter());
    EXPECT_EQ(metaOut.GetDuration(), g_metaDataCloneTest.GetDuration());

    SLOGI("AVMetaDataCopyDataByMask001 end");
}
