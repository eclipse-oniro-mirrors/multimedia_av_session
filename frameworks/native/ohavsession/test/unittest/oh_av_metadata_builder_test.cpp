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
#include "OHAVMetadataBuilder.h"
#include "avmeta_data.h"
#include "avsession_log.h"

using namespace testing::ext;

namespace OHOS::AVSession {
static OHAVMetadataBuilder g_ohAVMetaDataBuilder;
constexpr int DURATION = 40000;
constexpr int TAGS = 1;

class OHAVMetadataBuilderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void OHAVMetadataBuilderTest::SetUpTestCase()
{
}

void OHAVMetadataBuilderTest::TearDownTestCase()
{
}

void OHAVMetadataBuilderTest::SetUp()
{
}

void OHAVMetadataBuilderTest::TearDown()
{
}

/**
 * @tc.name: SetAVMetaData001
 * @tc.desc: set av meta data by class
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVMetadataBuilderTest, SetAVMetaData001, TestSize.Level0)
{
    SLOGI("SetAVMetaData001 Begin");
    AVMetaData* metadata;
    OH_AVMetadata* ohMetadata;
    g_ohAVMetaDataBuilder.SetTitle("UNIT TEST");
    g_ohAVMetaDataBuilder.SetArtist("Anonymous artist");
    g_ohAVMetaDataBuilder.SetAuthor("Anonymous author");
    g_ohAVMetaDataBuilder.SetAlbum("Anonymous album");
    g_ohAVMetaDataBuilder.SetWriter("Anonymous writer");
    g_ohAVMetaDataBuilder.SetComposer("Anonymous composer");
    g_ohAVMetaDataBuilder.SetDuration(DURATION);
    g_ohAVMetaDataBuilder.SetMediaImageUri("https://xxx.xxx.xx");
    g_ohAVMetaDataBuilder.SetSubtitle("fac");
    g_ohAVMetaDataBuilder.SetDescription("For somebody");
    g_ohAVMetaDataBuilder.SetLyric("balabala");
    g_ohAVMetaDataBuilder.SetAssetId("000");
    g_ohAVMetaDataBuilder.SetSkipIntervals(SECONDS_30);
    g_ohAVMetaDataBuilder.SetDisplayTags(TAGS);
    g_ohAVMetaDataBuilder.SetFilter(2);

    g_ohAVMetaDataBuilder.GenerateAVMetadata(&ohMetadata);

    metadata = reinterpret_cast<AVMetaData*>(ohMetadata);
    EXPECT_EQ(metadata->GetTitle(), "UNIT TEST");
    EXPECT_EQ(metadata->GetArtist(), "Anonymous artist");
    EXPECT_EQ(metadata->GetAuthor(), "Anonymous author");
    EXPECT_EQ(metadata->GetAlbum(), "Anonymous album");
    EXPECT_EQ(metadata->GetWriter(), "Anonymous writer");
    EXPECT_EQ(metadata->GetComposer(), "Anonymous composer");
    EXPECT_EQ(metadata->GetDuration(), DURATION);
    EXPECT_EQ(metadata->GetMediaImageUri(), "https://xxx.xxx.xx");
    EXPECT_EQ(metadata->GetSubTitle(), "fac");
    EXPECT_EQ(metadata->GetDescription(), "For somebody");
    EXPECT_EQ(metadata->GetLyric(), "balabala");
    EXPECT_EQ(metadata->GetAssetId(), "000");
    EXPECT_EQ(metadata->GetSkipIntervals(), SECONDS_30);
    EXPECT_EQ(metadata->GetDisplayTags(), TAGS);
    EXPECT_EQ(metadata->GetFilter(), 2);

    delete metadata;
    metadata = nullptr;
    SLOGI("SetAVMetaData001 End");
}

/**
 * @tc.name: SetAVMetaData002
 * @tc.desc: set av meta data
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVMetadataBuilderTest, SetAVMetaData002, TestSize.Level0)
{
    SLOGI("SetAVMetaData002 Begin");
    int ret = g_ohAVMetaDataBuilder.SetSkipIntervals((AVMetadata_SkipIntervals)(SECONDS_30 + 1));
    EXPECT_EQ(ret, AVMETADATA_ERROR_INVALID_PARAM);
    SLOGI("SetAVMetaData002 End");
}

/**
 * @tc.name: SetAVMetaData003
 * @tc.desc: set av meta data by func
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVMetadataBuilderTest, SetAVMetaData003, TestSize.Level0)
{
    SLOGI("SetAVMetaData001 Begin");
    AVMetaData* metadata;
    OH_AVMetadataBuilder* builder;
    OH_AVMetadata* ohMetadata;

    OH_AVMetadataBuilder_Create(&builder);

    OH_AVMetadataBuilder_SetTitle(builder, "UNIT TEST");
    OH_AVMetadataBuilder_SetArtist(builder, "Anonymous artist");
    OH_AVMetadataBuilder_SetAuthor(builder, "Anonymous author");
    OH_AVMetadataBuilder_SetAlbum(builder, "Anonymous album");
    OH_AVMetadataBuilder_SetWriter(builder, "Anonymous writer");
    OH_AVMetadataBuilder_SetComposer(builder, "Anonymous composer");
    OH_AVMetadataBuilder_SetDuration(builder, DURATION);
    OH_AVMetadataBuilder_SetMediaImageUri(builder, "https://xxx.xxx.xx");
    OH_AVMetadataBuilder_SetSubtitle(builder, "fac");
    OH_AVMetadataBuilder_SetDescription(builder, "For somebody");
    OH_AVMetadataBuilder_SetLyric(builder, "balabala");
    OH_AVMetadataBuilder_SetAssetId(builder, "000");
    OH_AVMetadataBuilder_SetSkipIntervals(builder, SECONDS_30);
    OH_AVMetadataBuilder_SetDisplayTags(builder, TAGS);
    OH_AVMetadataBuilder_SetFilter(builder, 2);
    OH_AVMetadataBuilder_GenerateAVMetadata(builder, &ohMetadata);

    metadata = reinterpret_cast<AVMetaData*>(ohMetadata);

    EXPECT_EQ(metadata->GetTitle(), "UNIT TEST");
    EXPECT_EQ(metadata->GetArtist(), "Anonymous artist");
    EXPECT_EQ(metadata->GetAuthor(), "Anonymous author");
    EXPECT_EQ(metadata->GetAlbum(), "Anonymous album");
    EXPECT_EQ(metadata->GetWriter(), "Anonymous writer");
    EXPECT_EQ(metadata->GetComposer(), "Anonymous composer");
    EXPECT_EQ(metadata->GetDuration(), DURATION);
    EXPECT_EQ(metadata->GetMediaImageUri(), "https://xxx.xxx.xx");
    EXPECT_EQ(metadata->GetSubTitle(), "fac");
    EXPECT_EQ(metadata->GetDescription(), "For somebody");
    EXPECT_EQ(metadata->GetLyric(), "balabala");
    EXPECT_EQ(metadata->GetAssetId(), "000");
    EXPECT_EQ(metadata->GetSkipIntervals(), SECONDS_30);
    EXPECT_EQ(metadata->GetDisplayTags(), TAGS);
    EXPECT_EQ(metadata->GetFilter(), 2);

    OH_AVMetadataBuilder_Destroy(builder);
    OH_AVMetadata_Destroy(ohMetadata);

    SLOGI("SetAVMetaData001 End");
}

/**
 * @tc.name: GenerateAVMetadata001
 * @tc.desc: test GenerateAVMetadata
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVMetadataBuilderTest, GenerateAVMetadata001, TestSize.Level0)
{
    SLOGI("GenerateAVMetadata001 Begin");
    AVMetadata_SkipIntervals intervals = SECONDS_10;
    AVMetadata_Result ret = g_ohAVMetaDataBuilder.SetSkipIntervals(intervals);
    EXPECT_EQ(ret, AVMETADATA_SUCCESS);

    std::shared_ptr<AVMetaData> metadata = std::make_shared<AVMetaData>();
    OH_AVMetadata* avMetadata = reinterpret_cast<OH_AVMetadata*>(metadata.get());
    OH_AVMetadata** ptr = &avMetadata;
    ret = g_ohAVMetaDataBuilder.GenerateAVMetadata(ptr);
    EXPECT_EQ(ret, AVMETADATA_SUCCESS);
    SLOGI("GenerateAVMetadata001 End");
}

/**
 * @tc.name: GenerateAVMetadata002
 * @tc.desc: test GenerateAVMetadata
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVMetadataBuilderTest, GenerateAVMetadata002, TestSize.Level0)
{
    SLOGI("GenerateAVMetadata002 Begin");
    AVMetadata_SkipIntervals intervals = SECONDS_15;
    AVMetadata_Result ret = g_ohAVMetaDataBuilder.SetSkipIntervals(intervals);
    EXPECT_EQ(ret, AVMETADATA_SUCCESS);

    std::shared_ptr<AVMetaData> metadata = std::make_shared<AVMetaData>();
    OH_AVMetadata* avMetadata = reinterpret_cast<OH_AVMetadata*>(metadata.get());
    OH_AVMetadata** ptr = &avMetadata;
    ret = g_ohAVMetaDataBuilder.GenerateAVMetadata(ptr);
    EXPECT_EQ(ret, AVMETADATA_SUCCESS);
    SLOGI("GenerateAVMetadata002 End");
}

/**
 * @tc.name: GenerateAVMetadata003
 * @tc.desc: test GenerateAVMetadata
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVMetadataBuilderTest, GenerateAVMetadata003, TestSize.Level0)
{
    SLOGI("GenerateAVMetadata003 Begin");
    AVMetadata_SkipIntervals intervals = SECONDS_30;
    AVMetadata_Result ret = g_ohAVMetaDataBuilder.SetSkipIntervals(intervals);
    EXPECT_EQ(ret, AVMETADATA_SUCCESS);

    std::shared_ptr<AVMetaData> metadata = std::make_shared<AVMetaData>();
    OH_AVMetadata* avMetadata = reinterpret_cast<OH_AVMetadata*>(metadata.get());
    OH_AVMetadata** ptr = &avMetadata;
    ret = g_ohAVMetaDataBuilder.GenerateAVMetadata(ptr);
    EXPECT_EQ(ret, AVMETADATA_SUCCESS);
    SLOGI("GenerateAVMetadata003 End");
}

/**
 * @tc.name: GenerateAVMetadata004
 * @tc.desc: test GenerateAVMetadata
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVMetadataBuilderTest, GenerateAVMetadata004, TestSize.Level0)
{
    SLOGI("GenerateAVMetadata004 Begin");
    AVMetadata_SkipIntervals intervals = static_cast<AVMetadata_SkipIntervals>(100);
    AVMetadata_Result ret = g_ohAVMetaDataBuilder.SetSkipIntervals(intervals);
    EXPECT_EQ(ret, AVMETADATA_ERROR_INVALID_PARAM);

    std::shared_ptr<AVMetaData> metadata = std::make_shared<AVMetaData>();
    OH_AVMetadata* avMetadata = reinterpret_cast<OH_AVMetadata*>(metadata.get());
    OH_AVMetadata** ptr = &avMetadata;
    ret = g_ohAVMetaDataBuilder.GenerateAVMetadata(ptr);
    EXPECT_EQ(ret, AVMETADATA_SUCCESS);
    SLOGI("GenerateAVMetadata004 End");
}

}  // namespace OHOS::AVSession