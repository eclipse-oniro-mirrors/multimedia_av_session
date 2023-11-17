/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "avcall_meta_data.h"
#include "avsession_log.h"
#include "av_session.h"
#include "avsession_errors.h"
#include "avsession_pixel_map_adapter.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace AVSession {
static AVCallMetaData g_avcallMetaDataCloneTest;
static AVCallMetaData g_callMetaData;
static OHOS::Parcel g_parcel;

class AVCallMetaDataTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<OHOS::Media::PixelMap> CreatePixelMap();
};

void AVCallMetaDataTest::SetUpTestCase()
{
}

void AVCallMetaDataTest::TearDownTestCase()
{
}

void AVCallMetaDataTest::SetUp()
{
    g_callMetaData.Reset();
    g_callMetaData.SetName("xiaoming");
    g_callMetaData.SetPhoneNumber("123456789");
    g_callMetaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));
}

void AVCallMetaDataTest::TearDown()
{
}

std::shared_ptr<OHOS::Media::PixelMap> AVCallMetaDataTest::CreatePixelMap()
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
 * @tc.name: SetAVCallMetaData001
 * @tc.desc: set av call meta data
 * @tc.type: FUNC
 */
HWTEST_F(AVCallMetaDataTest, SetAVCallMetaData001, TestSize.Level1)
{
    SLOGI("SetAVCallMetaData001 Begin");
    AVCallMetaData avCallMetaData;
    avCallMetaData.Reset();
    avCallMetaData.SetName("xiaoming");
    avCallMetaData.SetPhoneNumber("123456789");
    avCallMetaData.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(CreatePixelMap()));

    EXPECT_EQ("xiaoming", avCallMetaData.GetName());
    EXPECT_EQ("123456789", avCallMetaData.GetPhoneNumber());
    EXPECT_NE(nullptr, avCallMetaData.GetMediaImage());
    SLOGI("SetAVCallMetaData001 End");
}

/**
 * @tc.name: GetAVCallMetaData001
 * @tc.desc: get av call meta data result
 * @tc.type: FUNC
 */
HWTEST_F(AVCallMetaDataTest, GetAVCallMetaData001, TestSize.Level1)
{
    SLOGI("GetAVCallMetaData001 Begin");
    AVCallMetaData avCallMetaData;
    avCallMetaData.Reset();
    avCallMetaData.CopyFrom(g_callMetaData);
    EXPECT_EQ(avCallMetaData.GetName(), g_callMetaData.GetName());
    EXPECT_EQ(avCallMetaData.GetPhoneNumber(), g_callMetaData.GetPhoneNumber());
    EXPECT_EQ(avCallMetaData.GetMediaImage(), g_callMetaData.GetMediaImage());
    SLOGI("GetAVCallMetaData001 End");
}

/**
 * @tc.name: AVCallMetaDataMarshalling001
 * @tc.desc: avcallmetadata marshalling test
 * @tc.type: FUNC
 */
HWTEST_F(AVCallMetaDataTest, AVCallMetaDataMarshalling001, TestSize.Level1)
{
    SLOGI("AVCallMetaDataMarshalling001 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto ret = g_callMetaData.Marshalling(parcel);
    EXPECT_EQ(ret, true);
    SLOGI("AVCallMetaDataMarshalling001 End");
}

/**
 * @tc.name: AVCallMetaDataUnmarshalling001
 * @tc.desc: avcallmetadata unmarshalling test
 * @tc.type: FUNC
 */
HWTEST_F(AVCallMetaDataTest, AVCallMetaDataUnmarshalling001, TestSize.Level1)
{
    SLOGI("AVCallMetaDataUnmarshalling001 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto unmarshallingPtr = g_callMetaData.Unmarshalling(parcel);
    EXPECT_NE(unmarshallingPtr, nullptr);
    SLOGI("AVCallMetaDataUnmarshalling001 End");
}

/**
 * @tc.name: AVCallMetaDataGetMask001
 * @tc.desc: get avcall meta mask
 * @tc.type: FUNC
 */
HWTEST_F(AVCallMetaDataTest, AVCallMetaDataGetMask001, TestSize.Level1)
{
    SLOGI("AVCallMetaDataGetMask001 Begin");
    AVCallMetaData avCallMetaData;
    avCallMetaData.Reset();
    avCallMetaData.SetPhoneNumber("123456789");
    EXPECT_NE(avCallMetaData.GetAVCallMetaMask().to_string(), "");
    SLOGI("AVCallMetaDataGetMask001 End");
}

/**
 * @tc.name: AVCallMetaDataCopyDataFromMetaIn001
 * @tc.desc: copy avcall meta item from @metaIn according to set bit of @metaIn meta mask
 * @tc.type: FUNC
 */
HWTEST_F(AVCallMetaDataTest, AVCallMetaDataCopyDataFromMetaIn001, TestSize.Level1)
{
    SLOGI("AVCallMetaDataCopyDataFromMetaIn001 Begin");
    AVCallMetaData avCallMetaData;
    g_avcallMetaDataCloneTest.SetName("xiaoming");
    g_avcallMetaDataCloneTest.SetPhoneNumber("123456789");
    auto ret = avCallMetaData.CopyFrom(g_avcallMetaDataCloneTest);

    EXPECT_EQ(ret, true);
    EXPECT_EQ(avCallMetaData.GetName(), g_avcallMetaDataCloneTest.GetName());
    EXPECT_EQ(avCallMetaData.GetPhoneNumber(), g_avcallMetaDataCloneTest.GetPhoneNumber());
    SLOGI("AVCallMetaDataCopyDataFromMetaIn001 End");
}

/**
 * @tc.name: AVCallMetaDataCopyDataByMask001
 * @tc.desc: copy avcall meta item to @metaOut according to intersection of meta mask.
 * @tc.type: FUNC
 */
HWTEST_F(AVCallMetaDataTest, AVCallMetaDataCopyDataByMask001, TestSize.Level1)
{
    SLOGI("AVCallMetaDataCopyDataByMask001 Begin");
    AVCallMetaData metaOut;
    metaOut.SetName("xiaoming");
    metaOut.SetPhoneNumber("123456789");
    AVCallMetaData::AVCallMetaMaskType mask = metaOut.GetAVCallMetaMask();

    auto ret = g_avcallMetaDataCloneTest.CopyToByMask(mask, metaOut);
    EXPECT_EQ(ret, true);

    EXPECT_EQ(metaOut.GetName(), g_avcallMetaDataCloneTest.GetName());
    EXPECT_EQ(metaOut.GetPhoneNumber(), g_avcallMetaDataCloneTest.GetPhoneNumber());
    SLOGI("AVCallMetaDataCopyDataByMask001 End");
}
} // namespace AVSession
} // namespace OHOS
