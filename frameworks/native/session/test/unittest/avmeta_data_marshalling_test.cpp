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

class AVMetaDataMarshallingTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: AVMetaDataMarshallingExceedsLimit001
 * @tc.desc: metadata marshalling with media image exceeding limit
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataMarshallingTest, AVMetaDataMarshallingExceedsLimit001, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshallingExceedsLimit001 Begin");
    OHOS::MessageParcel parcel;
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> bigBuffer(10 * 1024 * 1024 + 1, 0x01);
    pixelMap->SetInnerImgBuffer(bigBuffer);
    AVMetaData metaData;
    metaData.SetMediaImage(pixelMap);
    auto ret = metaData.WriteToParcel(parcel);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(metaData.GetMediaLength(), 0);
    SLOGI("AVMetaDataMarshallingExceedsLimit001 End");
}

/**
 * @tc.name: AVMetaDataMarshallingExceedsLimit002
 * @tc.desc: metadata marshalling with avqueue image exceeding limit
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataMarshallingTest, AVMetaDataMarshallingExceedsLimit002, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshallingExceedsLimit002 Begin");
    OHOS::MessageParcel parcel;
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> bigBuffer(10 * 1024 * 1024 + 1, 0x01);
    pixelMap->SetInnerImgBuffer(bigBuffer);
    AVMetaData metaData;
    metaData.SetAVQueueImage(pixelMap);
    auto ret = metaData.WriteToParcel(parcel);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(metaData.GetAVQueueLength(), 0);
    SLOGI("AVMetaDataMarshallingExceedsLimit002 End");
}

/**
 * @tc.name: AVMetaDataMarshallingWithinLimit001
 * @tc.desc: metadata marshalling with media image within limit
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataMarshallingTest, AVMetaDataMarshallingWithinLimit001, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshallingWithinLimit001 Begin");
    OHOS::MessageParcel parcel;
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> buffer = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(buffer);
    AVMetaData metaData;
    metaData.SetMediaImage(pixelMap);
    auto ret = metaData.WriteToParcel(parcel);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(metaData.GetMediaLength(), static_cast<int32_t>(buffer.size()));
    SLOGI("AVMetaDataMarshallingWithinLimit001 End");
}

/**
 * @tc.name: AVMetaDataMarshallingWithinLimit002
 * @tc.desc: metadata marshalling with avqueue image within limit
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataMarshallingTest, AVMetaDataMarshallingWithinLimit002, TestSize.Level0)
{
    SLOGI("AVMetaDataMarshallingWithinLimit002 Begin");
    OHOS::MessageParcel parcel;
    auto pixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> buffer = {0, 1, 0, 1};
    pixelMap->SetInnerImgBuffer(buffer);
    AVMetaData metaData;
    metaData.SetAVQueueImage(pixelMap);
    auto ret = metaData.WriteToParcel(parcel);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(metaData.GetAVQueueLength(), static_cast<int32_t>(buffer.size()));
    SLOGI("AVMetaDataMarshallingWithinLimit002 End");
}

/**
 * @tc.name: AVMetaDataReadDrmSchemesNullptr001
 * @tc.desc: read drm schemes with nullptr metaData
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataMarshallingTest, AVMetaDataReadDrmSchemesNullptr001, TestSize.Level0)
{
    SLOGI("AVMetaDataReadDrmSchemesNullptr001 Begin");
    OHOS::Parcel parcel;
    bool ret = AVMetaData::ReadDrmSchemes(parcel, nullptr);
    EXPECT_EQ(ret, false);
    SLOGI("AVMetaDataReadDrmSchemesNullptr001 End");
}

/**
 * @tc.name: AVMetaDataReadDrmSchemesWithMeta001
 * @tc.desc: read drm schemes with valid metaData
 * @tc.type: FUNC
 */
HWTEST_F(AVMetaDataMarshallingTest, AVMetaDataReadDrmSchemesWithMeta001, TestSize.Level0)
{
    SLOGI("AVMetaDataReadDrmSchemesWithMeta001 Begin");
    OHOS::Parcel parcel;
    parcel.WriteInt32(0);
    AVMetaData metaData;
    metaData.SetDrmSchemes({"test"});
    EXPECT_EQ(metaData.GetDrmSchemes().size(), 1);
    bool ret = AVMetaData::ReadDrmSchemes(parcel, &metaData);
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(metaData.GetDrmSchemes().empty());
    SLOGI("AVMetaDataReadDrmSchemesWithMeta001 End");
}

} // namespace AVSession
} // namespace OHOS
