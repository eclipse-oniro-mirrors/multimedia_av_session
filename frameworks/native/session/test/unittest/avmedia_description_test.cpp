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

#include "avmedia_description.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "av_session.h"
#include "avsession_errors.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

namespace OHOS {
namespace AVSession {
static AVMediaDescription g_mediaDescriptionCloneTest;
static AVMediaDescription g_mediaDescription;
static OHOS::Parcel g_parcel;

class AVMediaDescriptionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVMediaDescriptionTest::SetUpTestCase()
{
}

void AVMediaDescriptionTest::TearDownTestCase()
{
}

void AVMediaDescriptionTest::SetUp()
{
    g_mediaDescription.Reset();
    g_mediaDescription.SetMediaId("123");
    g_mediaDescription.SetTitle("Title");
    g_mediaDescription.SetSubtitle("Subtitle");
    g_mediaDescription.SetDescription("This is music description");
    g_mediaDescription.SetIcon(nullptr);
    g_mediaDescription.SetIconUri("xxxxx");
    g_mediaDescription.SetExtras(nullptr);
    g_mediaDescription.SetMediaUri("Media url");
}

void AVMediaDescriptionTest::TearDown()
{
}

/**
* @tc.name: SetAVMediaDescription001
* @tc.desc: Set av media description
* @tc.type: FUNC
* @tc.require: I6RJST
*/
HWTEST_F(AVMediaDescriptionTest, SetAVmediaDescription001, TestSize.Level1)
{
    SLOGI("SetAVMediaDescription001 Begin");
    AVMediaDescription mediaDescription;
    mediaDescription.Reset();
    mediaDescription.SetMediaId("123");
    mediaDescription.SetTitle("Title");
    mediaDescription.SetSubtitle("Subtitle");
    mediaDescription.SetDescription("This is music description");
    mediaDescription.SetIcon(nullptr);
    mediaDescription.SetIconUri("xxxxx");
    mediaDescription.SetExtras(nullptr);
    mediaDescription.SetMediaUri("Media url");

    EXPECT_EQ("123", mediaDescription.GetMediaId());
    EXPECT_EQ("Title", mediaDescription.GetTitle());
    EXPECT_EQ("Subtitle", mediaDescription.GetSubtitle());
    EXPECT_EQ("This is music description", mediaDescription.GetDescription());
    EXPECT_EQ(nullptr, mediaDescription.GetIcon());
    EXPECT_EQ("xxxxx", mediaDescription.GetIconUri());
    EXPECT_EQ(nullptr, mediaDescription.GetExtras());
    EXPECT_EQ("Media url", mediaDescription.GetMediaUri());

    SLOGI("SetAVMediaDescription001 End");
}

/**
* @tc.name: IsAVmediaDescriptionValid001
* @tc.desc: Check is av media description valid
* @tc.type: FUNC
* @tc.require: I6RJST
*/
HWTEST_F(AVMediaDescriptionTest, IsAVmediaDescriptionValid001, TestSize.Level1)
{
    SLOGI("IsAVmediaDescriptionValid001 Begin");
    AVMediaDescription mediaDescription;
    mediaDescription.Reset();
    mediaDescription.SetMediaId("123");
    bool ret = mediaDescription.IsValid();
    EXPECT_EQ(ret, true);
    SLOGI("IsAVmediaDescriptionValid001 End");
}

/**
* @tc.name: IsAVmediaDescriptionValid002
* @tc.desc: Check is av media description valid
* @tc.type: FUNC
* @tc.require: I6RJST
*/
HWTEST_F(AVMediaDescriptionTest, IsAVmediaDescriptionValid002, TestSize.Level1)
{
    SLOGI("IsAVmediaDescriptionValid002 Begin");
    AVMediaDescription mediaDescription;
    mediaDescription.Reset();
    bool ret = mediaDescription.IsValid();
    EXPECT_EQ(ret, false);
    SLOGI("IsAVmediaDescriptionValid002 End");
}

/**
 * @tc.name: AVmediaDescriptionMarshalling001
 * @tc.desc: mediaDescription marshalling test
 * @tc.type: FUNC
 * @tc.require:I6RJST
 */
HWTEST_F(AVMediaDescriptionTest, AVmediaDescriptionMarshalling001, TestSize.Level1)
{
    SLOGI("AVmediaDescriptionMarshalling001 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto ret = g_mediaDescription.Marshalling(parcel);
    EXPECT_EQ(ret, true);
    SLOGI("AVmediaDescriptionMarshalling001 End");
}

/**
 * @tc.name: AVmediaDescriptionUnmarshalling001
 * @tc.desc: mediaDescription unmarshalling test
 * @tc.type: FUNC
 * @tc.require:I6RJST
 */
HWTEST_F(AVMediaDescriptionTest, AVmediaDescriptionUnmarshalling001, TestSize.Level1)
{
    SLOGI("AVmediaDescriptionUnmarshalling001 Begin");
    OHOS::Parcel& parcel = g_parcel;
    auto unmarshallingPtr = g_mediaDescription.Unmarshalling(parcel);
    EXPECT_NE(unmarshallingPtr, nullptr);
    SLOGI("AVmediaDescriptionUnmarshalling001 End");
}
} // namespace AVSession
} // namespace OHOS
