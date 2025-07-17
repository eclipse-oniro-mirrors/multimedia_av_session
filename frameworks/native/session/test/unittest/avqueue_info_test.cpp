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

#include "avqueue_info.h"
#include "avsession_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVQueueInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVQueueInfoTest::SetUpTestCase()
{}

void AVQueueInfoTest::TearDownTestCase()
{}

void AVQueueInfoTest::SetUp()
{}

void AVQueueInfoTest::TearDown()
{}

/**
* @tc.name: Marshalling001
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVQueueInfoTest, Marshalling001, TestSize.Level0)
{
    AVQueueInfo avqueueInfo;
    avqueueInfo.SetAVQueueName("xiaoqiang");
    EXPECT_EQ(avqueueInfo.GetAVQueueName(), "xiaoqiang");
    avqueueInfo.SetAVQueueId("aaa");
    EXPECT_EQ(avqueueInfo.GetAVQueueId(), "aaa");
    avqueueInfo.SetAVQueueImageUri("bbb");
    EXPECT_EQ(avqueueInfo.GetAVQueueImageUri(), "bbb");
    Parcel parcel;
    bool result = avqueueInfo.Marshalling(parcel);
    EXPECT_EQ(result, true);
}

/**
* @tc.name: Unmarshalling001
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVQueueInfoTest, Unmarshalling001, TestSize.Level0)
{
    AVQueueInfo avqueueInfo;
    avqueueInfo.SetAVQueueName("xiaoqiang");
    EXPECT_EQ(avqueueInfo.GetAVQueueName(), "xiaoqiang");
    avqueueInfo.SetAVQueueId("aaa");
    EXPECT_EQ(avqueueInfo.GetAVQueueId(), "aaa");
    avqueueInfo.SetAVQueueImageUri("bbb");
    EXPECT_EQ(avqueueInfo.GetAVQueueImageUri(), "bbb");
    Parcel parcel;
    avqueueInfo.Marshalling(parcel);
    bool result = avqueueInfo.Unmarshalling(parcel);
    EXPECT_EQ(result, false);
}

/**
* @tc.name: Unmarshalling002
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVQueueInfoTest, Unmarshalling002, TestSize.Level0)
{
    AVQueueInfo avqueueInfo;
    avqueueInfo.SetBundleName("xiaoming");
    EXPECT_EQ(avqueueInfo.GetBundleName(), "xiaoming");
    avqueueInfo.SetAVQueueId("aaa");
    EXPECT_EQ(avqueueInfo.GetAVQueueId(), "aaa");
    avqueueInfo.SetAVQueueImageUri("bbb");
    EXPECT_EQ(avqueueInfo.GetAVQueueImageUri(), "bbb");
    Parcel parcel;
    avqueueInfo.Marshalling(parcel);
    bool result = avqueueInfo.Unmarshalling(parcel);
    EXPECT_EQ(result, false);
}

/**
* @tc.name: Unmarshalling003
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVQueueInfoTest, Unmarshalling003, TestSize.Level0)
{
    AVQueueInfo avqueueInfo;
    avqueueInfo.SetBundleName("xiaoming");
    EXPECT_EQ(avqueueInfo.GetBundleName(), "xiaoming");
    avqueueInfo.SetAVQueueName("xiaoqiang");
    EXPECT_EQ(avqueueInfo.GetAVQueueName(), "xiaoqiang");
    avqueueInfo.SetAVQueueImageUri("bbb");
    EXPECT_EQ(avqueueInfo.GetAVQueueImageUri(), "bbb");
    Parcel parcel;
    avqueueInfo.Marshalling(parcel);
    bool result = avqueueInfo.Unmarshalling(parcel);
    EXPECT_EQ(result, false);
}

/**
* @tc.name: Unmarshalling004
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVQueueInfoTest, Unmarshalling004, TestSize.Level0)
{
    AVQueueInfo avqueueInfo;
    avqueueInfo.SetBundleName("xiaoming");
    EXPECT_EQ(avqueueInfo.GetBundleName(), "xiaoming");
    avqueueInfo.SetAVQueueName("xiaoqiang");
    EXPECT_EQ(avqueueInfo.GetAVQueueName(), "xiaoqiang");
    avqueueInfo.SetAVQueueId("aaa");
    EXPECT_EQ(avqueueInfo.GetAVQueueId(), "aaa");
    Parcel parcel;
    bool result = avqueueInfo.Unmarshalling(parcel);
    EXPECT_EQ(result, false);
}

/**
* @tc.name: Unmarshalling005
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVQueueInfoTest, Unmarshalling005, TestSize.Level0)
{
    AVQueueInfo avqueueInfo;
    avqueueInfo.SetBundleName("xiaoming");
    EXPECT_EQ(avqueueInfo.GetBundleName(), "xiaoming");
    avqueueInfo.SetAVQueueName("xiaoqiang");
    EXPECT_EQ(avqueueInfo.GetAVQueueName(), "xiaoqiang");
    avqueueInfo.SetAVQueueId("aaa");
    EXPECT_EQ(avqueueInfo.GetAVQueueId(), "aaa");
    avqueueInfo.SetAVQueueImageUri("bbb");
    EXPECT_EQ(avqueueInfo.GetAVQueueImageUri(), "bbb");
    Parcel parcel;
    avqueueInfo.Marshalling(parcel);
    std::shared_ptr<AVSessionPixelMap> avQueueImage = std::make_shared<AVSessionPixelMap>();
    avqueueInfo.SetAVQueueImage(avQueueImage);
    bool result = avqueueInfo.Unmarshalling(parcel);
    EXPECT_EQ(result, false);
}

} // namespace AVSession
} // namespace OHOS