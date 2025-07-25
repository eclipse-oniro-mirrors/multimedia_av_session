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
 
#include "gtest/gtest.h"
 
#include "avsession_callback_client.h"
#include "avsession_descriptor.h"
 
using namespace testing::ext;
 
namespace OHOS {
namespace AVSession {
namespace {

std::string g_errLog;
void MyLogCallback(const LogType type, const LogLevel level, const unsigned int domain, const char *tag,
                   const char *msg)
{
    g_errLog = msg;
}
}   // namespace
 
class AVSessionDescriptorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};
 
void AVSessionDescriptorTest::SetUpTestCase()
{}
 
void AVSessionDescriptorTest::TearDownTestCase()
{}
 
void AVSessionDescriptorTest::SetUp()
{}
 
void AVSessionDescriptorTest::TearDown()
{}
 
/**
* @tc.name: Marshalling001
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, Marshalling001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVHistoryDescriptor> avHistoryDescriptor = std::make_shared<AVHistoryDescriptor>();
    EXPECT_NE(avHistoryDescriptor, nullptr);
    Parcel out;
    bool ret = avHistoryDescriptor->Marshalling(out);
    EXPECT_EQ(ret, true);
}
 
/**
* @tc.name: Unmarshalling001
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, Unmarshalling001, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<AVHistoryDescriptor> avHistoryDescriptor = std::make_shared<AVHistoryDescriptor>();
    Parcel in;
    EXPECT_NE(avHistoryDescriptor, nullptr);
    avHistoryDescriptor->Unmarshalling(in);
}
 
/**
* @tc.name: Marshalling002
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, Marshalling002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<DeviceInfo> deviceInfo = std::make_shared<DeviceInfo>();
    EXPECT_NE(deviceInfo, nullptr);
    Parcel out;
    bool ret = deviceInfo->Marshalling(out);
    EXPECT_EQ(ret, true);
}
 
/**
* @tc.name: Unmarshalling002
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, Unmarshalling002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<DeviceInfo> deviceInfo = std::make_shared<DeviceInfo>();
    EXPECT_NE(deviceInfo, nullptr);
    Parcel in;
    deviceInfo->Unmarshalling(in);
}
 
/**
* @tc.name: Marshalling003
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, Marshalling003, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<CastDisplayInfo> castDisplayInfo = std::make_shared<CastDisplayInfo>();
    EXPECT_NE(castDisplayInfo, nullptr);
    Parcel out;
    bool ret = castDisplayInfo->Marshalling(out);
    EXPECT_EQ(ret, true);
}
 
/**
* @tc.name: Unmarshalling003
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, Unmarshalling003, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<CastDisplayInfo> castDisplayInfo = std::make_shared<CastDisplayInfo>();
    EXPECT_NE(castDisplayInfo, nullptr);
    Parcel in;
    castDisplayInfo->Unmarshalling(in);
}
 
/**
* @tc.name: ReadFromParcel003
* @tc.desc: test ReadFromParcel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, ReadFromParcel003, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    std::shared_ptr<CastDisplayInfo> castDisplayInfo = std::make_shared<CastDisplayInfo>();
    EXPECT_NE(castDisplayInfo, nullptr);
    Parcel in;
    bool ret = castDisplayInfo->ReadFromParcel(in);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: Marshalling004
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, Marshalling004, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    DeviceState deviceState;
    Parcel out;
    bool ret = deviceState.Marshalling(out);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: Unmarshalling004
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, Unmarshalling004, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    DeviceState deviceState;
    Parcel in;
    auto ret = deviceState.Unmarshalling(in);
    EXPECT_EQ(ret, nullptr);
}

/**
* @tc.name: ReadFromParcel004
* @tc.desc: test ReadFromParcel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionDescriptorTest, ReadFromParcel002, TestSize.Level1)
{
    LOG_SetCallback(MyLogCallback);
    DeviceState deviceState;
    Parcel in;
    bool ret = deviceState.ReadFromParcel(in);
    EXPECT_EQ(ret, false);
}

} // namespace AVSESSION
} // namespace OHOS