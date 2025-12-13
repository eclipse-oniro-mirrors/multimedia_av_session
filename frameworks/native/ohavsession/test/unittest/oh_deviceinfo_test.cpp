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
#include "OHDeviceInfo.h"
#include <memory>

using namespace testing::ext;
namespace OHOS::AVSession {
class OHDeviceInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OHDeviceInfoTest::SetUpTestCase(void)
{
}

void OHDeviceInfoTest::TearDownTestCase(void)
{
}

void OHDeviceInfoTest::SetUp()
{
}

void OHDeviceInfoTest::TearDown()
{
}

/**
 * @tc.name: OH_DeviceInfo_GetAVCastCategory_001
 * @tc.desc: Get AV cast category from OHDeviceInfo
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHDeviceInfoTest, OH_DeviceInfo_GetAVCastCategory_001, TestSize.Level0)
{
    SLOGI("OH_DeviceInfo_GetAVCastCategory_001 Begin");
    OHDeviceInfo* ohDeviceInfo = new OHDeviceInfo(CATEGORY_REMOTE, "deviceId", "deviceName",
        DEVICE_TYPE_TV, TYPE_CAST_PLUS_STREAM);
    AVSession_AVCastCategory castCategory;
    OH_DeviceInfo_GetAVCastCategory((AVSession_DeviceInfo*)ohDeviceInfo, &castCategory);
    EXPECT_EQ(castCategory, CATEGORY_REMOTE);
    SLOGI("OH_DeviceInfo_GetAVCastCategory_001 End");
}

/**
 * @tc.name: OH_DeviceInfo_GetDeviceId_001
 * @tc.desc: Get device ID from OHDeviceInfo
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHDeviceInfoTest, OH_DeviceInfo_GetDeviceId_001, TestSize.Level0)
{
    SLOGI("OH_DeviceInfo_GetDeviceId_001 Begin");
    OHDeviceInfo* ohDeviceInfo = new OHDeviceInfo(CATEGORY_REMOTE, "deviceId", "deviceName",
        DEVICE_TYPE_TV, TYPE_CAST_PLUS_STREAM);
    char* deviceId;
    OH_DeviceInfo_GetDeviceId((AVSession_DeviceInfo*)ohDeviceInfo, &deviceId);
    EXPECT_STREQ(deviceId, "deviceId");
    SLOGI("OH_DeviceInfo_GetDeviceId_001 End");
}
/**
 * @tc.name: OH_DeviceInfo_GetDeviceName_001
 * @tc.desc: Get device name from OHDeviceInfo
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHDeviceInfoTest, OH_DeviceInfo_GetDeviceName_001, TestSize.Level0)
{
    SLOGI("OH_DeviceInfo_GetDeviceName_001 Begin");
    OHDeviceInfo* ohDeviceInfo = new OHDeviceInfo(CATEGORY_REMOTE, "deviceId", "deviceName",
        DEVICE_TYPE_TV, TYPE_CAST_PLUS_STREAM);
    char* deviceName;
    OH_DeviceInfo_GetDeviceName((AVSession_DeviceInfo*)ohDeviceInfo, &deviceName);
    EXPECT_STREQ(deviceName, "deviceName");
    SLOGI("OH_DeviceInfo_GetDeviceName_001 End");
}
/**
 * @tc.name: OH_DeviceInfo_GetDeviceType_001
 * @tc.desc: Get device type from OHDeviceInfo
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHDeviceInfoTest, OH_DeviceInfo_GetDeviceType_001, TestSize.Level0)
{
    SLOGI("OH_DeviceInfo_GetDeviceType_001 Begin");
    OHDeviceInfo* ohDeviceInfo = new OHDeviceInfo(CATEGORY_REMOTE, "deviceId", "deviceName",
        DEVICE_TYPE_TV, TYPE_CAST_PLUS_STREAM);
    AVSession_DeviceType deviceType;
    OH_DeviceInfo_GetDeviceType((AVSession_DeviceInfo*)ohDeviceInfo, &deviceType);
    EXPECT_EQ(deviceType, DEVICE_TYPE_TV);
    SLOGI("OH_DeviceInfo_GetDeviceType_001 End");
}
/**
 * @tc.name: OH_DeviceInfo_GetSupportedProtocols_001
 * @tc.desc: Get supported protocols from OHDeviceInfo
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHDeviceInfoTest, OH_DeviceInfo_GetSupportedProtocols_001, TestSize.Level0)
{
    SLOGI("OH_DeviceInfo_GetSupportedProtocols_001 Begin");
    OHDeviceInfo* ohDeviceInfo = new OHDeviceInfo(CATEGORY_REMOTE, "deviceId", "deviceName",
        DEVICE_TYPE_TV, TYPE_CAST_PLUS_STREAM);
    uint32_t supportedProtocols;
    OH_DeviceInfo_GetSupportedProtocols((AVSession_DeviceInfo*)ohDeviceInfo, &supportedProtocols);
    EXPECT_EQ(supportedProtocols, TYPE_CAST_PLUS_STREAM);
    SLOGI("OH_DeviceInfo_GetSupportedProtocols_001 End");
}
}   // namespace OHOS::AVSession