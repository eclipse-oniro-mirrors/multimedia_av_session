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
#include <memory>
#include <fstream>
#include <cstdio>
#include <cstring>
#include "avsession_log.h"
#include "input_manager.h"
#include "key_event.h"
#include "avsession_manager.h"
#include "avsession_errors.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avsession_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "system_ability_definition.h"
#include "system_ability_ondemand_reason.h"
#include "audio_info.h"
#include "avsession_callback_client.h"
#include "avsession_pixel_map.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_info.h"
#include "avsession_service.h"
#include "avsession_service_proxy.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AudioStandard;

static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};

class AVSessionServiceAddedTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionServiceAddedTest::SetUpTestCase()
{
    SLOGI("set up AVSessionServiceAddedTest");
    system("killall -9 com.example.hiMusicDemo");
    sleep(1);
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
    g_AVSessionService->InitKeyEvent();
}

void AVSessionServiceAddedTest::TearDownTestCase()
{
    g_AVSessionService->Close();
}

void AVSessionServiceAddedTest::SetUp() {}

void AVSessionServiceAddedTest::TearDown() {}

/**
 * @tc.name: SuperLauncher001
 * @tc.desc: Verifying NotifyFlowControl with a non-full flow control list.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, SuperLauncher001, TestSize.Level1)
{
    SLOGD("SuperLauncher001 begin!");
    std::string deviceId = "IDLE";
    std::string serviceName = "SuperLauncher-Dual";
    std::string extraInfo = "extra";
    const std::string& state = "CONNECTING";
    g_AVSessionService->migrateAVSession_ = nullptr;
    g_AVSessionService->SuperLauncher(deviceId, serviceName, extraInfo, state);
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("SuperLauncher001 end!");
}

/**
 * @tc.name: SuperLauncher002
 * @tc.desc: Verifying NotifyFlowControl with a non-full flow control list.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, SuperLauncher002, TestSize.Level1)
{
    SLOGD("SuperLauncher002 begin!");
    std::string deviceId = "NOTIDLE";
    std::string serviceName = "SuperLauncher-Dual";
    std::string extraInfo = "extra";
    const std::string& state = "CONNECTING";
    g_AVSessionService->SuperLauncher(deviceId, serviceName, extraInfo, state);
    g_AVSessionService->migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("SuperLauncher002 end!");
}


/**
 * @tc.name: SuperLauncherTest003
 * @tc.desc: Verifies the behavior of SuperLauncher for HuaweiCast service.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, SuperLauncherTest003, TestSize.Level1)
{
    SLOGD("SuperLauncherTest003 begin!");
    #ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::string deviceId = "NOTIDLE";
    std::string serviceName = "HuaweiCast";
    std::string extraInfo = "extra";
    const std::string& state = "IDLE";
    g_AVSessionService->SuperLauncher(deviceId, serviceName, extraInfo, state);
    g_AVSessionService->migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
    #endif
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("SuperLauncherTest003 end!");
}

/**
 * @tc.name: SuperLauncherTest004
 * @tc.desc: Verifies the behavior of SuperLauncher for HuaweiCast service.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, SuperLauncherTest004, TestSize.Level1)
{
    SLOGD("SuperLauncherTest004 begin!");
    #ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGD("SuperLauncherTest005 begin!");
    std::string deviceId = "NOTIDLE";
    std::string serviceName = "HuaweiCast";
    std::string extraInfo = "extra";
    const std::string& state = "CONNECT_SUCC";
    g_AVSessionService->SuperLauncher(deviceId, serviceName, extraInfo, state);
    g_AVSessionService->migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
    g_AVSessionService->is2in1_ = true;
    #endif
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("SuperLauncherTest004 end!");
}

/**
 * @tc.name: SuperLauncherTest005
 * @tc.desc: test SplitExtraInfo
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, SuperLauncherTest005, TestSize.Level1)
{
    SLOGD("SuperLauncherTest005 begin!");
    #ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGD("SuperLauncherTest006 begin!");
    std::string deviceId = "test_device_id";
    std::string serviceName = "HuaweiCast";
    std::string extraInfo = "SUPPORT_MIRROR_TO_STREAM=true;deviceId:1001;deviceName:TestDevice;deviceType:5";
    const std::string& state = "CONNECT_SUCC";
    g_AVSessionService->SuperLauncher(deviceId, serviceName, extraInfo, state);
    #endif
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("SuperLauncherTest005 end!");
}

/**
 * @tc.name: checkEnableCast001
 * @tc.desc: test checkEnableCast
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, checkEnableCast001, TestSize.Level1)
{
    SLOGD("checkEnableCast001 begin!");
    bool enable = true;
    g_AVSessionService->isInCast_ = false;
    auto ret = g_AVSessionService->checkEnableCast(enable);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGD("checkEnableCast001 end!");
}

/**
 * @tc.name: checkEnableCast002
 * @tc.desc: test checkEnableCast
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, checkEnableCast002, TestSize.Level1)
{
    SLOGD("checkEnableCast002 begin!");
    bool enable = false;
    g_AVSessionService->isInCast_ = true;
    auto ret = g_AVSessionService->checkEnableCast(enable);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGD("checkEnableCast002 end!");
}

/**
 * @tc.name: StopCast001
 * @tc.desc: test StopCast
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, StopCast001, TestSize.Level1)
{
    SLOGD("StopCast001 begin!");
    #ifdef CASTPLUS_CAST_ENGINE_ENABLE
    const OHOS::AVSession::SessionToken sessionToken = {
        .sessionId = "success",
        .pid = 1234,
        .uid = 5678
    };
    auto ret = g_AVSessionService->StopCast(sessionToken);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    #endif
    SLOGD("StopCast001 end!");
}

/**
 * @tc.name: ProcessTargetMigrateTest001
 * @tc.desc: Test for deviceTypeId mismatch.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, ProcessTargetMigrateTest001, TestSize.Level1)
{
    SLOGD("ProcessTargetMigrateTest001 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    bool isOnline = true;
    bool result = g_AVSessionService->ProcessTargetMigrate(isOnline, deviceInfo);
    EXPECT_FALSE(result);
    SLOGD("ProcessTargetMigrateTest001 end!");
}

/**
 * @tc.name: ProcessTargetMigrateTest002
 * @tc.desc: Test when CheckWhetherTargetDevIsNext returns false.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, ProcessTargetMigrateTest002, TestSize.Level1)
{
    SLOGD("ProcessTargetMigrateTest002 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "test";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    bool isOnline = true;
    bool result = g_AVSessionService->ProcessTargetMigrate(isOnline, deviceInfo);
    EXPECT_FALSE(result);
    SLOGD("ProcessTargetMigrateTest002 end!");
}

/**
 * @tc.name: ProcessTargetMigrateTest003
 * @tc.desc: Test when both conditions fail.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, ProcessTargetMigrateTest003, TestSize.Level1)
{
    SLOGD("ProcessTargetMigrateTest003 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "test";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    bool isOnline = true;
    bool result = g_AVSessionService->ProcessTargetMigrate(isOnline, deviceInfo);
    EXPECT_FALSE(result);
    SLOGD("ProcessTargetMigrateTest003 end!");
}

/**
 * @tc.name: ProcessTargetMigrateTest004
 * @tc.desc: Test entering the else branch.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, ProcessTargetMigrateTest004, TestSize.Level1)
{
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "valid";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    std::string extraData = "{\"OS_TYPE\":1}";
    deviceInfo.extraData = extraData;
    bool isOnline = true;
    bool result = g_AVSessionService->ProcessTargetMigrate(isOnline, deviceInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ProcessTargetMigrateTest005
 * @tc.desc: Test entering the else branch.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, ProcessTargetMigrateTest005, TestSize.Level1)
{
    SLOGD("ProcessTargetMigrateTest005 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "valid";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    std::string extraData = "{\"OS_TYPE\":1}";
    deviceInfo.extraData = extraData;
    bool isOnline = true;
    g_AVSessionService->localDeviceType_ = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    bool result = g_AVSessionService->ProcessTargetMigrate(isOnline, deviceInfo);
    EXPECT_TRUE(result);
    SLOGD("ProcessTargetMigrateTest005 end!");
}

/**
 * @tc.name: ProcessTargetMigrateTest006
 * @tc.desc: Test entering the else branch.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, ProcessTargetMigrateTest006, TestSize.Level1)
{
    SLOGD("ProcessTargetMigrateTest006 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "valid";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    std::string extraData = "{\"OS_TYPE\":1}";
    deviceInfo.extraData = extraData;
    bool isOnline = false;
    bool result = g_AVSessionService->ProcessTargetMigrate(isOnline, deviceInfo);
    EXPECT_TRUE(result);
    SLOGD("ProcessTargetMigrateTest006 end!");
}

/**
 * @tc.name: CheckWhetherTargetDevIsNextTest001
 * @tc.desc: Test entering the second if branch but not the first inner branch.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, CheckWhetherTargetDevIsNextTest001, TestSize.Level1)
{
    SLOGD("CheckWhetherTargetDevIsNextTest001 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    std::string extraData = "{\"OS_TYPE\":\"string_value\"}";
    deviceInfo.extraData = extraData;
    bool result = g_AVSessionService->CheckWhetherTargetDevIsNext(deviceInfo);
    EXPECT_FALSE(result);
    SLOGD("CheckWhetherTargetDevIsNextTest001 end!");
}

/**
 * @tc.name: CheckWhetherTargetDevIsNextTest002
 * @tc.desc: Test entering the first inner branch but not the second inner branch.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, CheckWhetherTargetDevIsNextTest002, TestSize.Level1)
{
    SLOGD("CheckWhetherTargetDevIsNextTest002 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    std::string extraData = "{\"OS_TYPE\":-1}";
    deviceInfo.extraData = extraData;
    bool result = g_AVSessionService->CheckWhetherTargetDevIsNext(deviceInfo);
    EXPECT_FALSE(result);
    SLOGD("CheckWhetherTargetDevIsNextTest002 end!");
}

/**
 * @tc.name: AVSessionDeviceStateCallbackTest_OnDeviceReady_001
 * @tc.desc: Test entering the if branch of OnDeviceReady.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionDeviceStateCallbackTest_OnDeviceReady_001, TestSize.Level1)
{
    SLOGD("AVSessionDeviceStateCallbackTest_OnDeviceReady_001 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "valid";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    std::string extraData = "{\"OS_TYPE\":1}";
    deviceInfo.extraData = extraData;
    AVSessionDeviceStateCallback callback(g_AVSessionService.get());
    callback.OnDeviceReady(deviceInfo);
    SLOGD("AVSessionDeviceStateCallbackTest_OnDeviceReady_001 end!");
}

/**
 * @tc.name: AVSessionDeviceStateCallbackTest_OnDeviceReady_002
 * @tc.desc: Test not entering the if branch of OnDeviceReady.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionDeviceStateCallbackTest_OnDeviceReady_002, TestSize.Level1)
{
    SLOGD("AVSessionDeviceStateCallbackTest_OnDeviceReady_002 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    AVSessionDeviceStateCallback callback(g_AVSessionService.get());
    callback.OnDeviceReady(deviceInfo);
    ASSERT_TRUE(callback.servicePtr_ != nullptr);
    SLOGD("AVSessionDeviceStateCallbackTest_OnDeviceReady_002 end!");
}

/**
 * @tc.name: AVSessionDeviceStateCallbackTest_OnDeviceOffline_001
 * @tc.desc: Test entering the if branch of OnDeviceOffline.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionDeviceStateCallbackTest_OnDeviceOffline_001, TestSize.Level1)
{
    SLOGD("AVSessionDeviceStateCallbackTest_OnDeviceOffline_001 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "valid";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    std::string extraData = "{\"OS_TYPE\":1}";
    deviceInfo.extraData = extraData;
    AVSessionDeviceStateCallback callback(g_AVSessionService.get());
    callback.OnDeviceOffline(deviceInfo);
    ASSERT_TRUE(callback.servicePtr_ != nullptr);
    SLOGD("AVSessionDeviceStateCallbackTest_OnDeviceOffline_001 end!");
}

/**
 * @tc.name: AVSessionDeviceStateCallbackTest_OnDeviceOffline_002
 * @tc.desc: Test not entering the if branch of OnDeviceOffline.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionDeviceStateCallbackTest_OnDeviceOffline_002, TestSize.Level1)
{
    SLOGD("AVSessionDeviceStateCallbackTest_OnDeviceOffline_002 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    std::string name = "test";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    std::string extraData = "{\"OS_TYPE\":-1}";
    deviceInfo.extraData = extraData;
    AVSessionDeviceStateCallback callback(g_AVSessionService.get());
    callback.OnDeviceOffline(deviceInfo);
    ASSERT_TRUE(callback.servicePtr_ != nullptr);
    SLOGD("AVSessionDeviceStateCallbackTest_OnDeviceOffline_002 end!");
}

/**
 * @tc.name: DoRemoteAVSessionLoad_001
 * @tc.desc: Test DoRemoteAVSessionLoad.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, DoRemoteAVSessionLoad_001, TestSize.Level1)
{
    SLOGD("DoRemoteAVSessionLoad_001 begin!");
    std::string remoteDeviceId = "device";
    g_AVSessionService->DoRemoteAVSessionLoad(remoteDeviceId);
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("DoRemoteAVSessionLoad_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_DoConnectProcessWithMigrate_001
 * @tc.desc: Test entering the if branch of DoConnectProcessWithMigrate.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_DoConnectProcessWithMigrate_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_DoConnectProcessWithMigrate_001 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "valid";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    g_AVSessionService->localDeviceType_ = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    g_AVSessionService->DoConnectProcessWithMigrate(deviceInfo);
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("AVSessionServiceAddedTest_DoConnectProcessWithMigrate_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_DoConnectProcessWithMigrate_002
 * @tc.desc: Test not entering the if branch of DoConnectProcessWithMigrate.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_DoConnectProcessWithMigrate_002, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_DoConnectProcessWithMigrate_002 begin!");
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string name = "valid";
    strcpy_s(deviceInfo.deviceName, name.size(), name.c_str());
    deviceInfo.deviceName[name.size()] = '\0';
    g_AVSessionService->localDeviceType_ = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD;
    g_AVSessionService->DoConnectProcessWithMigrate(deviceInfo);
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("AVSessionServiceAddedTest_DoConnectProcessWithMigrate_002 end!");
}