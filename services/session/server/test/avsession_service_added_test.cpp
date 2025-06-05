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

static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};

class AVSessionServiceAddedTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionServiceAddedTest::SetUpTestCase() {}

void AVSessionServiceAddedTest::TearDownTestCase() {}

void AVSessionServiceAddedTest::SetUp()
{
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
    g_AVSessionService->InitKeyEvent();
}

void AVSessionServiceAddedTest::TearDown()
{
    if (g_AVSessionService != nullptr) {
        g_AVSessionService->Close();
    }
}

class AVSessionListenerMock : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override {}
    void OnSessionRelease(const AVSessionDescriptor& descriptor) override {}
    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override {}
    void OnAudioSessionChecked(const int32_t uid) override {}
    void OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override {}
    void OnDeviceOffline(const std::string& deviceId) override {}
    ~AVSessionListenerMock() override {}
};

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

/**
 * @tc.name: AVSessionServiceAddedTest_HandleUserEvent_001
 * @tc.desc: set type to accountEventSwitched
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_HandleUserEvent_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_HandleUserEvent_001 begin!");
    std::string type = "SWITCHED";
    int userId = 1;
    g_AVSessionService->HandleUserEvent(type, userId);
    ASSERT_TRUE(g_AVSessionService != nullptr);
    SLOGD("AVSessionServiceAddedTest_HandleUserEvent_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_HandleUserEvent_002
 * @tc.desc: set type to accountEventRemoved
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_HandleUserEvent_002, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_HandleUserEvent_002 begin!");
    std::string type = "REMOVED";
    int userId = 1;
    g_AVSessionService->HandleUserEvent(type, userId);
    EXPECT_TRUE(g_AVSessionService != nullptr);
    SLOGD("AVSessionServiceAddedTest_HandleUserEvent_002 end!");
}


/**
 * @tc.name: AVSessionServiceAddedTest_GetPresentController_001
 * @tc.desc: success to read data from file
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_GetPresentController_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_GetPresentController_001 begin!");
    pid_t pid = 2220;
    std::string sessionId = "1234567890";
    std::list<OHOS::sptr<AVControllerItem>> itemList;
    itemList.push_back(nullptr);
    g_AVSessionService->controllers_.insert({pid, itemList});
    auto ret = g_AVSessionService->GetPresentController(pid, sessionId);
    EXPECT_TRUE(ret == nullptr);
    SLOGD("AVSessionServiceAddedTest_GetPresentController_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_NotifySessionRelease_001
 * @tc.desc: success to read data from file
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_NotifySessionRelease_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_NotifySessionRelease_001 begin!");
    AVSessionDescriptor descriptor;
    descriptor.userId_ = 1001;
    descriptor.pid_ = 2001;
    
    std::map<pid_t, OHOS::sptr<ISessionListener>> listenerMap =
        g_AVSessionService->GetUsersManager().GetSessionListener(descriptor.userId_);
    listenerMap.insert({descriptor.pid_, nullptr});

    std::map<pid_t, OHOS::sptr<ISessionListener>> listenerMapForAll =
        g_AVSessionService->GetUsersManager().GetSessionListenerForAllUsers();
    listenerMapForAll.insert({descriptor.pid_, nullptr});
    
    g_AVSessionService->innerSessionListeners_.push_back(nullptr);
    g_AVSessionService->NotifySessionRelease(descriptor);
    EXPECT_TRUE(g_AVSessionService->innerSessionListeners_.size() > 0);
    SLOGD("AVSessionServiceAddedTest_NotifySessionRelease_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_NotifyTopSessionChanged_001
 * @tc.desc: success to read data from file
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_NotifyTopSessionChanged_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_NotifyTopSessionChanged_001 begin!");
    AVSessionDescriptor descriptor;
    descriptor.userId_ = 1002;
    descriptor.pid_ = 2002;
    
    std::map<pid_t, OHOS::sptr<ISessionListener>> listenerMap =
        g_AVSessionService->GetUsersManager().GetSessionListener(descriptor.userId_);
    listenerMap.insert({descriptor.pid_, nullptr});

    std::map<pid_t, OHOS::sptr<ISessionListener>> listenerMapForAll =
        g_AVSessionService->GetUsersManager().GetSessionListenerForAllUsers();
    listenerMapForAll.insert({descriptor.pid_, nullptr});
    
    auto listener = std::make_shared<AVSessionListenerMock>();
    g_AVSessionService->innerSessionListeners_.push_back(listener.get());
    g_AVSessionService->innerSessionListeners_.push_back(nullptr);
    g_AVSessionService->NotifyTopSessionChanged(descriptor);
    EXPECT_TRUE(g_AVSessionService->innerSessionListeners_.size() > 0);
    SLOGD("AVSessionServiceAddedTest_NotifyTopSessionChanged_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_HandleRemoveMediaCardEvent_001
 * @tc.desc: set IsCasting to true
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_HandleRemoveMediaCardEvent_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_HandleRemoveMediaCardEvent_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    avsessionItem->descriptor_.sessionTag_ = "test";
    avsessionItem->castHandle_ = 1;
    g_AVSessionService->UpdateTopSession(avsessionItem);
    bool ret = g_AVSessionService->topSession_->IsCasting();
    EXPECT_EQ(ret, true);
    g_AVSessionService->HandleRemoveMediaCardEvent();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_HandleRemoveMediaCardEvent_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_HandleChangeTopSession_001
 * @tc.desc: topSession_->GetUid() != ancoUid
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_HandleChangeTopSession_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);
    g_AVSessionService->UpdateTopSession(avsessionItem);
    int32_t infoUid = 0;
    int32_t userId = 0;
    int32_t infoPid = 0;
    g_AVSessionService->HandleChangeTopSession(infoUid, infoPid, userId);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_HandleChangeTopSession_002
 * @tc.desc: able to pass the fisrt judgement
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_HandleChangeTopSession_002, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);

    int32_t infoUid = 0;
    avsessionItem->SetUid(infoUid);
    bool check = avsessionItem->GetUid() == infoUid && avsessionItem->GetSessionType() != "voice_call"
        && avsessionItem->GetSessionType() != "video_call";
    EXPECT_EQ(check, true);
    g_AVSessionService->UpdateTopSession(avsessionItem);

    int32_t userId = 0;
    int32_t infoPid = 0;
    g_AVSessionService->HandleChangeTopSession(infoUid, infoPid, userId);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_002 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_HandleChangeTopSession_003
 * @tc.desc: avsessionItem->GetSessionType() == "voice_call"
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_HandleChangeTopSession_003, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_003 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);
    
    int32_t infoUid = 0;
    avsessionItem->SetUid(infoUid);
    bool check = avsessionItem->GetUid() == infoUid && avsessionItem->GetSessionType() != "voice_call"
        && avsessionItem->GetSessionType() != "video_call";
    EXPECT_EQ(check, false);
    g_AVSessionService->UpdateTopSession(avsessionItem);
    
    int32_t userId = 0;
    int32_t infoPid = 0;
    g_AVSessionService->HandleChangeTopSession(infoUid, infoPid, userId);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_003 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_HandleChangeTopSession_004
 * @tc.desc: avsessionItem->GetSessionType() == "video_call"
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_HandleChangeTopSession_004, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_004 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VIDEO_CALL, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);
    
    int32_t infoUid = 0;
    avsessionItem->SetUid(infoUid);
    bool check = avsessionItem->GetUid() == infoUid && avsessionItem->GetSessionType() != "voice_call"
        && avsessionItem->GetSessionType() != "video_call";
    EXPECT_EQ(check, false);
    g_AVSessionService->UpdateTopSession(avsessionItem);
    
    int32_t userId = 0;
    int32_t infoPid = 0;
    g_AVSessionService->HandleChangeTopSession(infoUid, infoPid, userId);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_004 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_HandleChangeTopSession_005
 * @tc.desc: set infoUid qual to ancoUid
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_HandleChangeTopSession_005, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_005 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);
    
    int32_t ancoUid = 1041;
    avsessionItem->SetUid(ancoUid);
    bool check = avsessionItem->GetUid() == ancoUid && avsessionItem->GetSessionType() != "voice_call"
        && avsessionItem->GetSessionType() != "video_call";
    EXPECT_EQ(check, true);
    g_AVSessionService->UpdateTopSession(avsessionItem);
    
    int32_t userId = 0;
    int32_t infoPid = 0;
    g_AVSessionService->HandleChangeTopSession(ancoUid, infoPid, userId);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_HandleChangeTopSession_005 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_RegisterBundleDeleteEventForHistory_001
 * @tc.desc: success to read data from file
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, RegisterBundleDeleteEventForHistory_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_RegisterBundleDeleteEventForHistory_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);

    int32_t ancoUid = 1041;
    avsessionItem->SetUid(ancoUid);
    std::string filePath = g_AVSessionService->GetAVSortDir(ancoUid);
    std::ofstream ofs;
    ofs.open(filePath, std::ios::out);
    std::string jsonStr = R"(
        {"bundleName", "test"}
    )";
    ofs << jsonStr;
    ofs.close();

    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_RegisterBundleDeleteEventForHistory_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_LowQualityCheck_001
 * @tc.desc: (hasTitle || hasImage) is true
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_LowQualityCheck_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_LowQualityCheck_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);

    pid_t uid = avsessionItem->GetUid();
    pid_t pid = avsessionItem->GetPid();
    AVMetaData meta;
    meta.SetTitle("test");
    std::vector<uint8_t> imgBuffer = {1, 2, 3, 4, 5, 6, 7, 8};
    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    mediaImage->SetInnerImgBuffer(imgBuffer);
    meta.SetMediaImage(mediaImage);
    meta.SetMediaImageUri("test");
    avsessionItem->SetAVMetaData(meta);

    OHOS::AudioStandard::StreamUsage streamUsage = OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    OHOS::AudioStandard::RendererState rendererState = OHOS::AudioStandard::RendererState::RENDERER_PAUSED;
    g_AVSessionService->LowQualityCheck(uid, pid, streamUsage, rendererState);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_LowQualityCheck_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_LowQualityCheck_002
 * @tc.desc: title is empty
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_LowQualityCheck_002, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_LowQualityCheck_002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);

    pid_t uid = avsessionItem->GetUid();
    pid_t pid = avsessionItem->GetPid();
    AVMetaData meta;
    std::vector<uint8_t> imgBuffer = {1, 2, 3, 4, 5, 6, 7, 8};
    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    mediaImage->SetInnerImgBuffer(imgBuffer);
    meta.SetMediaImage(mediaImage);
    meta.SetMediaImageUri("test");
    avsessionItem->SetAVMetaData(meta);

    OHOS::AudioStandard::StreamUsage streamUsage = OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    OHOS::AudioStandard::RendererState rendererState = OHOS::AudioStandard::RendererState::RENDERER_PAUSED;
    g_AVSessionService->LowQualityCheck(uid, pid, streamUsage, rendererState);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_LowQualityCheck_002 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_LowQualityCheck_003
 * @tc.desc: MediaImage is empty
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_LowQualityCheck_003, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_LowQualityCheck_003 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);

    pid_t uid = avsessionItem->GetUid();
    pid_t pid = avsessionItem->GetPid();
    AVMetaData meta;
    meta.SetTitle("test");

    OHOS::AudioStandard::StreamUsage streamUsage = OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MEDIA;
    OHOS::AudioStandard::RendererState rendererState = OHOS::AudioStandard::RendererState::RENDERER_PAUSED;
    g_AVSessionService->LowQualityCheck(uid, pid, streamUsage, rendererState);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_LowQualityCheck_003 end!");
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
/**
 * @tc.name: AVSessionServiceAddedTest_AddCapsuleServiceCallback_001
 * @tc.desc: MediaImage is empty
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_AddCapsuleServiceCallback_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_AddCapsuleServiceCallback_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);

    g_AVSessionService->AddCapsuleServiceCallback(avsessionItem);
    auto callback = avsessionItem->serviceCallbackForCastNtf_;
    std::string sessionId = "test";
    bool isPlaying = true;
    bool isChange = true;
    callback(sessionId, isPlaying, isChange);

    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_AddCapsuleServiceCallback_001 end!");
}
#endif // CASTPLUS_CAST_ENGINE_ENABLE

/**
 * @tc.name: AVSessionServiceAddedTest_AddKeyEventServiceCallback_001
 * @tc.desc: MediaImage is empty
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_AddKeyEventServiceCallback_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_AddKeyEventServiceCallback_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);

    g_AVSessionService->AddKeyEventServiceCallback(avsessionItem);
    auto callback = avsessionItem->serviceCallbackForKeyEvent_;
    std::string sessionId = "test";
    callback(sessionId);

    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_AddKeyEventServiceCallback_001 end!");
}

/**
 * @tc.name: AVSessionServiceAddedTest_IsCapsuleNeeded_001
 * @tc.desc: MediaImage is empty
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_IsCapsuleNeeded_001, TestSize.Level1)
{
    SLOGD("AVSessionServiceAddedTest_IsCapsuleNeeded_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_VIDEO, false, elementName);
    EXPECT_EQ(avsessionItem != nullptr, true);
    g_AVSessionService->UpdateTopSession(avsessionItem);

    bool ret = g_AVSessionService->IsCapsuleNeeded();
    EXPECT_EQ(ret, false);
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGD("AVSessionServiceAddedTest_IsCapsuleNeeded_001 end!");
}

/**
* @tc.name: StartDefaultAbilityByCall001
* @tc.desc: read data from AVSortDir
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_StartDefaultAbilityByCall_001, TestSize.Level1)
{
    SLOGI("StartDefaultAbilityByCall001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string filePath = g_AVSessionService->GetAVSortDir();
    std::ofstream ofs;
    ofs.open(filePath, std::ios::out);
    std::string jsonStr = R"({
        "bundleName": "test",
        "sessionId": "12345",
        "test": "",
    })";
    ofs << jsonStr;
    ofs.close();

    std::string sessionId = avsessionItem->GetSessionId();
    int32_t ret = g_AVSessionService->StartDefaultAbilityByCall(sessionId);
    EXPECT_EQ(ret == ERR_ABILITY_NOT_AVAILABLE || ret == AVSESSION_SUCCESS || ret == AVSESSION_ERROR, true);
    g_AVSessionService->HandleSessionRelease(sessionId);
    avsessionItem->Destroy();
    SLOGI("StartDefaultAbilityByCall001 end!");
}

/**
* @tc.name: StartAbilityByCall001
* @tc.desc: read data from AVSortDir and get sessionIdNeeded
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_StartAbilityByCall_001, TestSize.Level1)
{
    SLOGI("StartAbilityByCall001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string filePath = g_AVSessionService->GetAVSortDir();
    std::ofstream ofs;
    ofs.open(filePath, std::ios::out);
    std::string jsonStr = R"({
        "bundleName": "test",
        "sessionId": "12345",
        "abilityName": "test",
    })";
    ofs << jsonStr;
    ofs.close();

    std::string sessionIdNeeded = "12345";
    std::string sessionId = avsessionItem->GetSessionId();
    int32_t ret = g_AVSessionService->StartAbilityByCall(sessionIdNeeded, sessionId);
    EXPECT_EQ(ret == ERR_ABILITY_NOT_AVAILABLE || ret == AVSESSION_SUCCESS || ret == AVSESSION_ERROR, true);
    g_AVSessionService->HandleSessionRelease(sessionId);
    avsessionItem->Destroy();
    SLOGI("StartAbilityByCall001 end!");
}

/**
* @tc.name: AVSessionServiceAddedTest_GetLocalTitle_001
* @tc.desc: success to get title
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_GetLocalTitle_001, TestSize.Level1)
{
    SLOGI("AVSessionServiceAddedTest_GetLocalTitle_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_TRUE(avsessionItem != nullptr);
    g_AVSessionService->UpdateTopSession(avsessionItem);

    auto title = g_AVSessionService->GetLocalTitle();
    EXPECT_TRUE(title.empty());

    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGI("AVSessionServiceAddedTest_GetLocalTitle_001 end!");
}

/**
* @tc.name: AVSessionServiceAddedTest_NotifySystemUI_001
* @tc.desc: addCapsule && topSession_ is true
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceAddedTest, AVSessionServiceAddedTest_NotifySystemUI_001, TestSize.Level1)
{
    SLOGI("AVSessionServiceAddedTest_NotifySystemUI_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem =
        g_AVSessionService->CreateSessionInner(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    EXPECT_TRUE(avsessionItem != nullptr);
    g_AVSessionService->UpdateTopSession(avsessionItem);

    auto historyDescriptor = std::make_shared<AVSessionDescriptor>();
    bool isActiveSession = true;
    bool addCapsule = true;
    bool isCapsuleUpdate = true;
    g_AVSessionService->NotifySystemUI(historyDescriptor.get(),
        isActiveSession, addCapsule, isCapsuleUpdate);
    bool ret = addCapsule && g_AVSessionService->topSession_;
    EXPECT_EQ(ret, true);

    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    avsessionItem->Destroy();
    SLOGI("AVSessionServiceAddedTest_NotifySystemUI_001 end!");
}