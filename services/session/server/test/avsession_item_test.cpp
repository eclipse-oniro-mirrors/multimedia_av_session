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
#include <chrono>
#include <thread>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_log.h"
#include "migrate_avsession_constant.h"
#include "system_ability_definition.h"
#include "avsession_service.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static std::shared_ptr<MigrateAVSessionServer> g_MigrateAVSessionServer {nullptr};
static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};
static OHOS::sptr<AVSessionItem> g_AVSessionItem {nullptr};
static OHOS::sptr<AVControllerItem> g_AVControllerItem {nullptr};

class AVsessionItemTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class AVSessionCallbackImpl : public AVSessionCallback {
public:
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override {};
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward(int64_t time) override {};
    void OnRewind(int64_t time) override {};
    void OnSeek(int64_t time) override {};
    void OnSetSpeed(double speed) override {};
    void OnSetLoopMode(int32_t loopMode) override {};
    void OnSetTargetLoopMode(int32_t targetLoopMode) override {};
    void OnToggleFavorite(const std::string& mediaId) override {};
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override {};
    void OnOutputDeviceChange(const int32_t connectionState,
        const OHOS::AVSession::OutputDeviceInfo& outputDeviceInfo) override {};
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override {};
    void OnSkipToQueueItem(int32_t itemId) override {};
    void OnAVCallAnswer() override {};
    void OnAVCallHangUp() override {};
    void OnAVCallToggleCallMute() override {};
    void OnPlayFromAssetId(int64_t assetId) override {};
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override {};

    ~AVSessionCallbackImpl() override;
};

class MockIAVCastControllerProxy : public OHOS::AVSession::IAVCastControllerProxy {
    void Release() override {}
    int32_t RegisterControllerListener(const
        std::shared_ptr<IAVCastControllerProxyListener> listener) override { return 0; }
    int32_t UnRegisterControllerListener(const
        std::shared_ptr<IAVCastControllerProxyListener> listener) override { return 0; }
    AVQueueItem GetCurrentItem() override { return AVQueueItem(); }
    int32_t Start(const AVQueueItem& item) override { return 0; }
    int32_t Prepare(const AVQueueItem& item) override { return 0; }
    void SendControlCommand(const AVCastControlCommand cmd) override {}
    int32_t GetDuration(int32_t& duration) override { return 0; }
    int32_t GetCastAVPlaybackState(AVPlaybackState& state) override { return 0; }
    int32_t SetValidAbility(const std::vector<int32_t>& validAbilityList) override { return 0; }
    int32_t GetValidAbility(std::vector<int32_t>& validAbilityList) override { return 0; }
    int32_t SetDisplaySurface(std::string& surfaceId) override { return 0; }
    int32_t ProcessMediaKeyResponse(const
        std::string& assetId, const std::vector<uint8_t>& response) override { return 0; }
    int32_t GetSupportedDecoders(std::vector<std::string>& decoderTypes) override { return 0; }
    int32_t GetRecommendedResolutionLevel(std::string& decoderType, ResolutionLevel& resolutionLevel)
        override { return 0; }
    int32_t GetSupportedHdrCapabilities(std::vector<HDRFormat>& hdrFormats) override { return 0; }
    int32_t GetSupportedPlaySpeeds(std::vector<float>& playSpeeds) override { return 0; }
};

void AVsessionItemTest::SetUpTestCase()
{
    SLOGI("AVsessionItemTest SetUpTestCase");
    g_MigrateAVSessionServer = std::make_shared<MigrateAVSessionServer>();
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID, true);
    g_AVSessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    g_AVControllerItem = g_AVSessionService->CreateNewControllerForSession(
        g_AVSessionItem->GetPid(), g_AVSessionItem);
}

void AVsessionItemTest::TearDownTestCase()
{
    SLOGI("AVsessionItemTest TearDownTestCase");
    g_AVSessionService->HandleSessionRelease(g_AVSessionItem->GetSessionId());
    g_AVControllerItem->Destroy();
    g_AVSessionItem->Destroy();
}

void AVsessionItemTest::SetUp()
{}

void AVsessionItemTest::TearDown()
{}

/**
 * @tc.name: AVSessionItem_DestroyTask_001
 * @tc.desc: Test DestroyTask when the session is already destroyed.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_DestroyTask_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_DestroyTask_001 begin!");
    g_AVSessionItem->isDestroyed_ = true;
    int32_t result = g_AVSessionItem->DestroyTask(false);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_DestroyTask_001 end!");
}

/**
 * @tc.name: AVSessionItem_DestroyTask_002
 * @tc.desc: Test DestroyTask with no valid controllers in the controllers list.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_DestroyTask_002, TestSize.Level1)
{
    SLOGD("AVSessionItem_DestroyTask_002 begin!");
    g_AVSessionItem->controllers_.clear();
    int32_t result = g_AVSessionItem->DestroyTask(false);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_DestroyTask_002 end!");
}

/**
 * @tc.name: AVSessionItem_DestroyTask_003
 * @tc.desc: Test DestroyTask with castHandle_ > 0 but sessionTag_ is "RemoteCast".
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_DestroyTask_003, TestSize.Level1)
{
    SLOGD("AVSessionItem_DestroyTask_003 begin!");
    g_AVSessionItem->descriptor_.sessionTag_ = "RemoteCast";
    g_AVSessionItem->castHandle_ = 1;
    int32_t result = g_AVSessionItem->DestroyTask(false);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_DestroyTask_003 end!");
}

/**
 * @tc.name: AVSessionItem_DestroyTask_004
 * @tc.desc: Test DestroyTask with castHandle_ > 0 and sessionTag_ is not "RemoteCast".
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_DestroyTask_004, TestSize.Level1)
{
    SLOGD("AVSessionItem_DestroyTask_004 begin!");
    g_AVSessionItem->descriptor_.sessionTag_ = "TestSession";
    g_AVSessionItem->castHandle_ = 1;
    int32_t result = g_AVSessionItem->DestroyTask(false);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_DestroyTask_004 end!");
}

/**
 * @tc.name: AVSessionItem_SetAVCallMetaData_001
 * @tc.desc: Test SetAVCallMetaData with valid media image in AVCallMetaData.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetAVCallMetaData_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetAVCallMetaData_001 begin!");
    OHOS::AVSession::AVCallMetaData avCallMetaData;
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    avCallMetaData.SetMediaImage(innerPixelMap);
    int32_t result = g_AVSessionItem->SetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_SetAVCallMetaData_001 end!");
}

/**
 * @tc.name: AVSessionItem_SetAVCallMetaData_002
 * @tc.desc: Test SetAVCallMetaData with no valid controllers in the controllers list.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetAVCallMetaData_002, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetAVCallMetaData_002 begin!");
    g_AVSessionItem->controllers_.clear();
    OHOS::AVSession::AVCallMetaData avCallMetaData;
    avCallMetaData.SetName("TestName");
    avCallMetaData.SetPhoneNumber("123456789");
    int32_t result = g_AVSessionItem->SetAVCallMetaData(avCallMetaData);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_SetAVCallMetaData_002 end!");
}

/**
 * @tc.name: AVSessionItem_SetLaunchAbility_001
 * @tc.desc: Test SetLaunchAbility with want being nullptr.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetLaunchAbility_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetLaunchAbility_001 begin!");
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    int32_t result = g_AVSessionItem->SetLaunchAbility(ability);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_SetLaunchAbility_001 end!");
}

/**
 * @tc.name: AVSessionItem_SetLaunchAbility_003
 * @tc.desc: Test SetLaunchAbility with valid want and launWantAgent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetLaunchAbility_003, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetLaunchAbility_003 begin!");
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> launWantAgent =
        std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(ability);
    int32_t result = g_AVSessionItem->SetLaunchAbility(ability);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_SetLaunchAbility_003 end!");
}

/**
 * @tc.name: AVSessionItem_Activate_001
 * @tc.desc: Test Activate with valid controllers.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_Activate_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_Activate_001 begin!");
    OHOS::sptr<AVControllerItem> controller = g_AVControllerItem;
    g_AVSessionItem->controllers_[controller->GetPid()] = controller;
    int32_t result = g_AVSessionItem->Activate();
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_Activate_001 end!");
}

/**
 * @tc.name: AVSessionItem_Activate_002
 * @tc.desc: Test Activate with session type not being voice or video call.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_Activate_002, TestSize.Level1)
{
    SLOGD("AVSessionItem_Activate_002 begin!");
    g_AVSessionItem->descriptor_.sessionType_ = AVSession::SESSION_TYPE_VOICE_CALL;
    int32_t result = g_AVSessionItem->Activate();
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_Activate_002 end!");
}

/**
 * @tc.name: AVSessionItem_Activate_003
 * @tc.desc: Test Activate with session type being voice or video call.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_Activate_003, TestSize.Level1)
{
    SLOGD("AVSessionItem_Activate_003 begin!");
    g_AVSessionItem->descriptor_.sessionType_ = AVSession::SESSION_TYPE_VIDEO_CALL;
    int32_t result = g_AVSessionItem->Activate();
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_Activate_003 end!");
}

/**
 * @tc.name: AVSessionItem_GetAnonymousDeviceId_001
 * @tc.desc: Test GetAnonymousDeviceId with empty deviceId.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_GetAnonymousDeviceId_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_GetAnonymousDeviceId_001 begin!");
    std::string deviceId = "";
    std::string result = g_AVSessionItem->GetAnonymousDeviceId(deviceId);
    EXPECT_EQ(result, "unknown");
    SLOGD("AVSessionItem_GetAnonymousDeviceId_001 end!");
}

/**
 * @tc.name: AVSessionItem_GetAnonymousDeviceId_002
 * @tc.desc: Test GetAnonymousDeviceId with deviceId length less than DEVICE_ID_MIN_LEN.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_GetAnonymousDeviceId_002, TestSize.Level1)
{
    SLOGD("AVSessionItem_GetAnonymousDeviceId_002 begin!");
    std::string deviceId = "12345";
    std::string result = g_AVSessionItem->GetAnonymousDeviceId(deviceId);
    EXPECT_EQ(result, "unknown");
    SLOGD("AVSessionItem_GetAnonymousDeviceId_002 end!");
}

/**
 * @tc.name: AVSessionItem_GetAnonymousDeviceId_003
 * @tc.desc: Test GetAnonymousDeviceId with deviceId length greater than or equal to DEVICE_ID_MIN_LEN.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_GetAnonymousDeviceId_003, TestSize.Level1)
{
    SLOGD("AVSessionItem_GetAnonymousDeviceId_003 begin!");
    std::string deviceId = "1234567890";
    std::string result = g_AVSessionItem->GetAnonymousDeviceId(deviceId);
    EXPECT_NE(result, "unknown");
    SLOGD("AVSessionItem_GetAnonymousDeviceId_003 end!");
}

/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_001
 * @tc.desc: Test RegisterListenerStreamToCast with castHandle_ > 0.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_001 begin!");
    g_AVSessionItem->castHandle_ = 1;
    std::map<std::string, std::string> serviceNameMapState;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameMapState, deviceInfo);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_001 end!");
}

/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_002
 * @tc.desc: Test RegisterListenerStreamToCast with GetMirrorCastHandle() == -1.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_002, TestSize.Level1)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_002 begin!");
    g_AVSessionItem->castHandle_ = AVSESSION_ERROR;
    std::map<std::string, std::string> serviceNameMapState;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameMapState, deviceInfo);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_002 end!");
}

/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_003
 * @tc.desc: Test RegisterListenerStreamToCast with castControllerProxy_ and GetDescription() != nullptr.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_003, TestSize.Level1)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_003 begin!");
    g_AVSessionItem->castHandle_ = 0;
    std::map<std::string, std::string> serviceNameMapState;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    
    auto mockCastControllerProxy = std::make_shared<MockIAVCastControllerProxy>();
    g_AVSessionItem->castControllerProxy_ = mockCastControllerProxy;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameMapState, deviceInfo);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_003 end!");
}


/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_004
 * @tc.desc: Test RegisterListenerStreamToCast with castControllerProxy_ == nullptr and castHandle_ <= 0.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_004, TestSize.Level1)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_004 begin!");
    g_AVSessionItem->castHandle_ = 0;
    std::map<std::string, std::string> serviceNameMapState;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    g_AVSessionItem->castControllerProxy_ = nullptr;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameMapState, deviceInfo);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_004 end!");
}

/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_005
 * @tc.desc: Test RegisterListenerStreamToCast with GetCurrentItem().GetDescription() == nullptr and castHandle_ <= 0.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_005, TestSize.Level1)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_005 begin!");
    g_AVSessionItem->castHandle_ = 0;
    std::map<std::string, std::string> serviceNameMapState;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    
    auto mockCastControllerProxy = std::make_shared<MockIAVCastControllerProxy>();
    g_AVSessionItem->castControllerProxy_ = mockCastControllerProxy;
    AVQueueItem item;
    item.description_ = nullptr;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameMapState, deviceInfo);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_005 end!");
}


/**
 * @tc.name: AVSessionItem_SetOutputDevice_001
 * @tc.desc: Test SetOutputDevice with controllers not empty.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetOutputDevice_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetOutputDevice_001 begin!");
    OutputDeviceInfo info;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "DeviceId1";
    deviceInfo.deviceName_ = "DeviceName1";
    deviceInfo.deviceType_ = 1;
    info.deviceInfos_.push_back(deviceInfo);
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    g_AVSessionItem->SetOutputDevice(info);
    EXPECT_TRUE(g_AVSessionItem->descriptor_.outputDeviceInfo_.deviceInfos_[0].deviceId_ == "DeviceId1");
    EXPECT_TRUE(g_AVSessionItem->descriptor_.outputDeviceInfo_.deviceInfos_[0].deviceName_ == "DeviceName1");
    EXPECT_TRUE(g_AVSessionItem->descriptor_.outputDeviceInfo_.deviceInfos_[0].deviceType_ == 1);
    SLOGD("AVSessionItem_SetOutputDevice_001 end!");
}

/**
 * @tc.name: AVSessionItem_SetOutputDevice_002
 * @tc.desc: Test SetOutputDevice with controllers empty.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetOutputDevice_002, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetOutputDevice_002 begin!");
    OutputDeviceInfo info;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "DeviceId1";
    deviceInfo.deviceName_ = "DeviceName1";
    deviceInfo.deviceType_ = 1;
    info.deviceInfos_.push_back(deviceInfo);
    g_AVSessionItem->controllers_.clear();
    g_AVSessionItem->SetOutputDevice(info);
    EXPECT_TRUE(g_AVSessionItem->descriptor_.outputDeviceInfo_.deviceInfos_[0].deviceId_ == "DeviceId1");
    EXPECT_TRUE(g_AVSessionItem->descriptor_.outputDeviceInfo_.deviceInfos_[0].deviceName_ == "DeviceName1");
    EXPECT_TRUE(g_AVSessionItem->descriptor_.outputDeviceInfo_.deviceInfos_[0].deviceType_ == 1);
    SLOGD("AVSessionItem_SetOutputDevice_002 end!");
}