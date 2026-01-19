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
#include <new>
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
#include "int_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

namespace OHOS {
namespace AVSession {

static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static std::shared_ptr<MigrateAVSessionServer> g_MigrateAVSessionServer {nullptr};
static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};
static OHOS::sptr<AVSessionItem> g_AVSessionItem {nullptr};
static OHOS::sptr<AVControllerItem> g_AVControllerItem {nullptr};

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
static const int32_t REPORT_SIZE = 100;
static const int32_t CONTROL_COLD_START = 2;
#endif


class AVsessionItemTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class AVSessionCallbackImpl : public IAVSessionCallback {
public:
    ErrCode OnPlay(const AVControlCommand& cmd) override { return AVSESSION_SUCCESS; };
    ErrCode OnPause() override { return AVSESSION_SUCCESS; };
    ErrCode OnStop() override { return AVSESSION_SUCCESS; };
    ErrCode OnPlayNext(const AVControlCommand& cmd) override { return AVSESSION_SUCCESS; };
    ErrCode OnPlayPrevious(const AVControlCommand& cmd) override { return AVSESSION_SUCCESS; };
    ErrCode OnFastForward(int64_t time, const AVControlCommand& cmd) override { return AVSESSION_SUCCESS; };
    ErrCode OnRewind(int64_t time, const AVControlCommand& cmd) override { return AVSESSION_SUCCESS; };
    ErrCode OnSeek(int64_t time) override { return AVSESSION_SUCCESS; };
    ErrCode OnSetSpeed(double speed) override { return AVSESSION_SUCCESS; };
    ErrCode OnSetLoopMode(int32_t loopMode) override { return AVSESSION_SUCCESS; };
    ErrCode OnSetTargetLoopMode(int32_t targetLoopMode) override { return AVSESSION_SUCCESS; };
    ErrCode OnToggleFavorite(const std::string& mediaId) override { return AVSESSION_SUCCESS; };
    ErrCode OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override { return AVSESSION_SUCCESS; };
    ErrCode OnOutputDeviceChange(const int32_t connectionState,
        const OHOS::AVSession::OutputDeviceInfo& outputDeviceInfo) override { return AVSESSION_SUCCESS; };
    ErrCode OnCommonCommand(const std::string& commonCommand,
        const OHOS::AAFwk::WantParams& commandArgs) override { return AVSESSION_SUCCESS; };
    ErrCode OnSkipToQueueItem(int32_t itemId) override { return AVSESSION_SUCCESS; };
    ErrCode OnAVCallAnswer() override { return AVSESSION_SUCCESS; };
    ErrCode OnAVCallHangUp() override { return AVSESSION_SUCCESS; };
    ErrCode OnAVCallToggleCallMute() override { return AVSESSION_SUCCESS; };
    ErrCode OnPlayFromAssetId(int64_t assetId) override { return AVSESSION_SUCCESS; };
    ErrCode OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override { return AVSESSION_SUCCESS; };
    sptr<IRemoteObject> AsObject() override { return nullptr; }
    ErrCode OnPlayWithAssetId(const std::string& assetId) override { return AVSESSION_SUCCESS; };
    ErrCode OnCustomData(const OHOS::AAFwk::WantParams& data) override { return AVSESSION_SUCCESS; };
    ErrCode OnDesktopLyricVisibilityChanged(bool isVisible) override { return AVSESSION_SUCCESS; };
    ErrCode OnDesktopLyricStateChanged(const DesktopLyricState &state) override { return AVSESSION_SUCCESS; };

    AVSessionCallbackImpl() = default;
    ~AVSessionCallbackImpl() = default;
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
    int32_t RefreshCurrentAVQueueItem(const AVQueueItem& avQueueItem) override {return 0;}
    void SetSessionCallbackForCastCap(const std::function<void(bool, bool)>& callback) override {}
    void SetSpid(uint32_t spid) override {}
};

class MockAVSessionItemExtension : public AVSessionItemExtension {
public:
    int32_t StartDesktopLyricAbility(const std::string &sessionId, const std::string &handler)
        override { return isStartSuccend; }
    int32_t UploadDesktopLyricOperationInfo(const std::string &sessionId,
        const std::string &handler, uint32_t sceneCode) override { return 0; }
    int32_t isStartSuccend = 0; // is start success
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
HWTEST_F(AVsessionItemTest, AVSessionItem_DestroyTask_001, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_DestroyTask_002, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_DestroyTask_003, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_DestroyTask_004, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_SetAVCallMetaData_001, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_SetAVCallMetaData_002, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_SetLaunchAbility_001, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_SetLaunchAbility_003, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_Activate_001, TestSize.Level0)
{
    SLOGD("AVSessionItem_Activate_001 begin!");
    OHOS::sptr<AVControllerItem> controller = g_AVControllerItem;
    g_AVSessionItem->controllers_[controller->GetPid()] = controller;
    int32_t result = g_AVSessionItem->Activate();
    g_AVSessionItem->descriptor_.isActive_ = false;
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_Activate_001 end!");
}

/**
 * @tc.name: AVSessionItem_Activate_002
 * @tc.desc: Test Activate with session type not being voice or video call.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_Activate_002, TestSize.Level0)
{
    SLOGD("AVSessionItem_Activate_002 begin!");
    g_AVSessionItem->descriptor_.sessionType_ = AVSession::SESSION_TYPE_VOICE_CALL;
    int32_t result = g_AVSessionItem->Activate();
    g_AVSessionItem->descriptor_.isActive_ = false;
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_Activate_002 end!");
}

/**
 * @tc.name: AVSessionItem_Activate_003
 * @tc.desc: Test Activate with session type being voice or video call.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_Activate_003, TestSize.Level0)
{
    SLOGD("AVSessionItem_Activate_003 begin!");
    g_AVSessionItem->descriptor_.sessionType_ = AVSession::SESSION_TYPE_VIDEO_CALL;
    int32_t result = g_AVSessionItem->Activate();
    g_AVSessionItem->descriptor_.isActive_ = false;
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_Activate_003 end!");
}

/**
 * @tc.name: AVSessionItem_UpdateElement_001
 * @tc.desc: Test update session element.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_UpdateElement_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_UpdateElement_001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("TestBundleName");
    elementName.SetAbilityName("TestAbilityName");
    g_AVSessionItem->UpdateSessionElement(elementName);
    EXPECT_EQ(g_AVSessionItem->GetBundleName(), "TestBundleName");
    EXPECT_EQ(g_AVSessionItem->GetAbilityName(), "TestAbilityName");

    OHOS::AppExecFwk::ElementName oriElementName;
    oriElementName.SetBundleName(g_testAnotherBundleName);
    oriElementName.SetAbilityName(g_testAnotherAbilityName);
    g_AVSessionItem->UpdateSessionElement(oriElementName);
    EXPECT_EQ(g_AVSessionItem->GetBundleName(), g_testAnotherBundleName);
    EXPECT_EQ(g_AVSessionItem->GetAbilityName(), g_testAnotherAbilityName);
    SLOGD("AVSessionItem_UpdateElement_001 end!");
}

/**
 * @tc.name: AVSessionItem_GetAnonymousDeviceId_001
 * @tc.desc: Test GetAnonymousDeviceId with empty deviceId.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_GetAnonymousDeviceId_001, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_GetAnonymousDeviceId_002, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_GetAnonymousDeviceId_003, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_001, TestSize.Level0)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_001 begin!");
    g_AVSessionItem->castHandle_ = 1;
    std::pair<std::string, std::string> serviceNameStatePair;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameStatePair, deviceInfo);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_001 end!");
}

/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_002
 * @tc.desc: Test RegisterListenerStreamToCast with GetMirrorCastHandle() == -1.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_002, TestSize.Level0)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_002 begin!");
    g_AVSessionItem->castHandle_ = AVSESSION_ERROR;
    std::pair<std::string, std::string> serviceNameStatePair;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameStatePair, deviceInfo);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_002 end!");
}

/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_003
 * @tc.desc: Test RegisterListenerStreamToCast with castControllerProxy_ and GetDescription() != nullptr.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_003, TestSize.Level0)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_003 begin!");
    g_AVSessionItem->castHandle_ = 0;
    std::pair<std::string, std::string> serviceNameStatePair;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    
    auto mockCastControllerProxy = std::make_shared<MockIAVCastControllerProxy>();
    g_AVSessionItem->castControllerProxy_ = mockCastControllerProxy;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameStatePair, deviceInfo);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_003 end!");
}


/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_004
 * @tc.desc: Test RegisterListenerStreamToCast with castControllerProxy_ == nullptr and castHandle_ <= 0.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_004, TestSize.Level0)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_004 begin!");
    g_AVSessionItem->castHandle_ = 0;
    std::pair<std::string, std::string> serviceNameStatePair;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "1234567890";
    deviceInfo.deviceName_ = "TestDevice";
    deviceInfo.deviceType_ = 1;
    deviceInfo.networkId_ = "12345";
    deviceInfo.supportedProtocols_ = 2;
    g_AVSessionItem->castControllerProxy_ = nullptr;
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameStatePair, deviceInfo);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_004 end!");
}

/**
 * @tc.name: AVSessionItem_RegisterListenerStreamToCast_005
 * @tc.desc: Test RegisterListenerStreamToCast with GetCurrentItem().GetDescription() == nullptr and castHandle_ <= 0.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_RegisterListenerStreamToCast_005, TestSize.Level0)
{
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_005 begin!");
    g_AVSessionItem->castHandle_ = 0;
    std::pair<std::string, std::string> serviceNameStatePair;
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
    int32_t result = g_AVSessionItem->RegisterListenerStreamToCast(serviceNameStatePair, deviceInfo);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_RegisterListenerStreamToCast_005 end!");
}


/**
 * @tc.name: AVSessionItem_SetOutputDevice_001
 * @tc.desc: Test SetOutputDevice with controllers not empty.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetOutputDevice_001, TestSize.Level0)
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
HWTEST_F(AVsessionItemTest, AVSessionItem_SetOutputDevice_002, TestSize.Level0)
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

/**
 * @tc.name: AVSessionItem_HandleOnSetTargetLoopMode_001
 * @tc.desc: Test HandleOnSetTargetLoopMode.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_HandleOnSetTargetLoopMode_001, TestSize.Level0)
{
    SLOGD("AVSessionItem_HandleOnSetTargetLoopMode_001 begin!");
    OHOS::sptr<IAVSessionCallback> callback = new(std::nothrow) AVSessionCallbackImpl();
    ASSERT_TRUE(callback != nullptr);
    g_AVSessionItem->callback_ = callback;
    AVControlCommand cmd;
    cmd.SetCommand(AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE);
    g_AVSessionItem->HandleOnSetTargetLoopMode(cmd);
    int32_t targetLoopMode = AVSESSION_ERROR;
    auto ret = cmd.GetTargetLoopMode(targetLoopMode);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_HandleOnSetTargetLoopMode_001 end!");
}

/**
 * @tc.name: AVSessionItem_DelRecommend_001
 * @tc.desc: Test DelRecommend.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_DelRecommend_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_DelRecommend_001 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    g_AVSessionItem->isRecommend_ = true;
    g_AVSessionItem->DelRecommend();
    EXPECT_EQ(g_AVSessionItem->isRecommend_, false);
    SLOGD("AVSessionItem_DelRecommend_001 end!");
}

/**
 * @tc.name: AVSessionItem_CheckIfSendCapsule_001
 * @tc.desc: Test CheckIfSendCapsule.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_CheckIfSendCapsule_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_CheckIfSendCapsule_001 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    int oriUid = g_AVSessionItem->GetUid();
    g_AVSessionItem->SetUid(5557);
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_AVSessionItem->CheckIfSendCapsule(state);
    EXPECT_EQ(g_AVSessionItem->isPlayingState_, true);
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PAUSE);
    g_AVSessionItem->CheckIfSendCapsule(state);
    EXPECT_EQ(g_AVSessionItem->isPlayingState_, false);
    g_AVSessionItem->SetUid(oriUid);
    SLOGD("AVSessionItem_CheckIfSendCapsule_001 end!");
}

#ifdef INPUT_REDISTRIBUTE_ENABLE
/**
 * @tc.name: AVSessionItem_SetSessionEvent_001
 * @tc.desc: Test SetSessionEvent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetSessionEvent_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetSessionEvent_001 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    std::string event = "InputRedistributeEvent";
    int32_t keyCode = 123456789;
    AAFwk::WantParams args;
    args.SetParam("keyCode", AAFwk::Integer::Box(static_cast<int32_t>(keyCode)));
    int32_t result = g_AVSessionItem->SetSessionEvent(event, args);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("AVSessionItem_SetSessionEvent_001 end!");
}

/**
 * @tc.name: AVSessionItem_SetSessionEvent_002
 * @tc.desc: Test SetSessionEvent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetSessionEvent_002, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetSessionEvent_002 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    std::string event = "InputRedistributeEvent";
    int32_t keyCode = MMI::KeyEvent::KEYCODE_SPACE;
    AAFwk::WantParams args;
    args.SetParam("keyCode", AAFwk::Integer::Box(static_cast<int32_t>(keyCode)));
    int32_t result = g_AVSessionItem->SetSessionEvent(event, args);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("AVSessionItem_SetSessionEvent_002 end!");
}

/**
 * @tc.name: AVSessionItem_SetSessionEvent_003
 * @tc.desc: Test SetSessionEvent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetSessionEvent_003, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetSessionEvent_003 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    std::string event = "InputRedistributeEvent";
    int32_t keyCode = MMI::KeyEvent::KEYCODE_DPAD_UP;
    AAFwk::WantParams args;
    args.SetParam("keyCode", AAFwk::Integer::Box(static_cast<int32_t>(keyCode)));
    int32_t result = g_AVSessionItem->SetSessionEvent(event, args);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("AVSessionItem_SetSessionEvent_003 end!");
}

/**
 * @tc.name: AVSessionItem_SetSessionEvent_004
 * @tc.desc: Test SetSessionEvent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetSessionEvent_004, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetSessionEvent_004 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    std::string event = "InputRedistributeEvent";
    int32_t keyCode = MMI::KeyEvent::KEYCODE_DPAD_DOWN;
    AAFwk::WantParams args;
    args.SetParam("keyCode", AAFwk::Integer::Box(static_cast<int32_t>(keyCode)));
    int32_t result = g_AVSessionItem->SetSessionEvent(event, args);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("AVSessionItem_SetSessionEvent_004 end!");
}

/**
 * @tc.name: AVSessionItem_SetSessionEvent_005
 * @tc.desc: Test SetSessionEvent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetSessionEvent_005, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetSessionEvent_005 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    std::string event = "InputRedistributeEvent";
    int32_t keyCode = MMI::KeyEvent::KEYCODE_DPAD_LEFT;
    AAFwk::WantParams args;
    args.SetParam("keyCode", AAFwk::Integer::Box(static_cast<int32_t>(keyCode)));
    int32_t result = g_AVSessionItem->SetSessionEvent(event, args);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("AVSessionItem_SetSessionEvent_005 end!");
}

/**
 * @tc.name: AVSessionItem_SetSessionEvent_006
 * @tc.desc: Test SetSessionEvent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetSessionEvent_006, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetSessionEvent_006 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    std::string event = "InputRedistributeEvent";
    int32_t keyCode = MMI::KeyEvent::KEYCODE_DPAD_RIGHT;
    AAFwk::WantParams args;
    args.SetParam("keyCode", AAFwk::Integer::Box(static_cast<int32_t>(keyCode)));
    int32_t result = g_AVSessionItem->SetSessionEvent(event, args);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("AVSessionItem_SetSessionEvent_006 end!");
}

/**
 * @tc.name: AVSessionItem_SetSessionEvent_007
 * @tc.desc: Test SetSessionEvent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_SetSessionEvent_007, TestSize.Level1)
{
    SLOGD("AVSessionItem_SetSessionEvent_007 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    std::string event = "OtherEvent";
    AAFwk::WantParams args;
    int32_t result = g_AVSessionItem->SetSessionEvent(event, args);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_SetSessionEvent_007 end!");
}

/**
 * @tc.name: AVSessionItem_ProcessInputRedistributeEvent_001
 * @tc.desc: Test ProcessInputRedistributeEvent.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_ProcessInputRedistributeEvent_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_ProcessInputRedistributeEvent_001 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    EXPECT_EQ(g_AVSessionItem->ProcessInputRedistributeEvent(MMI::KeyEvent::KEYCODE_SPACE), AVSESSION_ERROR);
    EXPECT_EQ(g_AVSessionItem->ProcessInputRedistributeEvent(MMI::KeyEvent::KEYCODE_DPAD_UP), AVSESSION_ERROR);
    EXPECT_EQ(g_AVSessionItem->ProcessInputRedistributeEvent(MMI::KeyEvent::KEYCODE_DPAD_DOWN), AVSESSION_ERROR);
    EXPECT_EQ(g_AVSessionItem->ProcessInputRedistributeEvent(MMI::KeyEvent::KEYCODE_DPAD_LEFT), AVSESSION_ERROR);
    EXPECT_EQ(g_AVSessionItem->ProcessInputRedistributeEvent(MMI::KeyEvent::KEYCODE_DPAD_RIGHT), AVSESSION_ERROR);
    SLOGD("AVSessionItem_ProcessInputRedistributeEvent_001 end!");
}

/**
 * @tc.name: AVSessionItem_IsKeyEventSupported_001
 * @tc.desc: Test IsKeyEventSupported.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_IsKeyEventSupported_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_IsKeyEventSupported_001 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    EXPECT_EQ(g_AVSessionItem->IsKeyEventSupported(""), false);
    EXPECT_EQ(g_AVSessionItem->IsKeyEventSupported("com.test"), false);
    SLOGD("AVSessionItem_IsKeyEventSupported_001 end!");
}

/**
 * @tc.name: AVSessionItem_UpdateVolume_001
 * @tc.desc: Test UpdateVolume.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_UpdateVolume_001, TestSize.Level1)
{
    SLOGD("AVSessionItem_UpdateVolume_001 begin!");
    EXPECT_NE(g_AVSessionItem, nullptr);
    EXPECT_EQ(g_AVSessionItem->UpdateVolume(true), AVSESSION_SUCCESS);
    EXPECT_EQ(g_AVSessionItem->UpdateVolume(false), AVSESSION_SUCCESS);
    SLOGD("AVSessionItem_UpdateVolume_001 end!");
}
#endif

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
/**
 * @tc.name: AVSessionItem_ReportPlaybackState_001
 * @tc.desc: Test ReportPlaybackState.
 * @tc.type: FUNC
 * @tc.require: #IC7XD5
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_ReportPlaybackState_001, TestSize.Level0)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    AVPlaybackState state;
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    g_AVSessionItem->ReportPlaybackState(state);
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PAUSE);
    g_AVSessionItem->ReportPlaybackState(state);
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PREPARE);
    g_AVSessionItem->ReportPlaybackState(state);

    auto stateInfo = AVSessionSysEvent::GetInstance().GetPlayingStateInfo(g_testAnotherBundleName);
    ASSERT_TRUE(stateInfo != nullptr);
    for (auto i = 0; i < REPORT_SIZE; i++) {
        stateInfo->playbackState_.push_back(0);
    }

    state.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    AVSessionSysEvent::GetInstance().UpdatePlaybackState(g_testAnotherBundleName, state.GetState());
    EXPECT_EQ(stateInfo->playbackState_.size(), 0);
}

/**
 * @tc.name: AVSessionItem_ReportMetadataChange_001
 * @tc.desc: Test ReportMetadataChange.
 * @tc.type: FUNC
 * @tc.require: #IC7XD5
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_ReportMetadataChange_001, TestSize.Level0)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    std::string title = "Test Title";
    std::string url = "Test Url";
    AVMetaData metadata;
    g_AVSessionItem->ReportMetadataChange(metadata);

    metadata.SetTitle(title);
    g_AVSessionItem->ReportMetadataChange(metadata);

    metadata.SetTitle("");
    metadata.SetMediaImageUri(url);
    g_AVSessionItem->ReportMetadataChange(metadata);

    auto stateInfo = AVSessionSysEvent::GetInstance().GetPlayingStateInfo(g_testAnotherBundleName);
    ASSERT_TRUE(stateInfo != nullptr);
    for (auto i = 0; i < REPORT_SIZE; i++) {
        stateInfo->metaQuality_.push_back(0);
    }

    AVSessionSysEvent::GetInstance().UpdateMetaQuality(g_testAnotherBundleName, MetadataQuality::METADATA_QUALITY_BOTH);
    EXPECT_EQ(stateInfo->metaQuality_.size(), 0);
}

/**
 * @tc.name: AVSessionItem_ReportCommandChange_001
 * @tc.desc: Test ReportCommandChange.
 * @tc.type: FUNC
 * @tc.require: #IC7XD5
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_ReportCommandChange_001, TestSize.Level0)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    g_AVSessionItem->supportedCmd_.push_back(REPORT_SIZE);
    g_AVSessionItem->ReportCommandChange();

    auto stateInfo = AVSessionSysEvent::GetInstance().GetPlayingStateInfo(g_testAnotherBundleName);
    ASSERT_TRUE(stateInfo != nullptr);
    for (auto i = 0; i < REPORT_SIZE; i++) {
        stateInfo->commandQuality_.push_back(0);
    }

    AVSessionSysEvent::GetInstance().UpdateCommandQuality(g_testAnotherBundleName, 0);
    EXPECT_EQ(stateInfo->commandQuality_.size(), 0);
}

/**
 * @tc.name: AVSessionItem_ReportSessionControl_001
 * @tc.desc: Test ReportSessionControl.
 * @tc.type: FUNC
 * @tc.require: #IC7XD5
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_ReportSessionControl_001, TestSize.Level0)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    g_AVSessionItem->ReportSessionControl(g_testAnotherBundleName, AVControlCommand::SESSION_CMD_PLAY);
    g_AVSessionItem->ReportSessionControl(g_testAnotherBundleName, AVControlCommand::SESSION_CMD_PAUSE);
    g_AVSessionItem->ReportSessionControl(g_testAnotherBundleName, CONTROL_COLD_START);
    g_AVSessionItem->ReportSessionControl(g_testAnotherBundleName, REPORT_SIZE);

    auto stateInfo = AVSessionSysEvent::GetInstance().GetPlayingStateInfo(g_testAnotherBundleName);
    ASSERT_TRUE(stateInfo != nullptr);
    for (auto i = 0; i < REPORT_SIZE; i++) {
        stateInfo->control_.push_back(0);
    }

    AVSessionSysEvent::GetInstance().ReportPlayingState(g_testAnotherBundleName);
    EXPECT_EQ(stateInfo->control_.size(), 0);
}
#endif

/**
 * @tc.name: AVSessionItem_CheckUseAVMetaData_001
 * @tc.desc: Test CheckIfSendCapsule.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_CheckUseAVMetaData_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_CheckUseAVMetaData_001 begin");
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    g_AVSessionItem->serviceCallbackForAddAVQueueInfo_ = nullptr;
    g_AVSessionItem->metaData_.SetAssetId("test");
    g_AVSessionItem->metaData_.SetTitle("test");
    g_AVSessionItem->CheckUseAVMetaData(g_AVSessionItem->metaData_);
    ASSERT_TRUE(g_AVSessionItem->metaData_.GetAVQueueImage() == nullptr);
    
    auto avQueueImg = std::make_shared<AVSessionPixelMap>();
    ASSERT_TRUE(avQueueImg != nullptr);
    g_AVSessionItem->metaData_.SetAVQueueImage(avQueueImg);
    g_AVSessionItem->CheckUseAVMetaData(g_AVSessionItem->metaData_);
    ASSERT_TRUE(avQueueImg != nullptr);
    EXPECT_EQ(avQueueImg->GetInnerImgBuffer().size() > 0, false);

    std::vector<uint8_t> vec = {0, 1, 0, 1};
    avQueueImg->SetInnerImgBuffer(vec);
    g_AVSessionItem->CheckUseAVMetaData(g_AVSessionItem->metaData_);
    ASSERT_TRUE(avQueueImg != nullptr);
    EXPECT_EQ(avQueueImg->GetInnerImgBuffer().size() > 0, true);

    g_AVSessionItem->metaData_.SetAVQueueName("test");
    g_AVSessionItem->CheckUseAVMetaData(g_AVSessionItem->metaData_);
    ASSERT_TRUE(avQueueImg != nullptr);
    EXPECT_EQ(avQueueImg->GetInnerImgBuffer().size() > 0, true);

    g_AVSessionItem->metaData_.SetAVQueueId("test");
    g_AVSessionItem->CheckUseAVMetaData(g_AVSessionItem->metaData_);
    ASSERT_TRUE(avQueueImg != nullptr);
    EXPECT_EQ(avQueueImg->GetInnerImgBuffer().size(), 0);
    SLOGI("AVSessionItem_CheckUseAVMetaData_001 end");
}

/**
 * @tc.name: AVSessionItem_GetCurrentAppIndexForSession_001
 * @tc.desc: Test GetCurrentAppIndexForSession sets appIndex_ correctly.
 * @tc.type: FUNC
 * @tc.require: #1787
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_GetCurrentAppIndexForSession_001, TestSize.Level0)
{
    SLOGI("AVSessionItem_GetCurrentAppIndexForSession_001 begin!");
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    g_AVSessionItem->GetCurrentAppIndexForSession();
    int32_t appIndex = g_AVSessionItem->GetAppIndex();
    EXPECT_EQ(appIndex, 0);
    SLOGI("AVSessionItem_GetCurrentAppIndexForSession_001 end!");
}

/**
 * @tc.name: AVSessionItem_GetAppIndex_001
 * @tc.desc: Test GetAppIndex returns appIndex_ value.
 * @tc.type: FUNC
 * @tc.require: #1787
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_GetAppIndex_001, TestSize.Level0)
{
    SLOGI("AVSessionItem_GetAppIndex_001 begin!");
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    g_AVSessionItem->appIndex_ = 1;
    int32_t appIndex = g_AVSessionItem->GetAppIndex();
    EXPECT_EQ(appIndex, 1);
    SLOGI("AVSessionItem_GetAppIndex_001 end!");
}

/**
 * @tc.name: AVSessionItem_GetLaunchAbility_001
 * @tc.desc: Test GetLaunchAbility returns valid launch ability.
 * @tc.type: FUNC
 * @tc.require: #1787
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_GetLaunchAbility_001, TestSize.Level0)
{
    SLOGD("AVSessionItem_GetLaunchAbility_001 begin!");
    g_AVSessionItem->isSetLaunchAbility_= true;
    g_AVSessionItem->appIndex_= 1;
    auto launchAbility = g_AVSessionItem->GetLaunchAbility();
    EXPECT_EQ(launchAbility.IsLocal(), false);
    SLOGD("AVSessionItem_GetLaunchAbility_001 end!");
}

/**
 * @tc.name: AVSessionItem_StartCast_001
 * @tc.desc: Test StartCast.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_StartCast_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_StartCast_001 begin!");
    OutputDeviceInfo info;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "DeviceId1forTest";
    deviceInfo.deviceName_ = "DeviceName1forTest";
    deviceInfo.deviceType_ = 1;
    info.deviceInfos_.push_back(deviceInfo);
    g_AVSessionItem->castHandle_ = 0;
    int32_t result = g_AVSessionItem->StartCast(info);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGI("AVSessionItem_StartCast_001 end!");
}

/**
 * @tc.name: AVSessionItem_DealLocalState_001
 * @tc.desc: Test DealLocalState.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
HWTEST_F(AVsessionItemTest, AVSessionItem_DealLocalState_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_DealLocalState_001 begin!");
    OutputDeviceInfo info;
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "DeviceId1forTest";
    deviceInfo.deviceName_ = "DeviceName1forTest";
    deviceInfo.deviceType_ = 1;
    info.deviceInfos_.push_back(deviceInfo);
    g_AVSessionItem->newOutputDeviceInfo_ = info;
    int32_t castState = static_cast<int32_t>(ConnectionState::STATE_DISCONNECTED);
    g_AVSessionItem->DealLocalState(castState, info);
    auto deviceName = g_AVSessionItem->descriptor_.outputDeviceInfo_.deviceInfos_[0].deviceName_;
    EXPECT_EQ(deviceName, "LocalDevice");
    SLOGI("AVSessionItem_DealLocalState_001 end!");
}

/**
* @tc.name: AVSessionItem_EnableDesktopLyric_001
* @tc.desc: enable desktop lyric
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_EnableDesktopLyric_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_EnableDesktopLyric_001 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = true;
    int32_t res = g_AVSessionItem->EnableDesktopLyric(true);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_EnableDesktopLyric_001 End");
}

/**
* @tc.name: AVSessionItem_EnableDesktopLyric_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_EnableDesktopLyric_002, TestSize.Level1)
{
    SLOGI("AVSessionItem_EnableDesktopLyric_002 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    int32_t res = g_AVSessionItem->AVSession::EnableDesktopLyric(true);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_EnableDesktopLyric_002 End");
}

/**
* @tc.name: AVSessionItem_IsDesktopLyricEnabled_001
* @tc.desc: get desktop lyric enabled state
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_IsDesktopLyricEnabled_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_IsDesktopLyricEnabled_001 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = true;
    bool isEnable = false;
    int32_t res = g_AVSessionItem->IsDesktopLyricEnabled(isEnable);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_IsDesktopLyricEnabled_001 End");
}

/**
* @tc.name: AVSessionItem_SetDesktopLyricVisible_001
* @tc.desc: set desktop lyric visible
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_SetDesktopLyricVisible_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_SetDesktopLyricVisible_001 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = true;
    g_AVSessionItem->isEnabledDesktopLyric_ = true;
    MockAVSessionItemExtension extension;
    g_AVSessionItem->extension_ = &extension;
    int32_t res = AVSESSION_SUCCESS;

    extension.isStartSuccend = AVSESSION_ERROR;
    res = g_AVSessionItem->SetDesktopLyricVisible(true);
    EXPECT_EQ(res, AVSESSION_ERROR);

    extension.isStartSuccend = AVSESSION_SUCCESS;
    res = g_AVSessionItem->SetDesktopLyricVisible(true);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    g_AVSessionItem->extension_ = nullptr;
    SLOGI("AVSessionItem_SetDesktopLyricVisible_001 End");
}

/**
* @tc.name: AVSessionItem_SetDesktopLyricVisible_002
* @tc.desc: set desktop lyric visible
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_SetDesktopLyricVisible_002, TestSize.Level1)
{
    SLOGI("AVSessionItem_SetDesktopLyricVisible_002 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = true;
    g_AVSessionItem->isEnabledDesktopLyric_ = true;
    MockAVSessionItemExtension extension;
    g_AVSessionItem->extension_ = &extension;

    int32_t res = g_AVSessionItem->SetDesktopLyricVisible(false);
    EXPECT_EQ(res, AVSESSION_SUCCESS);

    auto cb = g_AVSessionItem->callback_;
    g_AVSessionItem->callback_ = nullptr;
    res = g_AVSessionItem->SetDesktopLyricVisible(false);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    g_AVSessionItem->callback_ = cb;
    g_AVSessionItem->extension_ = nullptr;
    SLOGI("AVSessionItem_SetDesktopLyricVisible_002 End");
}

/**
* @tc.name: AVSessionItem_SetDesktopLyricVisible_003
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_SetDesktopLyricVisible_003, TestSize.Level1)
{
    SLOGI("AVSessionItem_SetDesktopLyricVisible_003 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    int32_t res = g_AVSessionItem->AVSession::SetDesktopLyricVisible(false);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_SetDesktopLyricVisible_003 End");
}

/**
* @tc.name: AVSessionItem_IsDesktopLyricVisible_001
* @tc.desc: get desktop lyric visible
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_IsDesktopLyricVisible_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_IsDesktopLyricVisible_001 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = true;
    g_AVSessionItem->isEnabledDesktopLyric_ = true;
    bool isVisible = false;
    int32_t res = g_AVSessionItem->IsDesktopLyricVisible(isVisible);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_IsDesktopLyricVisible_001 End");
}

/**
* @tc.name: AVSessionItem_IsDesktopLyricVisible_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_IsDesktopLyricVisible_002, TestSize.Level1)
{
    SLOGI("AVSessionItem_IsDesktopLyricVisible_002 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    bool isVisible = false;
    int32_t res = g_AVSessionItem->AVSession::IsDesktopLyricVisible(isVisible);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_IsDesktopLyricVisible_002 End");
}

/**
* @tc.name: AVSessionItem_SetDesktopLyricState_001
* @tc.desc: set desktop lyric state
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_SetDesktopLyricState_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_SetDesktopLyricState_001 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = true;
    g_AVSessionItem->isEnabledDesktopLyric_ = true;
    MockAVSessionItemExtension extension;
    g_AVSessionItem->extension_ = &extension;
    DesktopLyricState state = {};
    int32_t res = g_AVSessionItem->SetDesktopLyricState(state);
    EXPECT_EQ(res, AVSESSION_SUCCESS);

    auto cb = g_AVSessionItem->callback_;
    g_AVSessionItem->callback_ = nullptr;
    res = g_AVSessionItem->SetDesktopLyricState(state);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    g_AVSessionItem->callback_ = cb;
    g_AVSessionItem->extension_ = nullptr;
    SLOGI("AVSessionItem_SetDesktopLyricState_001 End");
}

/**
* @tc.name: AVSessionItem_SetDesktopLyricState_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_SetDesktopLyricState_002, TestSize.Level1)
{
    SLOGI("AVSessionItem_SetDesktopLyricState_002 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    DesktopLyricState state = {};
    int32_t res = g_AVSessionItem->AVSession::SetDesktopLyricState(state);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_SetDesktopLyricState_002 End");
}

/**
* @tc.name: AVSessionItem_GetDesktopLyricState_001
* @tc.desc: get desktop lyric state
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_GetDesktopLyricState_001, TestSize.Level1)
{
    SLOGI("AVSessionItem_GetDesktopLyricState_001 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = true;
    g_AVSessionItem->isEnabledDesktopLyric_ = true;
    DesktopLyricState state = {};
    int32_t res = g_AVSessionItem->GetDesktopLyricState(state);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_GetDesktopLyricState_001 End");
}

/**
* @tc.name: AVSessionItem_GetDesktopLyricState_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVsessionItemTest, AVSessionItem_GetDesktopLyricState_002, TestSize.Level1)
{
    SLOGI("AVSessionItem_GetDesktopLyricState_002 Begin");
    ASSERT_NE(g_AVSessionItem, nullptr);
    DesktopLyricState state = {};
    int32_t res = g_AVSessionItem->AVSession::GetDesktopLyricState(state);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
    SLOGI("AVSessionItem_GetDesktopLyricState_002 End");
}
} //AVSession
} //OHOS
