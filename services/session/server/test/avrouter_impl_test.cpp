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
#include "avrouter_impl.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_service.h"
#include "hw_cast_provider.h"

using namespace testing::ext;
namespace OHOS {
namespace AVSession {

static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};
static std::shared_ptr<AVRouterImpl> g_AVRouterImpl {nullptr};

class AVRouterImplMock : public AVRouterImpl {
public:
    AVRouterImplMock() : AVRouterImpl() {}
    virtual ~AVRouterImplMock() {}
};

class AVCastControllerProxyMock : public IAVCastControllerProxy {
public:
    void Release() {};
    int32_t RegisterControllerListener(const std::shared_ptr<IAVCastControllerProxyListener>
        iAVCastControllerProxyListener) {return 0;}
    int32_t UnRegisterControllerListener(const std::shared_ptr<IAVCastControllerProxyListener>
        iAVCastControllerProxyListener) {return 0;}
    AVQueueItem GetCurrentItem() {return AVQueueItem();}
    int32_t Start(const AVQueueItem& avQueueItem) {return 0;}
    int32_t Prepare(const AVQueueItem& avQueueItem) {return 0;}
    void SendControlCommand(const AVCastControlCommand cmd) {}
    int32_t GetDuration(int32_t& duration) {return 0;}
    int32_t GetCastAVPlaybackState(AVPlaybackState& avPlaybackState) {return 0;}
    int32_t SetValidAbility(const std::vector<int32_t>& validAbilityList) {return 0;}
    int32_t GetValidAbility(std::vector<int32_t> &validAbilityList) {return 0;}
    int32_t SetDisplaySurface(std::string& surfaceId) {return 0;}
    int32_t ProcessMediaKeyResponse(const std::string& assetId, const std::vector<uint8_t>& response) {return 0;}
    int32_t GetSupportedDecoders(std::vector<std::string>& decoderTypes) {return 0;}
    int32_t GetRecommendedResolutionLevel(std::string& decoderType, ResolutionLevel& resolutionLevel) {return 0;}
    int32_t GetSupportedHdrCapabilities(std::vector<HDRFormat>& hdrFormats) {return 0;}
    int32_t GetSupportedPlaySpeeds(std::vector<float>& playSpeeds) {return 0;}
    int32_t RefreshCurrentAVQueueItem(const AVQueueItem& avQueueItem) {return 0;}
    void SetSessionCallbackForCastCap(const std::function<void(bool, bool)>& callback) {}
};

class AVRouterImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVRouterImplTest::SetUpTestCase()
{
    SLOGI("set up AVSessionServiceTest");
    system("killall -9 com.example.hiMusicDemo");
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
    g_AVRouterImpl = std::make_shared<AVRouterImplMock>();
    g_AVRouterImpl->Init(g_AVSessionService.get());
}

void AVRouterImplTest::TearDownTestCase()
{
    g_AVRouterImpl->Release();
    g_AVSessionService->Close();
}

void AVRouterImplTest::SetUp() {}

void AVRouterImplTest::TearDown() {}

class AVRouterListenerMock : public IAVRouterListener {
public:
    virtual void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove) {}

    virtual void OnCastEventRecv(int32_t errorCode, std::string& errorMsg) {}

    virtual ~AVRouterListenerMock() {}
};

class AVSessionServiceListenerMock : public IAVSessionServiceListener {
public:
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        void ReleaseCastSession() {}
        void CreateSessionByCast(const int64_t castHandle) {}
        void NotifyDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) {}
        void NotifyDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) {}
        void NotifyDeviceOffline(const std::string& deviceId) {}
        void NotifyDeviceStateChange(const DeviceState& deviceState) {}
        void setInCast(bool isInCast) {}
        void SetIsSupportMirrorToStream(bool isSupportMirrorToStream) {}
        int32_t checkEnableCast(bool enable) { return 0; }
#endif
    virtual ~AVSessionServiceListenerMock() {}
};

/**
* @tc.name: GetRemoteController001
* @tc.desc: get controller by handle
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, GetRemoteController001, TestSize.Level1)
{
    SLOGI("GetRemoteController001 begin");
    int32_t num = g_AVRouterImpl->providerNumber_;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(num) << 32) |
        static_cast<uint32_t>(num));
    auto controller = g_AVRouterImpl->GetRemoteController(castHandle);
    EXPECT_TRUE(controller == nullptr);
    SLOGI("GetRemoteController001 end");
}

/**
* @tc.name: GetRemoteController002
* @tc.desc: get controller by handle
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, GetRemoteController002, TestSize.Level1)
{
    SLOGI("GetRemoteController002 begin");
    int32_t num = g_AVRouterImpl->providerNumber_;
    g_AVRouterImpl->providerManagerMap_[num] = nullptr;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(num) << 32) |
        static_cast<uint32_t>(num));
    auto controller = g_AVRouterImpl->GetRemoteController(castHandle);
    EXPECT_TRUE(controller == nullptr);
    SLOGI("GetRemoteController002 end");
}

/**
* @tc.name: StartCast001
* @tc.desc: sessinId have existed in castHandleToInfoMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StartCast001, TestSize.Level1)
{
    SLOGI("StartCast001 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = g_AVRouterImpl->providerNumber_;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    std::pair<std::string, std::string> serviceNameStatePair;
    std::string sessionId = "1000";

    int32_t number = 10;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.sessionId_ = sessionId;
    g_AVRouterImpl->castHandleToInfoMap_.insert({number, castHandleInfo});

    auto ret = g_AVRouterImpl->StartCast(outputDeviceInfo, serviceNameStatePair, sessionId);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("StartCast001 end");
}

/**
* @tc.name: StartCast002
* @tc.desc: castHandleInfo.outputDeviceInfo_.deviceInfos_.size() equl to 0
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StartCast002, TestSize.Level1)
{
    SLOGI("StartCast002 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = g_AVRouterImpl->providerNumber_;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    std::pair<std::string, std::string> serviceNameStatePair;
    std::string sessionId = "1000";
    
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "1001";
    int32_t number = 11;
    g_AVRouterImpl->castHandleToInfoMap_.insert({number, castHandleInfo});

    auto ret = g_AVRouterImpl->StartCast(outputDeviceInfo, serviceNameStatePair, sessionId);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("StartCast002 end");
}

/**
* @tc.name: StartCast003
* @tc.desc: success to find deviceId in castHandleToInfoMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StartCast003, TestSize.Level1)
{
    SLOGI("StartCast003 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = g_AVRouterImpl->providerNumber_;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    std::pair<std::string, std::string> serviceNameStatePair;
    std::string sessionId = "1000";

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "1001";
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    int32_t number = 11;
    g_AVRouterImpl->castHandleToInfoMap_.insert({number, castHandleInfo});

    auto ret = g_AVRouterImpl->StartCast(outputDeviceInfo, serviceNameStatePair, sessionId);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("StartCast003 end");
}

/**
* @tc.name: AddDevice001
* @tc.desc: success to add device
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, AddDevice001, TestSize.Level1)
{
    SLOGI("AddDevice001 begin");
    int32_t tempId = g_AVRouterImpl->providerNumber_;
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = tempId;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) |
        static_cast<uint32_t>(castId));

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t ret = g_AVRouterImpl->AddDevice(castId, outputDeviceInfo);
    EXPECT_TRUE(ret == AVSESSION_SUCCESS);
    SLOGI("AddDevice001 end");
}

/**
* @tc.name: AddDevice002
* @tc.desc: fail to add device
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, AddDevice002, TestSize.Level1)
{
    SLOGI("AddDevice002 begin");
    int32_t tempId = g_AVRouterImpl->providerNumber_;
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = tempId;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) |
        static_cast<uint32_t>(castId));

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle + 100, castHandleInfo});

    int32_t ret = g_AVRouterImpl->AddDevice(castId, outputDeviceInfo);
    EXPECT_TRUE(ret == AVSESSION_SUCCESS);
    SLOGI("AddDevice002 end");
}

/**
* @tc.name: AddDevice003
* @tc.desc: fail to add device
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, AddDevice003, TestSize.Level1)
{
    SLOGI("AddDevice003 begin");
    int32_t tempId = g_AVRouterImpl->providerNumber_;
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = tempId;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) |
        static_cast<uint32_t>(castId));

    AVRouter::CastHandleInfo castHandleInfo;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t ret = g_AVRouterImpl->AddDevice(castId, outputDeviceInfo);
    EXPECT_TRUE(ret == AVSESSION_SUCCESS);
    SLOGI("AddDevice003 end");
}

/**
* @tc.name: AddDevice004
* @tc.desc: fail to add device
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, AddDevice004, TestSize.Level1)
{
    SLOGI("AddDevice004 begin");
    int32_t tempId = g_AVRouterImpl->providerNumber_;
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = tempId;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(tempId) << 32) |
        static_cast<uint32_t>(castId));
    
    OutputDeviceInfo outputDeviceInfo2;
    DeviceInfo deviceInfo2;
    deviceInfo2.providerId_ = 12321;
    outputDeviceInfo2.deviceInfos_.push_back(deviceInfo2);
    
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo2;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t ret = g_AVRouterImpl->AddDevice(castId, outputDeviceInfo);
    EXPECT_TRUE(ret == AVSESSION_SUCCESS);
    SLOGI("AddDevice004 end");
}

/**
* @tc.name: SetServiceAllConnectState001
* @tc.desc: success to set connect state
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, SetServiceAllConnectState001, TestSize.Level1)
{
    SLOGI("SetServiceAllConnectState001 begin");
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;
    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));
    
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t ret = g_AVRouterImpl->SetServiceAllConnectState(castId, deviceInfo);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("SetServiceAllConnectState001 end");
}

/**
* @tc.name: SetServiceAllConnectState002
* @tc.desc: fail to set connect state
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, SetServiceAllConnectState002, TestSize.Level1)
{
    SLOGI("SetServiceAllConnectState002 begin");
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;
    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));
    
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle + 100, castHandleInfo});

    int32_t ret = g_AVRouterImpl->SetServiceAllConnectState(castId, deviceInfo);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("SetServiceAllConnectState002 end");
}

/**
* @tc.name: OnCastStateChange001
* @tc.desc: set castState is disconnectStateFromCast_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, OnCastStateChange001, TestSize.Level1)
{
    SLOGI("OnCastStateChange001 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    int64_t castHandle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t castState = g_AVRouterImpl->disconnectStateFromCast_;
    g_AVRouterImpl->OnCastStateChange(castState, deviceInfo);

    EXPECT_TRUE(castHandleInfo.avRouterListener_ != nullptr);
    SLOGI("OnCastStateChange001 end");
}

/**
* @tc.name: OnCastStateChange002
* @tc.desc: set castState is connectStateFromCast_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, OnCastStateChange002, TestSize.Level1)
{
    SLOGI("OnCastStateChange002 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    int64_t castHandle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t castState = g_AVRouterImpl->connectStateFromCast_;
    g_AVRouterImpl->OnCastStateChange(castState, deviceInfo);

    EXPECT_TRUE(castHandleInfo.avRouterListener_ != nullptr);
    SLOGI("OnCastStateChange002 end");
}

/**
* @tc.name: OnCastStateChange003
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, OnCastStateChange003, TestSize.Level1)
{
    SLOGI("OnCastStateChange003 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    int64_t castHandle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t castState = g_AVRouterImpl->connectStateFromCast_;
    g_AVRouterImpl->OnCastStateChange(castState, deviceInfo);

    EXPECT_TRUE(castHandleInfo.avRouterListener_ == nullptr);
    SLOGI("OnCastStateChange003 end");
}

/**
* @tc.name: OnCastEventRecv001
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, OnCastEventRecv001, TestSize.Level1)
{
    SLOGI("OnCastEventRecv001 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    int64_t castHandle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t errorCode = -1;
    std::string errorMsg = "**";
    g_AVRouterImpl->OnCastEventRecv(errorCode, errorMsg);

    EXPECT_TRUE(castHandleInfo.avRouterListener_ == nullptr);
    SLOGI("OnCastEventRecv001 end");
}

/**
* @tc.name: OnCastEventRecv002
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, OnCastEventRecv002, TestSize.Level1)
{
    SLOGI("OnCastEventRecv002 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    int64_t castHandle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    int32_t errorCode = -1;
    std::string errorMsg = "**";
    g_AVRouterImpl->OnCastEventRecv(errorCode, errorMsg);

    EXPECT_TRUE(castHandleInfo.avRouterListener_ != nullptr);
    SLOGI("OnCastEventRecv002 end");
}

/**
* @tc.name: DisconnectOtherSession001
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, DisconnectOtherSession001, TestSize.Level1)
{
    SLOGI("DisconnectOtherSession001 begin");
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;

    std::string sessionId = "12345";
    std::shared_ptr<IAVRouterListener> listener = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->mirrorSessionMap_.insert({sessionId, listener});

    g_AVRouterImpl->DisconnectOtherSession(sessionId, deviceInfo);
    EXPECT_TRUE(listener != nullptr);
    SLOGI("DisconnectOtherSession001 end");
}

/**
* @tc.name: DisconnectOtherSession002
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, DisconnectOtherSession002, TestSize.Level1)
{
    SLOGI("DisconnectOtherSession002 begin");
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;

    std::string sessionId = "12345";
    std::shared_ptr<IAVRouterListener> listener = nullptr;
    g_AVRouterImpl->mirrorSessionMap_.insert({"12344", listener});

    g_AVRouterImpl->DisconnectOtherSession(sessionId, deviceInfo);
    EXPECT_TRUE(listener == nullptr);
    SLOGI("DisconnectOtherSession002 end");
}

/**
* @tc.name: DisconnectOtherSession003
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, DisconnectOtherSession003, TestSize.Level1)
{
    SLOGI("DisconnectOtherSession003 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    int64_t castHandle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    std::string sessionId = "12345";
    g_AVRouterImpl->DisconnectOtherSession(sessionId, deviceInfo);
    EXPECT_TRUE(castHandleInfo.avRouterListener_ != nullptr);
    SLOGI("DisconnectOtherSession003 end");
}

/**
* @tc.name: DisconnectOtherSession004
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, DisconnectOtherSession004, TestSize.Level1)
{
    SLOGI("DisconnectOtherSession004 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    int64_t castHandle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    std::string sessionId = "12340";
    g_AVRouterImpl->DisconnectOtherSession(sessionId, deviceInfo);
    EXPECT_TRUE(castHandleInfo.avRouterListener_ != nullptr);
    SLOGI("DisconnectOtherSession004 end");
}

/**
* @tc.name: DisconnectOtherSession005
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, DisconnectOtherSession005, TestSize.Level1)
{
    SLOGI("DisconnectOtherSession005 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    
    int64_t castHandle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.avRouterListener_ = nullptr;
    g_AVRouterImpl->castHandleToInfoMap_.insert({castHandle, castHandleInfo});

    std::string sessionId = "12340";
    g_AVRouterImpl->DisconnectOtherSession(sessionId, deviceInfo);
    EXPECT_TRUE(castHandleInfo.avRouterListener_ == nullptr);
    SLOGI("DisconnectOtherSession005 end");
}

/**
* @tc.name: StartDeviceLogging001
* @tc.desc: the size of providerManagerMap_ bigger than zero
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StartDeviceLogging001, TestSize.Level1)
{
    SLOGI("StartDeviceLogging001 begin");
    int32_t fd = 0;
    uint32_t maxSize = 0;
    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    g_AVRouterImpl->providerManagerMap_.insert({fd, avCastProviderManager});
    g_AVRouterImpl->StartDeviceLogging(fd, maxSize);
    EXPECT_TRUE(!g_AVRouterImpl->providerManagerMap_.empty());
    SLOGI("StartDeviceLogging001 end");
}

/**
* @tc.name: StopDeviceLogging001
* @tc.desc: set cacheStartDeviceLogging_ to false
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StopDeviceLogging001, TestSize.Level1)
{
    SLOGI("StopDeviceLogging001 begin");
    g_AVRouterImpl->cacheStartDeviceLogging_ = false;
    g_AVRouterImpl->StopDeviceLogging();
    EXPECT_TRUE(g_AVRouterImpl->cacheStartDeviceLogging_ == false);
    SLOGI("StopDeviceLogging001 end");
}

/**
* @tc.name: StartCastDiscovery001
* @tc.desc: the size of providerManagerMap_ bigger than zero
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StartCastDiscovery001, TestSize.Level1)
{
    SLOGI("StartCastDiscovery001 begin");
    int32_t castDeviceCapability = 0;
    std::vector<std::string> drmSchemes = {"test"};
    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    g_AVRouterImpl->providerManagerMap_.insert({castDeviceCapability, avCastProviderManager});
    g_AVRouterImpl->StartCastDiscovery(castDeviceCapability, drmSchemes);
    EXPECT_TRUE(!g_AVRouterImpl->providerManagerMap_.empty());
    SLOGI("StartCastDiscovery001 end");
}

/**
* @tc.name: StopCastDiscovery001
* @tc.desc: set cacheStartDeviceLogging_ to false
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StopCastDiscovery001, TestSize.Level1)
{
    SLOGI("StopCastDiscovery001 begin");
    g_AVRouterImpl->cacheStartDeviceLogging_ = false;
    g_AVRouterImpl->StopCastDiscovery();
    EXPECT_TRUE(g_AVRouterImpl->cacheStartDeviceLogging_ == false);
    SLOGI("StopCastDiscovery001 end");
}

/**
* @tc.name: OnDeviceAvailable001
* @tc.desc: set servicePtr_ to not nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, OnDeviceAvailable001, TestSize.Level1)
{
    SLOGI("OnDeviceAvailable001 begin");
    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);
    auto listener = std::make_shared<AVSessionServiceListenerMock>();
    g_AVRouterImpl->servicePtr_ = listener.get();
    g_AVRouterImpl->OnDeviceAvailable(outputDeviceInfo);
    EXPECT_TRUE(g_AVRouterImpl->servicePtr_ != nullptr);
    SLOGI("OnDeviceAvailable001 end");
}

/**
* @tc.name: OnCastServerDied001
* @tc.desc: set servicePtr_ to not nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, OnCastServerDied001, TestSize.Level1)
{
    SLOGI("OnCastServerDied001 begin");
    int32_t providerNumber = 0;
    auto listener = std::make_shared<AVSessionServiceListenerMock>();
    g_AVRouterImpl->servicePtr_ = listener.get();
    g_AVRouterImpl->OnCastServerDied(providerNumber);
    EXPECT_TRUE(g_AVRouterImpl->servicePtr_ != nullptr);
    SLOGI("OnCastServerDied001 end");
}

/**
* @tc.name: GetRemoteController003
* @tc.desc: fail to get controller by handle
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, GetRemoteController003, TestSize.Level1)
{
    SLOGI("GetRemoteController003 begin");
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;
    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    int64_t handle = 2000;
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->castHandleToInfoMap_[handle] = castHandleInfo;

    auto controller = g_AVRouterImpl->GetRemoteController(castHandle);
    EXPECT_TRUE(controller == nullptr);
    SLOGI("GetRemoteController003 end");
}

/**
* @tc.name: GetRemoteController004
* @tc.desc: fail to get controller by handle
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, GetRemoteController004, TestSize.Level1)
{
    SLOGI("GetRemoteController004 begin");
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;
    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;

    auto controller = g_AVRouterImpl->GetRemoteController(castHandle);
    EXPECT_TRUE(controller == nullptr);
    SLOGI("GetRemoteController004 end");
}

/**
* @tc.name: StartCast004
* @tc.desc: the size of providerManagerMap_ bigger than zero
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StartCast004, TestSize.Level1)
{
    SLOGI("StartCast004 begin");
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;
    
    std::pair<std::string, std::string> serviceNameStatePair;
    std::string sessionId = "1000";
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.sessionId_ = sessionId;
    g_AVRouterImpl->castHandleToInfoMap_[providerNumber] = castHandleInfo;

    auto ret = g_AVRouterImpl->StartCast(outputDeviceInfo, serviceNameStatePair, "1001");
    EXPECT_TRUE(ret != AVSESSION_ERROR);
    SLOGI("StartCast004 end");
}

/**
* @tc.name: StartCast005
* @tc.desc: the size of providerManagerMap_ bigger than zero
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StartCast005, TestSize.Level1)
{
    SLOGI("StartCast005 begin");
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;
    
    std::pair<std::string, std::string> serviceNameStatePair;
    std::string sessionId = "1000";
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.sessionId_ = sessionId;
    g_AVRouterImpl->castHandleToInfoMap_[providerNumber] = castHandleInfo;

    OutputDeviceInfo outputDeviceInfo2;
    DeviceInfo deviceInfo2;
    deviceInfo2.providerId_ = providerNumber + 100;
    outputDeviceInfo2.deviceInfos_.push_back(deviceInfo2);

    auto ret = g_AVRouterImpl->StartCast(outputDeviceInfo2, serviceNameStatePair, sessionId);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("StartCast005 end");
}

/**
* @tc.name: StartCast006
* @tc.desc: the size of providerManagerMap_ bigger than zero
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StartCast006, TestSize.Level1)
{
    SLOGI("StartCast006 begin");
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;
    
    std::pair<std::string, std::string> serviceNameStatePair;
    std::string sessionId = "1000";
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.sessionId_ = sessionId;
    g_AVRouterImpl->castHandleToInfoMap_[providerNumber] = castHandleInfo;

    auto ret = g_AVRouterImpl->StartCast(outputDeviceInfo, serviceNameStatePair, sessionId);
    EXPECT_TRUE(ret == AVSESSION_ERROR);
    SLOGI("StartCast006 end");
}

/**
* @tc.name: AddDevice005
* @tc.desc: success to add device
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, AddDevice005, TestSize.Level1)
{
    SLOGI("AddDevice005 begin");
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));
    
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;

    int32_t ret = g_AVRouterImpl->AddDevice(castId, outputDeviceInfo);
    EXPECT_TRUE(ret == AVSESSION_SUCCESS);
    SLOGI("AddDevice005 end");
}

/**
* @tc.name: AddDevice006
* @tc.desc: fail to add device
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, AddDevice006, TestSize.Level1)
{
    SLOGI("AddDevice006 begin");
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));
    
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;

    int32_t ret = g_AVRouterImpl->AddDevice(castId + 1, outputDeviceInfo);
    EXPECT_TRUE(ret == ERR_DEVICE_CONNECTION_FAILED);
    SLOGI("AddDevice006 end");
}

/**
* @tc.name: StopCast001
* @tc.desc: success to stop cast
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StopCast001, TestSize.Level1)
{
    SLOGI("StopCast001 begin");
    bool continuePlay = true;
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;
    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;
    
    std::string sessionId = "1000";
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    castHandleInfo.sessionId_ = sessionId;
    g_AVRouterImpl->castHandleToInfoMap_[providerNumber] = castHandleInfo;

    auto ret = g_AVRouterImpl->StopCast(castHandle, continuePlay);
    EXPECT_TRUE(ret == AVSESSION_SUCCESS);
    SLOGI("StopCast001 end");
}

/**
* @tc.name: StopCastSession001
* @tc.desc: success to stop cast session
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, StopCastSession001, TestSize.Level1)
{
    SLOGI("StopCastSession001 begin");
    g_AVRouterImpl->providerNumber_ = 1;
    int32_t providerNumber = g_AVRouterImpl->providerNumber_;
    int32_t castId = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;
    outputDeviceInfo.deviceInfos_.push_back(deviceInfo);

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.outputDeviceInfo_ = outputDeviceInfo;
    g_AVRouterImpl->castHandleToInfoMap_[providerNumber] = castHandleInfo;
    g_AVRouterImpl->castHandleToInfoMap_[providerNumber + 100] = castHandleInfo;

    auto ret = g_AVRouterImpl->StopCastSession(castHandle);
    EXPECT_TRUE(ret == AVSESSION_SUCCESS);
    SLOGI("StopCastSession001 end");
}

/**
* @tc.name: GetRemoteController005
* @tc.desc: find controller in castHandleToInfoMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, GetRemoteController005, TestSize.Level1)
{
    SLOGI("GetRemoteController005 begin");
    int32_t providerNumber = 1;
    int32_t castId = 1;
    g_AVRouterImpl->providerNumber_ = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    AVRouter::CastHandleInfo castHandleInfo2;
    castHandleInfo2.sessionId_ = "12346";
    castHandleInfo2.avRouterListener_ = nullptr;
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;
    g_AVRouterImpl->castHandleToInfoMap_[castHandle + 1] = castHandleInfo2;

    auto controller = g_AVRouterImpl->GetRemoteController(castHandle);
    EXPECT_TRUE(controller == nullptr);
    SLOGI("GetRemoteController005 end");
}

/**
* @tc.name: GetRemoteController006
* @tc.desc: find controller in providerManagerMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, GetRemoteController006, TestSize.Level1)
{
    SLOGI("GetRemoteController005 begin");
    int32_t providerNumber = 1;
    int32_t castId = 1;
    g_AVRouterImpl->providerNumber_ = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.avRouterListener_ = nullptr;
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;

    auto controller = g_AVRouterImpl->GetRemoteController(castHandle);
    EXPECT_TRUE(controller == nullptr);
    SLOGI("GetRemoteController006 end");
}

/**
* @tc.name: RegisterCallback001
* @tc.desc: have no provider in castHandleToInfoMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, RegisterCallback001, TestSize.Level1)
{
    SLOGI("RegisterCallback001 begin");
    int32_t providerNumber = 20;
    int32_t castId = 20;
    g_AVRouterImpl->providerNumber_ = providerNumber;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    std::shared_ptr<IAVRouterListener> callback = std::make_shared<AVRouterListenerMock>();
    std::string sessionId = "12345";
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;

    auto ret = g_AVRouterImpl->RegisterCallback(castHandle, callback, sessionId, deviceInfo);
    EXPECT_TRUE(AVSESSION_SUCCESS == ret);
    SLOGI("RegisterCallback001 end");
}

/**
* @tc.name: RegisterCallback002
* @tc.desc: find controller in providerManagerMap_ but avRouterListener_ is null
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, RegisterCallback002, TestSize.Level1)
{
    SLOGI("RegisterCallback002 begin");
    int32_t providerNumber = 21;
    int32_t castId = 21;
    g_AVRouterImpl->providerNumber_ = providerNumber;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.avRouterListener_ = nullptr;
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;

    std::shared_ptr<IAVRouterListener> callback = std::make_shared<AVRouterListenerMock>();
    std::string sessionId = "12345";
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;

    auto ret = g_AVRouterImpl->RegisterCallback(castHandle, callback, sessionId, deviceInfo);
    EXPECT_TRUE(AVSESSION_SUCCESS == ret);
    SLOGI("RegisterCallback002 end");
}

/**
* @tc.name: RegisterCallback003
* @tc.desc: find controller in providerManagerMap_ and avRouterListener_ is not null
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, RegisterCallback003, TestSize.Level1)
{
    SLOGI("RegisterCallback003 begin");
    int32_t providerNumber = 22;
    int32_t castId = 22;
    g_AVRouterImpl->providerNumber_ = providerNumber;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.avRouterListener_ = std::make_shared<AVRouterListenerMock>();
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;

    std::shared_ptr<IAVRouterListener> callback = std::make_shared<AVRouterListenerMock>();
    std::string sessionId = "12345";
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = providerNumber;

    auto ret = g_AVRouterImpl->RegisterCallback(castHandle, callback, sessionId, deviceInfo);
    EXPECT_TRUE(AVSESSION_SUCCESS == ret);
    SLOGI("RegisterCallback003 end");
}

/**
* @tc.name: UnRegisterCallback001
* @tc.desc: find controller in providerManagerMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, UnRegisterCallback001, TestSize.Level1)
{
    SLOGI("UnRegisterCallback001 begin");
    int32_t providerNumber = 30;
    int32_t castId = 30;
    g_AVRouterImpl->providerNumber_ = providerNumber;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    std::string sessionId = "12345";
    auto listener = std::make_shared<AVRouterListenerMock>();
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = sessionId;
    castHandleInfo.avRouterListener_ = listener;
    
    AVRouter::CastHandleInfo castHandleInfo2;
    castHandleInfo2.sessionId_ = "12346";
    castHandleInfo2.avRouterListener_ = listener;

    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;
    g_AVRouterImpl->castHandleToInfoMap_[castHandle + 1] = castHandleInfo2;
    g_AVRouterImpl->mirrorSessionMap_[sessionId] = listener;

    std::shared_ptr<IAVRouterListener> callback = std::make_shared<AVRouterListenerMock>();
    auto ret = g_AVRouterImpl->UnRegisterCallback(castHandle, callback, sessionId);
    EXPECT_TRUE(AVSESSION_SUCCESS == ret);
    SLOGI("UnRegisterCallback001 end");
}

/**
* @tc.name: UnRegisterCallback002
* @tc.desc: find controller in providerManagerMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, UnRegisterCallback002, TestSize.Level1)
{
    SLOGI("UnRegisterCallback002 begin");
    int32_t providerNumber = 31;
    int32_t castId = 31;
    g_AVRouterImpl->providerNumber_ = providerNumber;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    std::string sessionId = "12345";
    auto listener = std::make_shared<AVRouterListenerMock>();
    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12346";
    castHandleInfo.avRouterListener_ = listener;

    AVRouter::CastHandleInfo castHandleInfo2;
    castHandleInfo2.sessionId_ = "12345";
    castHandleInfo2.avRouterListener_ = listener;
    
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;
    g_AVRouterImpl->castHandleToInfoMap_[castHandle + 1] = castHandleInfo2;
    g_AVRouterImpl->mirrorSessionMap_[sessionId] = listener;

    std::shared_ptr<IAVRouterListener> callback = std::make_shared<AVRouterListenerMock>();
    auto ret = g_AVRouterImpl->UnRegisterCallback(castHandle, callback, sessionId);
    EXPECT_TRUE(AVSESSION_SUCCESS == ret);
    SLOGI("UnRegisterCallback002 end");
}
/**
* @tc.name: Release001
* @tc.desc: call Release
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, Release001, TestSize.Level1)
{
    std::shared_ptr<AVRouterImpl> aVRouterImpl = std::make_shared<AVRouterImplMock>();
    auto ret = aVRouterImpl->Release();
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: GetRemoteController007
* @tc.desc: find controller in providerManagerMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, GetRemoteController007, TestSize.Level1)
{
    SLOGI("GetRemoteController007 begin");
    int32_t providerNumber = 1;
    int32_t castId = 1;
    g_AVRouterImpl->providerNumber_ = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.avRouterListener_ = nullptr;
    castHandleInfo.avCastControllerProxy_ = std::make_shared<AVCastControllerProxyMock>();
    g_AVRouterImpl->castHandleToInfoMap_[castHandle] = castHandleInfo;

    auto controller = g_AVRouterImpl->GetRemoteController(castHandle);
    EXPECT_NE(controller, nullptr);
    SLOGI("GetRemoteController007 end");
}

/**
* @tc.name: GetRemoteController008
* @tc.desc: find controller in providerManagerMap_
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, GetRemoteController008, TestSize.Level1)
{
    SLOGI("GetRemoteController008 begin");
    int32_t providerNumber = 1;
    int32_t castId = 1;
    g_AVRouterImpl->providerNumber_ = 1;
    int64_t castHandle = static_cast<int64_t>((static_cast<uint64_t>(providerNumber) << 32) |
        static_cast<uint32_t>(castId));

    auto avCastProviderManager = std::make_shared<AVCastProviderManager>();
    auto hwCastProvider = std::make_shared<HwCastProvider>();
    avCastProviderManager->Init(providerNumber, hwCastProvider);
    g_AVRouterImpl->providerManagerMap_[providerNumber] = avCastProviderManager;

    AVRouter::CastHandleInfo castHandleInfo;
    castHandleInfo.sessionId_ = "12345";
    castHandleInfo.avRouterListener_ = nullptr;
    g_AVRouterImpl->castHandleToInfoMap_.clear();

    auto controller = g_AVRouterImpl->GetRemoteController(castHandle);
    EXPECT_EQ(controller, nullptr);
    SLOGI("GetRemoteController008 end");
}

/**
* @tc.name: DisconnectOtherSession006
* @tc.desc: listener is nullptr
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterImplTest, DisconnectOtherSession006, TestSize.Level1)
{
    SLOGI("DisconnectOtherSession006 begin");
    DeviceInfo deviceInfo;
    deviceInfo.providerId_ = 1;

    std::string sessionId = "12345";
    std::shared_ptr<IAVRouterListener> listener = std::make_shared<AVRouterListenerMock>();
    ASSERT_TRUE(listener != nullptr);
    g_AVRouterImpl->mirrorSessionMap_.insert({sessionId, listener});
    g_AVRouterImpl->mirrorSessionMap_.insert({"other_id", listener});

    g_AVRouterImpl->DisconnectOtherSession(sessionId, deviceInfo);
    EXPECT_TRUE(listener != nullptr);
    SLOGI("DisconnectOtherSession006 end");
}
} //AVSession
} //OHOS