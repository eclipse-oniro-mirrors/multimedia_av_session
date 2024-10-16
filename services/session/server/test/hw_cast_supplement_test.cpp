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
#include "avcast_provider_manager.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_service.h"
#include "hw_cast_stream_player.h"
#include "hw_cast_provider.h"

using namespace testing::ext;
namespace OHOS::AVSession {

static std::shared_ptr<AVSessionService> g_AVSessionService;

class HwCastSupplementTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HwCastSupplementTest::SetUpTestCase()
{
    SLOGI("set up AVSessionServiceTest");
    system("killall -9 com.example.hiMusicDemo");
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
}

void HwCastSupplementTest::TearDownTestCase()
{}

void HwCastSupplementTest::SetUp()
{}

void HwCastSupplementTest::TearDown()
{}

class AVCastControllerProxyDemo : public IAVCastControllerProxy {
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
};

class AVCastSessionStateListenerDemo : public IAVCastSessionStateListener {
public:
    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo) {}

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg) {}
};

/**
 * @tc.name: StopCastSession001
 * @tc.desc: test StopCastSession
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, StopCastSession001, TestSize.Level1)
{
    SLOGI("StopCastSession001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = 0;
    hwCastProvider->hwCastProviderSessionMap_[castId] = nullptr;
    hwCastProvider->StopCastSession(castId);
    SLOGI("StopCastSession001 end!");
}

/**
 * @tc.name: StopCastSession002
 * @tc.desc: test StopCastSession
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, StopCastSession002, TestSize.Level1)
{
    SLOGI("StopCastSession002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = 0;
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    hwCastProvider->StopCastSession(castId);
    SLOGI("StopCastSession002 end!");
}

/**
 * @tc.name: StopCastSession003
 * @tc.desc: test StopCastSession
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, StopCastSession003, TestSize.Level1)
{
    SLOGI("StopCastSession003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = -1;
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    hwCastProvider->StopCastSession(castId);
    SLOGI("StopCastSession003 end!");
}

/**
 * @tc.name: AddCastDevice001
 * @tc.desc: test AddCastDevice
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, AddCastDevice001, TestSize.Level1)
{
    SLOGI("AddCastDevice001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = 0;
    DeviceInfo deviceInfo;
    bool ret = hwCastProvider->AddCastDevice(castId, deviceInfo);
    EXPECT_EQ(ret, false);
    SLOGI("AddCastDevice001 end!");
}

/**
 * @tc.name: AddCastDevice002
 * @tc.desc: test AddCastDevice
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, AddCastDevice002, TestSize.Level1)
{
    SLOGI("AddCastDevice002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = 0;
    DeviceInfo deviceInfo;
    hwCastProvider->hwCastProviderSessionMap_[castId] = nullptr;
    bool ret = hwCastProvider->AddCastDevice(castId, deviceInfo);
    EXPECT_EQ(ret, false);
    SLOGI("AddCastDevice002 end!");
}

/**
 * @tc.name: AddCastDevice003
 * @tc.desc: test AddCastDevice
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, AddCastDevice003, TestSize.Level1)
{
    SLOGI("AddCastDevice003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = 0;
    DeviceInfo deviceInfo;
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    bool ret = hwCastProvider->AddCastDevice(castId, deviceInfo);
    EXPECT_EQ(ret, false);
    SLOGI("AddCastDevice003 end!");
}

/**
 * @tc.name: RemoveCastDevice001
 * @tc.desc: test RemoveCastDevice
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, RemoveCastDevice001, TestSize.Level1)
{
    SLOGI("RemoveCastDevice001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = 0;
    DeviceInfo deviceInfo;
    bool ret = hwCastProvider->RemoveCastDevice(castId, deviceInfo);
    EXPECT_EQ(ret, false);
    SLOGI("RemoveCastDevice001 end!");
}

/**
 * @tc.name: RemoveCastDevice002
 * @tc.desc: test RemoveCastDevice
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, RemoveCastDevice002, TestSize.Level1)
{
    SLOGI("RemoveCastDevice002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = 0;
    DeviceInfo deviceInfo;
    hwCastProvider->hwCastProviderSessionMap_[castId] = nullptr;
    bool ret = hwCastProvider->RemoveCastDevice(castId, deviceInfo);
    EXPECT_EQ(ret, false);
    SLOGI("RemoveCastDevice002 end!");
}

/**
 * @tc.name: RemoveCastDevice003
 * @tc.desc: test RemoveCastDevice
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, RemoveCastDevice003, TestSize.Level1)
{
    SLOGI("RemoveCastDevice003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int32_t castId = 0;
    DeviceInfo deviceInfo;
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    bool ret = hwCastProvider->RemoveCastDevice(castId, deviceInfo);
    EXPECT_EQ(ret, false);
    SLOGI("RemoveCastDevice003 end!");
}

/**
 * @tc.name: RegisterCastStateListener001
 * @tc.desc: test RegisterCastStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, RegisterCastStateListener001, TestSize.Level1)
{
    SLOGI("RegisterCastStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<AVCastProviderManager> avCastStateListenerDemo =
        std::make_shared<AVCastProviderManager>();
    bool ret = hwCastProvider->RegisterCastStateListener(avCastStateListenerDemo);
    EXPECT_EQ(ret, true);
    SLOGI("RegisterCastStateListener001 end!");
}

/**
 * @tc.name: UnRegisterCastStateListener001
 * @tc.desc: test UnRegisterCastStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, UnRegisterCastStateListener001, TestSize.Level1)
{
    SLOGI("UnRegisterCastStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<AVCastProviderManager> avCastStateListenerDemo =
        std::make_shared<AVCastProviderManager>();
    hwCastProvider->RegisterCastStateListener(avCastStateListenerDemo);
    bool ret = hwCastProvider->UnRegisterCastStateListener(avCastStateListenerDemo);
    EXPECT_EQ(ret, true);
    SLOGI("UnRegisterCastStateListener001 end!");
}

/**
 * @tc.name: UnRegisterCastStateListener002
 * @tc.desc: test UnRegisterCastStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, UnRegisterCastStateListener002, TestSize.Level1)
{
    SLOGI("UnRegisterCastStateListener002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<AVCastProviderManager> avCastStateListenerDemo =
        std::make_shared<AVCastProviderManager>();
    bool ret = hwCastProvider->UnRegisterCastStateListener(avCastStateListenerDemo);
    EXPECT_EQ(ret, false);
    SLOGI("UnRegisterCastStateListener002 end!");
}

/**
 * @tc.name: UnRegisterCastStateListener003
 * @tc.desc: test UnRegisterCastStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, UnRegisterCastStateListener003, TestSize.Level1)
{
    SLOGI("UnRegisterCastStateListener003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<IAVCastStateListener> avCastStateListenerDemo = nullptr;
    bool ret = hwCastProvider->UnRegisterCastStateListener(avCastStateListenerDemo);
    EXPECT_EQ(ret, false);
    SLOGI("UnRegisterCastStateListener003 end!");
}

/**
 * @tc.name: RegisterCastSessionStateListener001
 * @tc.desc: test RegisterCastSessionStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, RegisterCastSessionStateListener001, TestSize.Level1)
{
    SLOGI("RegisterCastSessionStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::shared_ptr<IAVCastSessionStateListener> listener =
        std::make_shared<AVCastSessionStateListenerDemo>();
    bool ret = hwCastProvider->RegisterCastSessionStateListener(castId, listener);
    EXPECT_EQ(ret, false);
    SLOGI("RegisterCastSessionStateListener001 end!");
}

/**
 * @tc.name: RegisterCastSessionStateListener002
 * @tc.desc: test RegisterCastSessionStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, RegisterCastSessionStateListener002, TestSize.Level1)
{
    SLOGI("RegisterCastSessionStateListener002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::shared_ptr<IAVCastSessionStateListener> listener =
        std::make_shared<AVCastSessionStateListenerDemo>();
    hwCastProvider->hwCastProviderSessionMap_[castId] = nullptr;
    bool ret = hwCastProvider->RegisterCastSessionStateListener(castId, listener);
    EXPECT_EQ(ret, false);
    SLOGI("RegisterCastSessionStateListener002 end!");
}

/**
 * @tc.name: RegisterCastSessionStateListener003
 * @tc.desc: test RegisterCastSessionStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, RegisterCastSessionStateListener003, TestSize.Level1)
{
    SLOGI("RegisterCastSessionStateListener003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::shared_ptr<IAVCastSessionStateListener> listener =
        std::make_shared<AVCastSessionStateListenerDemo>();
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    bool ret = hwCastProvider->RegisterCastSessionStateListener(castId, listener);
    EXPECT_EQ(ret, true);
    SLOGI("RegisterCastSessionStateListener003 end!");
}

/**
 * @tc.name: UnRegisterCastSessionStateListener001
 * @tc.desc: test UnRegisterCastSessionStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, UnRegisterCastSessionStateListener001, TestSize.Level1)
{
    SLOGI("UnRegisterCastSessionStateListener001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::shared_ptr<IAVCastSessionStateListener> listener =
        std::make_shared<AVCastSessionStateListenerDemo>();
    bool ret = hwCastProvider->UnRegisterCastSessionStateListener(castId, listener);
    EXPECT_EQ(ret, false);
    SLOGI("UnRegisterCastSessionStateListener001 end!");
}

/**
 * @tc.name: UnRegisterCastSessionStateListener002
 * @tc.desc: test UnRegisterCastSessionStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, UnRegisterCastSessionStateListener002, TestSize.Level1)
{
    SLOGI("UnRegisterCastSessionStateListener002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::shared_ptr<IAVCastSessionStateListener> listener =
        std::make_shared<AVCastSessionStateListenerDemo>();
    hwCastProvider->hwCastProviderSessionMap_[castId] = nullptr;
    bool ret = hwCastProvider->UnRegisterCastSessionStateListener(castId, listener);
    EXPECT_EQ(ret, false);
    SLOGI("UnRegisterCastSessionStateListener002 end!");
}

/**
 * @tc.name: UnRegisterCastSessionStateListener003
 * @tc.desc: test UnRegisterCastSessionStateListener
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, UnRegisterCastSessionStateListener003, TestSize.Level1)
{
    SLOGI("UnRegisterCastSessionStateListener003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::shared_ptr<IAVCastSessionStateListener> listener =
        std::make_shared<AVCastSessionStateListenerDemo>();
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    bool ret = hwCastProvider->UnRegisterCastSessionStateListener(castId, listener);
    EXPECT_EQ(ret, false);
    SLOGI("UnRegisterCastSessionStateListener003 end!");
}

/**
 * @tc.name: GetRemoteController001
 * @tc.desc: test GetRemoteController
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, GetRemoteController001, TestSize.Level1)
{
    SLOGI("GetRemoteController001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    auto ret = hwCastProvider->GetRemoteController(castId);
    EXPECT_EQ(ret, nullptr);
    SLOGI("GetRemoteController001 end!");
}

/**
 * @tc.name: GetRemoteController002
 * @tc.desc: test GetRemoteController
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, GetRemoteController002, TestSize.Level1)
{
    SLOGI("GetRemoteController002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    hwCastProvider->avCastControllerMap_[castId] = nullptr;
    auto ret = hwCastProvider->GetRemoteController(castId);
    EXPECT_EQ(ret, nullptr);
    SLOGI("GetRemoteController002 end!");
}

/**
 * @tc.name: GetRemoteController003
 * @tc.desc: test GetRemoteController
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, GetRemoteController003, TestSize.Level1)
{
    SLOGI("GetRemoteController003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    hwCastProvider->hwCastProviderSessionMap_[castId] = nullptr;
    auto ret = hwCastProvider->GetRemoteController(castId);
    EXPECT_EQ(ret, nullptr);
    SLOGI("GetRemoteController003 end!");
}

/**
 * @tc.name: GetRemoteController004
 * @tc.desc: test GetRemoteController
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, GetRemoteController004, TestSize.Level1)
{
    SLOGI("GetRemoteController003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    auto ret = hwCastProvider->GetRemoteController(castId);
    EXPECT_NE(ret, nullptr);
    SLOGI("GetRemoteController003 end!");
}

/**
 * @tc.name: SetStreamState001
 * @tc.desc: test SetStreamState
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, SetStreamState001, TestSize.Level1)
{
    SLOGI("SetStreamState001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    DeviceInfo deviceInfo;
    bool ret = hwCastProvider->SetStreamState(castId, deviceInfo);
    EXPECT_EQ(ret, false);
    SLOGI("SetStreamState001 end!");
}

/**
 * @tc.name: SetStreamState002
 * @tc.desc: test SetStreamState
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, SetStreamState002, TestSize.Level1)
{
    SLOGI("SetStreamState002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    DeviceInfo deviceInfo;
    hwCastProvider->hwCastProviderSessionMap_[castId] = nullptr;
    bool ret = hwCastProvider->SetStreamState(castId, deviceInfo);
    EXPECT_EQ(ret, false);
    SLOGI("SetStreamState002 end!");
}

/**
 * @tc.name: SetStreamState003
 * @tc.desc: test SetStreamState
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, SetStreamState003, TestSize.Level1)
{
    SLOGI("SetStreamState003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    DeviceInfo deviceInfo;
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    bool ret = hwCastProvider->SetStreamState(castId, deviceInfo);
    EXPECT_EQ(ret, true);
    SLOGI("SetStreamState003 end!");
}

/**
 * @tc.name: GetRemoteNetWorkId001
 * @tc.desc: test GetRemoteNetWorkId
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, GetRemoteNetWorkId001, TestSize.Level1)
{
    SLOGI("GetRemoteNetWorkId001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::string deviceId;
    std::string networkId;
    bool ret = hwCastProvider->GetRemoteNetWorkId(castId, deviceId, networkId);
    EXPECT_EQ(ret, false);
    SLOGI("GetRemoteNetWorkId001 end!");
}

/**
 * @tc.name: GetRemoteNetWorkId002
 * @tc.desc: test GetRemoteNetWorkId
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, GetRemoteNetWorkId002, TestSize.Level1)
{
    SLOGI("GetRemoteNetWorkId002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::string deviceId;
    std::string networkId;
    hwCastProvider->hwCastProviderSessionMap_[castId] = nullptr;
    bool ret = hwCastProvider->GetRemoteNetWorkId(castId, deviceId, networkId);
    EXPECT_EQ(ret, false);
    SLOGI("GetRemoteNetWorkId002 end!");
}

/**
 * @tc.name: GetRemoteNetWorkId003
 * @tc.desc: test GetRemoteNetWorkId
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, GetRemoteNetWorkId003, TestSize.Level1)
{
    SLOGI("GetRemoteNetWorkId003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    int castId = 0;
    std::string deviceId;
    std::string networkId;
    auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(nullptr);
    hwCastProvider->hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    bool ret = hwCastProvider->GetRemoteNetWorkId(castId, deviceId, networkId);
    EXPECT_EQ(ret, false);
    SLOGI("GetRemoteNetWorkId003 end!");
}

/**
 * @tc.name: OnDeviceFound001
 * @tc.desc: test OnDeviceFound
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, OnDeviceFound001, TestSize.Level1)
{
    SLOGI("OnDeviceFound001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    CastEngine::CastRemoteDevice castRemoteDevice;
    std::vector<CastEngine::CastRemoteDevice> deviceList;
    deviceList.push_back(castRemoteDevice);

    std::shared_ptr<AVCastProviderManager> ptr = std::make_shared<AVCastProviderManager>();
    hwCastProvider->castStateListenerList_.push_back(ptr);

    hwCastProvider->OnDeviceFound(deviceList);
    SLOGI("OnDeviceFound001 end!");
}

/**
 * @tc.name: OnDeviceFound002
 * @tc.desc: test OnDeviceFound
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, OnDeviceFound002, TestSize.Level1)
{
    SLOGI("OnDeviceFound002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    CastEngine::CastRemoteDevice castRemoteDevice;
    std::vector<CastEngine::CastRemoteDevice> deviceList;
    deviceList.push_back(castRemoteDevice);

    std::shared_ptr<IAVCastStateListener> ptr = nullptr;
    hwCastProvider->castStateListenerList_.push_back(ptr);

    hwCastProvider->OnDeviceFound(deviceList);
    SLOGI("OnDeviceFound002 end!");
}

/**
 * @tc.name: OnLogEvent001
 * @tc.desc: test OnLogEvent
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, OnLogEvent001, TestSize.Level1)
{
    SLOGI("OnLogEvent001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<IAVCastStateListener> ptr = nullptr;
    hwCastProvider->castStateListenerList_.push_back(ptr);

    int32_t eventId = 0;
    int64_t param = 0;
    hwCastProvider->OnLogEvent(eventId, param);
    SLOGI("OnLogEvent001 end!");
}

/**
 * @tc.name: OnLogEvent002
 * @tc.desc: test OnLogEvent
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, OnLogEvent002, TestSize.Level1)
{
    SLOGI("OnLogEvent002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<AVCastProviderManager> ptr = std::make_shared<AVCastProviderManager>();
    hwCastProvider->castStateListenerList_.push_back(ptr);

    int32_t eventId = 0;
    int64_t param = 0;
    hwCastProvider->OnLogEvent(eventId, param);
    SLOGI("OnLogEvent002 end!");
}

/**
 * @tc.name: OnLogEvent003
 * @tc.desc: test OnLogEvent
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, OnLogEvent003, TestSize.Level1)
{
    SLOGI("OnLogEvent003 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<AVCastProviderManager> ptr = std::make_shared<AVCastProviderManager>();
    hwCastProvider->castStateListenerList_.push_back(ptr);

    int32_t eventId = 1;
    int64_t param = 0;
    hwCastProvider->OnLogEvent(eventId, param);
    SLOGI("OnLogEvent003 end!");
}

/**
 * @tc.name: OnDeviceOffline001
 * @tc.desc: test OnDeviceOffline
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, OnDeviceOffline001, TestSize.Level1)
{
    SLOGI("OnDeviceOffline001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<IAVCastStateListener> ptr = nullptr;
    hwCastProvider->castStateListenerList_.push_back(ptr);

    std::string deviceId = "111";
    hwCastProvider->OnDeviceOffline(deviceId);
    SLOGI("OnDeviceOffline001 end!");
}

/**
 * @tc.name: OnDeviceOffline002
 * @tc.desc: test OnDeviceOffline
 * @tc.type: FUNC
 */
static HWTEST(HwCastSupplementTest, OnDeviceOffline002, TestSize.Level1)
{
    SLOGI("OnLogEvent002 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<AVCastProviderManager> ptr = std::make_shared<AVCastProviderManager>();
    hwCastProvider->castStateListenerList_.push_back(ptr);

    std::string deviceId = "111";
    hwCastProvider->OnDeviceOffline(deviceId);
    SLOGI("OnDeviceOffline002 end!");
}

/**
 * @tc.name: OnServiceDied001
 * @tc.desc: test OnServiceDied
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(HwCastSupplementTest, OnServiceDied001, TestSize.Level1)
{
    SLOGI("OnServiceDied001 begin!");
    std::shared_ptr<HwCastProvider> hwCastProvider = std::make_shared<HwCastProvider>();
    EXPECT_EQ(hwCastProvider != nullptr, true);
    hwCastProvider->Init();

    std::shared_ptr<AVCastProviderManager> ptr = std::make_shared<AVCastProviderManager>();
    hwCastProvider->castStateListenerList_.push_back(ptr);
    hwCastProvider->OnServiceDied();
    SLOGI("OnServiceDied001 end!");
}

} // OHOS::AVSession