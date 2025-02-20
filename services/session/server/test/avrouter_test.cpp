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
#include "av_router.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_service.h"

using namespace testing::ext;
namespace OHOS {
namespace AVSession {

static std::shared_ptr<AVSessionService> g_AVSessionService;

class AVRouterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVRouterTest::SetUpTestCase()
{
    SLOGI("set up AVSessionServiceTest");
    system("killall -9 com.example.hiMusicDemo");
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
}

void AVRouterTest::TearDownTestCase()
{}

void AVRouterTest::SetUp()
{}

void AVRouterTest::TearDown()
{}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE

/**
* @tc.name: StartCastDiscovery001
* @tc.desc: start cast discovery for default cast type "local"
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, StartCastDiscovery001, TestSize.Level1)
{
    SLOGI("StartCastDiscovery001 begin");
    auto ret = AVRouter::GetInstance().StartCastDiscovery(ProtocolType::TYPE_LOCAL, {});
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("StartCastDiscovery001 end");
}

/**
* @tc.name: StartCastDiscovery002
* @tc.desc: start cast discovery for invalid cast type
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, StartCastDiscovery002, TestSize.Level1)
{
    SLOGI("StartCastDiscovery001 begin");
    auto ret = AVRouter::GetInstance().StartCastDiscovery(-1, {});
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("StartCastDiscovery001 end");
}

/**
* @tc.name: StopCastDiscovery001
* @tc.desc: stop cast discovery success
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, StopCastDiscovery001, TestSize.Level1)
{
    SLOGI("StopCastDiscovery001 begin");
    auto ret = AVRouter::GetInstance().StartCastDiscovery(ProtocolType::TYPE_LOCAL, {});
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    ret = AVRouter::GetInstance().StopCastDiscovery();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("StopCastDiscovery001 end");
}

/**
* @tc.name: SetDiscoverable001
* @tc.desc: setDiscoverable true
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, SetDiscoverable001, TestSize.Level1)
{
    SLOGI("SetDiscoverable001 begin");
    auto ret = AVRouter::GetInstance().SetDiscoverable(true);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetDiscoverable001 end");
}

/**
* @tc.name: OnDeviceAvailable001
* @tc.desc: StartCast success
* @tc.type: FUNC
* @tc.require: NA
*/
HWTEST_F(AVRouterTest, OnDeviceAvailable001, TestSize.Level1)
{
    SLOGI("OnDeviceAvailable001 begin");
    OutputDeviceInfo outputDeviceInfo;
    auto ret = AVRouter::GetInstance().OnDeviceAvailable(outputDeviceInfo);
    EXPECT_NE(ret, AVSESSION_SUCCESS);
    SLOGI("OnDeviceAvailable001 end");
}

/**
* @tc.name: OnCastServerDied001
* @tc.desc: setDiscoverable true
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, OnCastServerDied001, TestSize.Level1)
{
    SLOGI("OnCastServerDied001 begin");
    auto ret = AVRouter::GetInstance().OnCastServerDied(-1);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("OnCastServerDied001 end");
}

/**
* @tc.name: StartDeviceLogging001
* @tc.desc: test StartDeviceLogging
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, StartDeviceLogging001, TestSize.Level1)
{
    SLOGI("StartDeviceLogging001 begin");
    int32_t fd = 1;
    uint32_t maxSize = 10;
    auto ret = AVRouter::GetInstance().StartDeviceLogging(fd, maxSize);
    AVRouter::GetInstance().StopDeviceLogging();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("StartDeviceLogging001 end");
}

/**
* @tc.name: StartDeviceLogging002
* @tc.desc: test StartDeviceLogging
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, StartDeviceLogging002, TestSize.Level1)
{
    SLOGI("StartDeviceLogging002 begin");
    int32_t fd = 1;
    uint32_t maxSize = 10;
    AVRouter::GetInstance().Init(g_AVSessionService.get());
    auto ret = AVRouter::GetInstance().StartDeviceLogging(fd, maxSize);
    AVRouter::GetInstance().StopDeviceLogging();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("StartDeviceLogging002 end");
}

/**
* @tc.name: OnDeviceLogEvent001
* @tc.desc: test OnDeviceLogEvent
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, OnDeviceLogEvent001, TestSize.Level1)
{
    SLOGI("OnDeviceLogEvent001 begin");
    DeviceLogEventCode eventId = DEVICE_LOG_FULL;
    int64_t param = 0;
    AVRouter::GetInstance().Init(nullptr);
    auto ret = AVRouter::GetInstance().OnDeviceLogEvent(eventId, param);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("OnDeviceLogEvent001 end");
}

/**
* @tc.name: OnDeviceLogEvent002
* @tc.desc: test OnDeviceLogEvent
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, OnDeviceLogEvent002, TestSize.Level1)
{
    SLOGI("OnDeviceLogEvent002 begin");
    DeviceLogEventCode eventId = DEVICE_LOG_FULL;
    int64_t param = 0;
    AVRouter::GetInstance().Init(g_AVSessionService.get());
    auto ret = AVRouter::GetInstance().OnDeviceLogEvent(eventId, param);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("OnDeviceLogEvent002 end");
}

/**
* @tc.name: OnDeviceOffline001
* @tc.desc: test OnDeviceOffline
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, OnDeviceOffline001, TestSize.Level1)
{
    SLOGI("OnDeviceOffline001 begin");
    std::string deviceId = "***";
    AVRouter::GetInstance().Init(nullptr);
    auto ret = AVRouter::GetInstance().OnDeviceOffline(deviceId);
    EXPECT_EQ(ret, ERR_SERVICE_NOT_EXIST);
    SLOGI("OnDeviceOffline001 end");
}

/**
* @tc.name: OnDeviceOffline002
* @tc.desc: test OnDeviceOffline
* @tc.type: FUNC
* @tc.require: NA
*/
static HWTEST_F(AVRouterTest, OnDeviceOffline002, TestSize.Level1)
{
    SLOGI("OnDeviceOffline002 begin");
    AVRouter::GetInstance().Init(g_AVSessionService.get());
    std::string deviceId = "***";
    auto ret = AVRouter::GetInstance().OnDeviceOffline(deviceId);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("OnDeviceOffline002 end");
}
#endif
}
}