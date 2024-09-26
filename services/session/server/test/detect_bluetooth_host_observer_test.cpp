
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
#include "avsession_service.h"
#ifdef BLUETOOTH_ENABLE
#include "bluetooth_def.h"
#endif

using namespace testing::ext;
namespace OHOS {
namespace AVSession {

static std::shared_ptr<AVSessionService> g_AVSessionService;
class DetectBluetoothHostObserverTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DetectBluetoothHostObserverTest::SetUpTestCase()
{
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID);
}

void DetectBluetoothHostObserverTest::TearDownTestCase()
{
    g_AVSessionService->Close();
}

void DetectBluetoothHostObserverTest::SetUp()
{
}

void DetectBluetoothHostObserverTest::TearDown()
{
}

#ifdef BLUETOOTH_ENABLE
/**
 * @tc.name: OnStateChanged001
 * @tc.desc: test OnStateChanged
 * @tc.type: FUNC
 */
HWTEST_F(DetectBluetoothHostObserverTest, OnStateChanged001, TestSize.Level1)
{
    DetectBluetoothHostObserver detectBluetoothHostObserver(g_AVSessionService.get());
    EXPECT_TRUE(g_AVSessionService.get() != nullptr);
    int32_t transport = OHOS::Bluetooth::BTTransport::ADAPTER_BREDR;
    int32_t status = OHOS::Bluetooth::BTStateID::STATE_TURN_ON;
    detectBluetoothHostObserver.OnStateChanged(transport, status);
}

/**
 * @tc.name: OnStateChanged002
 * @tc.desc: test OnStateChanged
 * @tc.type: FUNC
 */
HWTEST_F(DetectBluetoothHostObserverTest, OnStateChanged002, TestSize.Level1)
{
    DetectBluetoothHostObserver detectBluetoothHostObserver(g_AVSessionService.get());
    EXPECT_TRUE(g_AVSessionService.get() != nullptr);
    int32_t transport = OHOS::Bluetooth::BTTransport::ADAPTER_BLE;
    int32_t status = OHOS::Bluetooth::BTStateID::STATE_TURN_ON;
    detectBluetoothHostObserver.OnStateChanged(transport, status);
}

/**
 * @tc.name: OnStateChanged003
 * @tc.desc: test OnStateChanged
 * @tc.type: FUNC
 */
HWTEST_F(DetectBluetoothHostObserverTest, OnStateChanged003, TestSize.Level1)
{
    DetectBluetoothHostObserver detectBluetoothHostObserver(g_AVSessionService.get());
    EXPECT_TRUE(g_AVSessionService.get() != nullptr);
    int32_t transport = OHOS::Bluetooth::BTTransport::ADAPTER_BLE;
    int32_t status = OHOS::Bluetooth::BTStateID::STATE_TURN_OFF;
    detectBluetoothHostObserver.OnStateChanged(transport, status);
}

/**
 * @tc.name: OnStateChanged004
 * @tc.desc: test OnStateChanged
 * @tc.type: FUNC
 */
HWTEST_F(DetectBluetoothHostObserverTest, OnStateChanged004, TestSize.Level1)
{
    std::shared_ptr<AVSessionService> avSessionService(nullptr);
    DetectBluetoothHostObserver detectBluetoothHostObserver(avSessionService.get());
    EXPECT_TRUE(avSessionService.get() == nullptr);
    int32_t transport = OHOS::Bluetooth::BTTransport::ADAPTER_BREDR;
    int32_t status = OHOS::Bluetooth::BTStateID::STATE_TURN_ON;
    detectBluetoothHostObserver.OnStateChanged(transport, status);
}
#endif
}
}