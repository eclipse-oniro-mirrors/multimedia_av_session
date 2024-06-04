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

#include "avsession_errors.h"
#include "avsession_log.h"
#include "bluetooth_adapter.h"
#include "parameter.h"
#include "parameters.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "av_router.h"
#endif

namespace OHOS {
namespace AVSession {
using namespace std;

static std::shared_ptr<DetectBluetoothHostObserver> g_bluetoothObserver =
    std::make_shared<DetectBluetoothHostObserver>();

DetectBluetoothHostObserver::DetectBluetoothHostObserver()
{
    auto deviceProp = system::GetParameter("const.product.devicetype", "default");
    SLOGI("GetDeviceType, deviceProp=%{public}s", deviceProp.c_str());
    is2in1_ = strcmp(deviceProp.c_str(), "2in1");
}

void DetectBluetoothHostObserver::OnStateChanged(const int transport, const int status)
{
    SLOGI("transport=%{public}d status=%{public}d", transport, status);
    if (transport != OHOS::Bluetooth::BTTransport::ADAPTER_BREDR) {
        return;
    }
    bool newStatus = (status == OHOS::Bluetooth::BTStateID::STATE_TURN_ON);
    if (newStatus == lastEnabled_) {
        return;
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (newStatus && is2in1_ == 0) {
        AVRouter::GetInstance().SetDiscoverable(false);
        AVRouter::GetInstance().SetDiscoverable(true);
    }
#endif
    lastEnabled_ = newStatus;
}

void BluetoothAdapter::CheckBrEnable()
{
    SLOGI("BluetoothAdapter CheckBrEnable in");
    OHOS::Bluetooth::BluetoothHost *bluetoothHost = &OHOS::Bluetooth::BluetoothHost::GetDefaultHost();
    if (bluetoothHost != nullptr) {
        SLOGI("BluetoothAdapter RegisterObserver in");
        bluetoothHost->RegisterObserver(g_bluetoothObserver);
    }
}

BluetoothAdapter& BluetoothAdapter::GetInstance()
{
    static BluetoothAdapter bluetoothAdapter;
    return bluetoothAdapter;
}


}  // namespace AVSession
}  // namespace OHOS