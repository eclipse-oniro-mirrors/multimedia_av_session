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

#ifndef AV_SESSION_BLUETOOTH_ADAPTER_H
#define AV_SESSION_BLUETOOTH_ADAPTER_H

#include "bluetooth_host.h"

namespace OHOS::AVSession {

class DetectBluetoothHostObserver : public OHOS::Bluetooth::BluetoothHostObserver {
public:
    DetectBluetoothHostObserver();
    virtual ~DetectBluetoothHostObserver() = default;
    void OnStateChanged(const int transport, const int status) override;
    void OnDiscoveryStateChanged(int status) override
    {
        return;
    }
    
    void OnDiscoveryResult(const OHOS::Bluetooth::BluetoothRemoteDevice &device, int rssi,
        const std::string& deviceName, int deviceClass) override
    {
        return;
    }

    void OnPairRequested(const OHOS::Bluetooth::BluetoothRemoteDevice &device) override
    {
        return;
    }

    void OnPairConfirmed(const OHOS::Bluetooth::BluetoothRemoteDevice &device, int reqType, int number) override
    {
        return;
    }

    void OnScanModeChanged(int mode) override
    {
        return;
    }

    void OnDeviceNameChanged(const std::string &deviceName) override
    {
        return;
    }

    void OnDeviceAddrChanged(const std::string &address) override
    {
        return;
    }

private:
    bool is2in1_ = false;
    bool lastEnabled_ = false;
};

class BluetoothAdapter {
public:
    static BluetoothAdapter& GetInstance();
    void CheckBrEnable();
};

}
#endif // AV_SESSION_BLUETOOTH_ADAPTER_H
