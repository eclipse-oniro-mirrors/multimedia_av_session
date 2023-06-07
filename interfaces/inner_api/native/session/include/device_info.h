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

#ifndef OHOS_DEVICE_INFO_H
#define OHOS_DEVICE_INFO_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "parcel.h"
#include "avsession_pixel_map.h"

namespace OHOS::AVSession {
class DeviceInfoClass : public Parcelable {
// public:
//     enum {
//         DEVICE_INFO_KEY_DEVICE_CATEGORY = 0,
//         DEVICE_INFO_KEY_DEVICE_ID = 1,
//         DEVICE_INFO_KEY_DEVICE_NAME = 2,
//         DEVICE_INFO_KEY_DEVICE_TYPE = 3,
//         DEVICE_INFO_KEY_IP_ADDRESS = 4,
//         DEVICE_INFO_KEY_PROVIDER_ID = 5,
//         DEVICE_INFO_KEY_MAX = 6,

//     };
//     DeviceInfoClass() = default;
//     ~DeviceInfoClass() = default;

//     static DeviceInfoClass* Unmarshalling(Parcel& data);
//     bool Marshalling(Parcel& parcel) const override;

//     void SetDeviceCategory(const int32_t deviceCategory);
//     int32_t GetDeviceCategory() const;

//     void SetDeviceId(const std::string& deviceId);
//     std::string GetDeviceId() const;

//     void SetDeviceName(const std::string& deviceName);
//     std::string GetDeviceName() const;

//     void SetDeviceType(const int32_t deviceType);
//     int32_t GetDeviceType() const;

//     void SetIpAddress(const std::string& ipAddress);
//     std::string GetIpAddress() const;

//     void SetProviderId(const int32_t providerId);
//     int32_t GetProviderId() const;

//     bool IsValid() const;

//     void Reset();

// private:
//     int32_t deviceCategory_ = 0;
//     std::string deviceId_ = "";
//     std::string deviceName_ = "";
//     int32_t deviceType_ = 0;
//     std::string ipAddress_ = "";
//     int32_t providerId_ = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_DEVICE_INFO_H
