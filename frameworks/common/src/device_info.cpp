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

#include "device_info.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
// bool DeviceInfoClass::Marshalling(Parcel& parcel) const
// {
//     CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceCategory_), false, "write deviceCategory failed");
//     CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceId_), false, "write deviceId failed");
//     CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceName_), false, "write deviceName failed");
//     CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceType_), false, "write deviceType failed");
//     CHECK_AND_RETURN_RET_LOG(out.WriteString(ipAddress_), false, "write ipAddress failed");
//     CHECK_AND_RETURN_RET_LOG(out.WriteInt32(providerId_), false, "write providerId failed");

//     return true;
// }

// DeviceInfoClass *DeviceInfoClass::Unmarshalling(Parcel& data)
// {
//     auto *result = new (std::nothrow) DeviceInfoClass();

//     CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new DeviceInfoClass failed");
//     CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceCategory_), false, "Read deviceCategory failed");
//     CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceId_), false, "Read deviceId failed");
//     CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceName_), false, "Read deviceName failed");
//     CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceType_), false, "Read deviceType failed");
//     CHECK_AND_RETURN_RET_LOG(in.ReadString(ipAddress_), false, "Read ipAddress failed");
//     CHECK_AND_RETURN_RET_LOG(in.ReadInt32(providerId_), false, "Read providerId failed");

//     return result;
// }

// void DeviceInfoClass::SetDeviceCategory(const int32_t deviceCategory)
// {
//     deviceCategory_ = deviceCategory;
// }

// int32_t DeviceInfoClass::GetDeviceCategory() const
// {
//     return deviceCategory_;
// }

// void DeviceInfoClass::SetDeviceId(const std::string& deviceId)
// {
//     deviceId_ = deviceId;
// }

// std::string DeviceInfoClass::GetDeviceId() const
// {
//     return deviceId_;
// }

// void DeviceInfoClass::SetDeviceName(const std::string& deviceName)
// {
//     deviceName_ = deviceName;
// }

// std::string DeviceInfoClass::GetDeviceName() const
// {
//     return deviceName_;
// }

// void DeviceInfoClass::SetDeviceType(const int32_t deviceType)
// {
//     deviceType_ = deviceType;
// }

// int32_t DeviceInfoClass::GetDeviceType() const
// {
//     return deviceType_;
// }

// void DeviceInfoClass::SetIpAddress(const std::string& ipAddress)
// {
//     ipAddress_ = ipAddress;
// }

// std::string DeviceInfoClass::GetIpAddress() const
// {
//     return ipAddress_;
// }

// void DeviceInfoClass::SetProviderId(const int32_t providerId)
// {
//     providerId_ = providerId;
// }

// int32_t DeviceInfoClass::GetProviderId() const
// {
//     return providerId_;
// }

// bool DeviceInfoClass::IsValid() const
// {
//     return !(deviceId_.empty());
// }

// void DeviceInfoClass::Reset()
// {
//     deviceCategory_ = 0;
//     deviceId_ = "";
//     deviceName_ = "";
//     deviceType_ = 0;
//     ipAddress_ = "";
//     providerId_ = 0;
// }
} // namespace OHOS::AVSession
