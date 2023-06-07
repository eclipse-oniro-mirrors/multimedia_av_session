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

#include "napi_device_info.h"
#include "avsession_log.h"
#include "napi_utils.h"

namespace OHOS::AVSession {
// std::map<std::string, NapiDeviceInfoClass::GetterType> NapiDeviceInfoClass::getterMap_ = {
//     { "deviceCategory", GetDeviceCategory },
//     { "deviceId", GetDeviceId },
//     { "deviceName", GetDeviceName },
//     { "deviceType", GetDeviceType },
//     { "ipAddress",  GetIpAddress },
//     { "providerId", GetProviderId },
// };

// std::map<int32_t, NapiDeviceInfoClass::SetterType> NapiDeviceInfoClass::setterMap_ = {
//     { DeviceInfoClass::DEVICE_INFO_KEY_DEVICE_CATEGORY, SetDeviceCategory },
//     { DeviceInfoClass::DEVICE_INFO_KEY_DEVICE_ID, SetDeviceId },
//     { DeviceInfoClass::DEVICE_INFO_KEY_DEVICE_NAME, SetDeviceName },
//     { DeviceInfoClass::DEVICE_INFO_KEY_DEVICE_TYPE, SetDeviceType },
//     { DeviceInfoClass::DEVICE_INFO_KEY_IP_ADDRESS, SetIpAddress },
//     { DeviceInfoClass::DEVICE_INFO_KEY_PROVIDER_ID, SetProviderId },
// };

// napi_status NapiDeviceInfoClass::GetValue(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out)
// {
//     std::vector<std::string> propertyNames;
//     auto status = NapiUtils::GetPropertyNames(env, in, propertyNames);
//     CHECK_RETURN(status == napi_ok, "get property name failed", status);

//     for (const auto& name : propertyNames) {
//         auto it = getterMap_.find(name);
//         if (it == getterMap_.end()) {
//             SLOGE("property %{public}s is not of mediadescription", name.c_str());
//             return napi_invalid_arg;
//         }
//         auto getter = it->second;
//         if (getter(env, in, out) != napi_ok) {
//             SLOGE("get property %{public}s failed", name.c_str());
//             return napi_generic_failure;
//         }
//     }

//     return napi_ok;
// }

// napi_status NapiDeviceInfoClass::SetValue(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out)
// {
//     napi_status status = napi_create_object(env, &out);
//     CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

//     for (int i = 0; i < DeviceInfoClass::DEVICE_INFO_KEY_MAX; ++i) {
//         auto setter = setterMap_[i];
//         if (setter(env, in, out) != napi_ok) {
//             SLOGE("set property %{public}d failed", i);
//             return napi_generic_failure;
//         }
//     }
//     return napi_ok;
// }

// napi_status NapiDeviceInfoClass::GetDeviceCategory(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out)
// {
//     std::string property;
//     auto status = NapiUtils::GetNamedProperty(env, in, "deviceCategory", property);
//     CHECK_RETURN(status == napi_ok, "get property failed", status);
//     out->SetDeviceCategory(property);
//     return status;
// }

// napi_status NapiDeviceInfoClass::SetDeviceCategory(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out)
// {
//     napi_value property {};
//     auto status = NapiUtils::SetValue(env, in->GetDeviceCategory(), property);
//     CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
//     status = napi_set_named_property(env, out, "deviceCategory", property);
//     CHECK_RETURN(status == napi_ok, "set property failed", status);
//     return status;
// }

// napi_status NapiDeviceInfoClass::GetDeviceId(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out)
// {
//     std::string property;
//     auto status = NapiUtils::GetNamedProperty(env, in, "deviceId", property);
//     CHECK_RETURN(status == napi_ok, "get property failed", status);
//     out->SetDeviceId(property);
//     return status;
// }

// napi_status NapiDeviceInfoClass::SetDeviceId(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out)
// {
//     napi_value property {};
//     auto status = NapiUtils::SetValue(env, in->GetDeviceId(), property);
//     CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
//     status = napi_set_named_property(env, out, "deviceId", property);
//     CHECK_RETURN(status == napi_ok, "set property failed", status);
//     return status;
// }

// napi_status NapiDeviceInfoClass::GetDeviceName(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out)
// {
//     std::string property;
//     auto status = NapiUtils::GetNamedProperty(env, in, "deviceName", property);
//     CHECK_RETURN(status == napi_ok, "get property failed", status);
//     out->SetDeviceName(property);
//     return status;
// }

// napi_status NapiDeviceInfoClass::SetDeviceName(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out)
// {
//     napi_value property {};
//     auto status = NapiUtils::SetValue(env, in->GetDeviceName(), property);
//     CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
//     status = napi_set_named_property(env, out, "deviceName", property);
//     CHECK_RETURN(status == napi_ok, "set property failed", status);
//     return status;
// }

// napi_status NapiDeviceInfoClass::GetDeviceType(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out)
// {
//     std::string property;
//     auto status = NapiUtils::GetNamedProperty(env, in, "deviceType", property);
//     CHECK_RETURN(status == napi_ok, "get property failed", status);
//     out->SetDeviceType(property);
//     return status;
// }
// napi_status NapiDeviceInfoClass::SetDeviceType(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out)
// {
//     napi_value property {};
//     auto status = NapiUtils::SetValue(env, in->GetDeviceType(), property);
//     CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
//     status = napi_set_named_property(env, out, "deviceType", property);
//     CHECK_RETURN(status == napi_ok, "set property failed", status);
//     return status;
// }

// napi_status NapiDeviceInfoClass::GetIpAddress(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out)
// {
//     int32_t property;
//     auto status = NapiUtils::GetNamedProperty(env, in, "ipAddress", property);
//     CHECK_RETURN(status == napi_ok, "get property failed", status);
//     out->SetIpAddress(property);
//     return status;
// }
// napi_status NapiDeviceInfoClass::SetIpAddress(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out)
// {
//     napi_value property {};
//     auto status = NapiUtils::SetValue(env, in->GetIpAddress(), property);
//     CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
//     status = napi_set_named_property(env, out, "ipAddress", property);
//     CHECK_RETURN(status == napi_ok, "set property failed", status);
//     return status;
// }

// napi_status NapiDeviceInfoClass::GetProviderId(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out)
// {
//     int32_t property;
//     auto status = NapiUtils::GetNamedProperty(env, in, "providerId", property);
//     CHECK_RETURN(status == napi_ok, "get property failed", status);
//     out->SetProviderId(property);
//     return status;
// }
// napi_status NapiDeviceInfoClass::SetProviderId(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out)
// {
//     napi_value property {};
//     auto status = NapiUtils::SetValue(env, in->GetProviderId(), property);
//     CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
//     status = napi_set_named_property(env, out, "providerId", property);
//     CHECK_RETURN(status == napi_ok, "set property failed", status);
//     return status;
// }
} // namespace OHOS::AVSession
