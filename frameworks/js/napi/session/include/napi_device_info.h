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

#ifndef OHOS_NAPI_DEVICE_INFO_H
#define OHOS_NAPI_DEVICE_INFO_H

#include "device_info.h"
#include "napi/native_api.h"

namespace OHOS::AVSession {
class NapiDeviceInfoClass {
// public:
//     static napi_status GetValue(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out);
//     static napi_status SetValue(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out);

//     using GetterType = std::function<napi_status(napi_env, napi_value in, std::shared_ptr<DeviceInfoClass>& out)>;
//     using SetterType = std::function<napi_status(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out)>;

// private:
//     static napi_status GetDeviceCategory(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out);
//     static napi_status SetDeviceCategory(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out);

//     static napi_status GetDeviceId(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out);
//     static napi_status SetDeviceId(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out);

//     static napi_status GetDeviceName(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out);
//     static napi_status SetDeviceName(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out);

//     static napi_status GetDeviceType(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out);
//     static napi_status SetDeviceType(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out);

//     static napi_status GetIpAddress(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out);
//     static napi_status SetIpAddress(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out);

//     static napi_status GetProviderId(napi_env env, napi_value in, std::shared_ptr<DeviceInfoClass>& out);
//     static napi_status SetProviderId(napi_env env, const std::shared_ptr<DeviceInfoClass>& in, napi_value& out);

//     static std::map<std::string, GetterType> getterMap_;
//     static std::map<int32_t, SetterType> setterMap_;

//     static constexpr int GETTER_INDEX = 0;
//     static constexpr int SETTER_INDEX = 1;
//     static constexpr int ENUM_INDEX = 2;
};
}
#endif // OHOS_NAPI_DEVICE_INFO_H
