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

#ifndef OHOS_DEVICE_INFO_H
#define OHOS_DEVICE_INFO_H

#include "native_deviceinfo.h"
#include "avsession_log.h"
#include "native_avsession_errors.h"
#include "avsession_descriptor.h"

#include <string>

class OHDeviceInfo {
public:
    OHDeviceInfo() = default;
    OHDeviceInfo(int32_t castCategory, std::string deviceId, std::string deviceName, int32_t deviceType,
        int32_t supportedProtocols)
        : castCategory_(castCategory), deviceId_(deviceId), deviceName_(deviceName), deviceType_(deviceType),
        supportedProtocols_(supportedProtocols) {}

    int32_t GetAVCastCategory();
    const std::string& GetDeviceId();
    const std::string& GetDeviceName();
    int32_t GetDeviceType();
    int32_t GetSupportedProtocols();

    static AVSession_OutputDeviceInfo *ConvertDesc(const OHOS::AVSession::OutputDeviceInfo &outputDeviceInfoVec);
    static void DestroyAVSessionOutputDevice(AVSession_OutputDeviceInfo *array);

private:
    int32_t castCategory_ {};
    std::string deviceId_ = "";
    std::string deviceName_ = "";
    int32_t deviceType_ {};
    int32_t supportedProtocols_ {};
};

#endif // OHOS_DEVICE_INFO_H
