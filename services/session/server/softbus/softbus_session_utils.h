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

#ifndef SOFTBUS_SESSION_UTILS_H
#define SOFTBUS_SESSION_UTILS_H

#include <string>
#include "json/json.h"

namespace OHOS::AVSession {
class SoftbusSessionUtils {
public:
    static std::string AnonymizeDeviceId(const std::string &deviceId)
    {
        if (deviceId == "") {
            return "";
        }
        if (deviceId.length() <= DEVICE_ANONYMIZE_LENGTH) {
            return std::string(DEVICE_ANONYMIZE_ID);
        } else {
            unsigned long index =
                std::min<unsigned long>(deviceId.length() - DEVICE_ANONYMIZE_LENGTH, DEVICE_ANONYMIZE_LENGTH);
            std::string prefix = deviceId.substr(0, index);
            std::string suffix = deviceId.substr(deviceId.length() - index, deviceId.length());
            return prefix + std::string(DEVICE_ANONYMIZE_ID) + suffix;
        }
    }

    static inline void TransferJsonToStr(const Json::Value& jsonValue, std::string& jsonStr)
    {
        Json::FastWriter writer;
        jsonStr += writer.write(jsonValue);
    }

    static inline bool TransferStrToJson(const std::string& jsonStr, Json::Value& jsonValue)
    {
        Json::Reader jsonReader;
        if (!jsonReader.parse(jsonStr, jsonValue)) {
            return false;
        }
        return true;
    }

private:
    static constexpr const char *DEVICE_ANONYMIZE_ID = "******";
    static constexpr const int DEVICE_ANONYMIZE_LENGTH = 6;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_SESSION_UTILS_H