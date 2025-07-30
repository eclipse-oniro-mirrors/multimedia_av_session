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
#include "cJSON.h"
#include "migrate_avsession_constant.h"

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

    static inline void TransferJsonToStr(cJSON* jsonValue, std::string& jsonStr)
    {
        if (jsonValue == nullptr || cJSON_IsInvalid(jsonValue)) {
            jsonStr += "ERR_JSON";
            return;
        }
        char* jsonValueStr = cJSON_Print(jsonValue);
        if (jsonValueStr != nullptr) {
            jsonStr.append(jsonValueStr);
            cJSON_free(jsonValueStr);
        }
    }

    static inline bool TransferStrToJson(const std::string& jsonStr, cJSON*& jsonValue)
    {
        jsonValue = cJSON_Parse(jsonStr.c_str());
        if (jsonValue == nullptr) {
            return false;
        }
        if (cJSON_IsInvalid(jsonValue) || cJSON_IsNull(jsonValue)) {
            cJSON_Delete(jsonValue);
            return false;
        }
        return true;
    }

    static inline bool AddStringToJson(cJSON* item, const char* key, const std::string& value)
    {
        if (item == nullptr || cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return false;
        }
        cJSON_AddStringToObject(item, key, value.c_str());
        if (cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return false;
        }
        return true;
    }

    static inline bool AddIntToJson(cJSON* item, const char* key, int value)
    {
        if (item == nullptr || cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return false;
        }
        cJSON_AddNumberToObject(item, key, static_cast<long long>(value));
        if (cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return false;
        }
        return true;
    }

    static inline bool AddBoolToJson(cJSON* item, const char* key, bool value)
    {
        if (item == nullptr || cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return false;
        }
        cJSON_AddBoolToObject(item, key, value);
        if (cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return false;
        }
        return true;
    }

    static inline bool AddJsonArrayToJson(cJSON*& item, const char* key, cJSON*& jsonArray)
    {
        if (item == nullptr || cJSON_IsInvalid(item) || cJSON_IsNull(item) ||
            jsonArray == nullptr || cJSON_IsInvalid(jsonArray) || !cJSON_IsArray(jsonArray)) {
            cJSON_Delete(jsonArray);
            return false;
        }
        cJSON_AddItemToObject(item, key, jsonArray);
        if (cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return false;
        }
        return true;
    }

    static inline bool AddJsonToJsonArray(cJSON*& jsonArray, int32_t index, cJSON*& item)
    {
        if (jsonArray == nullptr || cJSON_IsInvalid(jsonArray) || !cJSON_IsArray(jsonArray) ||
            item == nullptr || cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            cJSON_Delete(item);
            return false;
        }
        cJSON_InsertItemInArray(jsonArray, index, item);
        if (cJSON_IsInvalid(jsonArray) || cJSON_IsNull(jsonArray)) {
            return false;
        }
        return true;
    }

    static inline std::string GetStringFromJson(cJSON* item, const char* key)
    {
        if (item == nullptr || cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return "";
        }
        cJSON* value = cJSON_GetObjectItem(item, key);
        if (value == nullptr || cJSON_IsInvalid(value) || !cJSON_IsString(value)) {
            return "";
        }
        return std::string(value->valuestring);
    }

    static inline int GetIntFromJson(cJSON* item, const char* key)
    {
        if (item == nullptr || cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return -1;
        }
        cJSON* value = cJSON_GetObjectItem(item, key);
        if (value == nullptr || cJSON_IsInvalid(value) || !cJSON_IsNumber(value)) {
            return -1;
        }
        return value->valueint;
    }

    static inline bool GetBoolFromJson(cJSON* item, const char* key)
    {
        if (item == nullptr || cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            return false;
        }
        cJSON* value = cJSON_GetObjectItem(item, key);
        if (value == nullptr || cJSON_IsInvalid(value) || !cJSON_IsBool(value)) {
            return false;
        }
        return cJSON_IsTrue(value);
    }

    static inline cJSON* GetNewCJSONObject()
    {
        cJSON* value = cJSON_CreateObject();
        if (value == nullptr) {
            return nullptr;
        }
        if (cJSON_IsInvalid(value) || cJSON_IsNull(value)) {
            cJSON_Delete(value);
            return nullptr;
        }
        return value;
    }

    static inline cJSON* GetNewCJSONArray()
    {
        cJSON* valueArray = cJSON_CreateArray();
        if (valueArray == nullptr) {
            return nullptr;
        }
        if (cJSON_IsInvalid(valueArray) || !cJSON_IsArray(valueArray)) {
            cJSON_Delete(valueArray);
            return nullptr;
        }
        return valueArray;
    }

    static bool CheckCJSONObjectEmpty(cJSON* item)
    {
        if (item == nullptr) {
            return true;
        }
        if (cJSON_IsInvalid(item) || cJSON_IsNull(item)) {
            cJSON_Delete(item);
            return true;
        }
        if (item->child == nullptr) {
            cJSON_Delete(item);
            return true;
        }
        return false;
    }

    static bool CopyCJSONObject(cJSON*& fromItem, cJSON*& toItem)
    {
        if (toItem != nullptr) {
            cJSON_Delete(toItem);
            toItem = nullptr;
        }
        if (fromItem == nullptr || cJSON_IsInvalid(fromItem) || cJSON_IsNull(fromItem)) {
            return false;
        }
        toItem = cJSON_Duplicate(fromItem, true);
        return true;
    }

    static std::string GetEncryptAddr(const std::string& addr)
    {
        if (addr.empty() || addr.length() != addressStrLen) {
            return std::string("");
        }
        std::string tmp = "**:**:**:**:**:**";
        std::string out = addr;
        for (int i = startPos; i <= endPos; i++) {
            out[i] = tmp[i];
        }
        return out;
    }

    static std::string AnonymizeMacAddressInSoftBusMsg(const std::string& input)
    {
        std::string output = input;
        std::string macKey = "\"" + std::string(AUDIO_MAC_ADDRESS) + "\":\"";
        std::string endKey = "\"";
        size_t startPos = 0;

        while ((startPos = output.find(macKey, startPos)) != std::string::npos) {
            startPos += macKey.length();
            size_t endPos = output.find(endKey, startPos);
            if (endPos != std::string::npos) {
                std::string macAddress = output.substr(startPos, endPos - startPos);
                std::string encryptedMac = GetEncryptAddr(macAddress);
                output.replace(startPos, endPos - startPos, encryptedMac);
            }
        }
        return output;
    }

private:
    static constexpr const char *DEVICE_ANONYMIZE_ID = "******";
    static constexpr const int DEVICE_ANONYMIZE_LENGTH = 6;

    static constexpr const int addressStrLen = 17;
    static constexpr const int startPos = 6;
    static constexpr const int endPos = 13;
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_SESSION_UTILS_H