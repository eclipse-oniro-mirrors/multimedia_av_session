/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "json_utils.h"
#include "avsession_log.h"
#include "av_session.h"

namespace OHOS::AVSession {
int32_t JsonUtils::ConvertSessionType(const std::string& typeString)
{
    int32_t typeNum = AVSession::SESSION_TYPE_INVALID;
    if (typeString == "audio") {
        typeNum = AVSession::SESSION_TYPE_AUDIO;
    } else if (typeString == "video") {
        typeNum = AVSession::SESSION_TYPE_VIDEO;
    }
    return typeNum;
}

std::string JsonUtils::ConvertSessionType(int32_t type)
{
    if (type == AVSession::SESSION_TYPE_AUDIO) {
        return "audio";
    } else if (type == AVSession::SESSION_TYPE_VIDEO) {
        return "video";
    } else {
        return "";
    }
}

int32_t JsonUtils::JsonToVector(cJSON* object, std::vector<int32_t>& out)
{
    CHECK_AND_RETURN_RET_LOG(object != nullptr, AVSESSION_ERROR, "json object is null");
    CHECK_AND_RETURN_RET_LOG(!cJSON_IsInvalid(object), AVSESSION_ERROR, "json object is invalid");
    CHECK_AND_RETURN_RET_LOG(cJSON_IsArray(object), AVSESSION_ERROR, "json object is not array");

    const cJSON* numberItem = nullptr;
    cJSON_ArrayForEach(numberItem, object) {
        CHECK_AND_CONTINUE(numberItem != nullptr && !cJSON_IsInvalid(numberItem) && cJSON_IsNumber(numberItem));
        out.push_back(numberItem->valueint);
    }
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetIntVectorToCJSON(cJSON* jsonObject, std::string key, const std::vector<int32_t>& array)
{
    CHECK_AND_RETURN_RET_LOG(jsonObject != nullptr, AVSESSION_ERROR, "json object is null");
    CHECK_AND_RETURN_RET_LOG(!cJSON_IsInvalid(jsonObject), AVSESSION_ERROR, "json object is invalid");
    cJSON* itemArray = cJSON_CreateArray();
    CHECK_AND_RETURN_RET_LOG(itemArray != nullptr, AVSESSION_ERROR, "itemArray is null");
    if (cJSON_IsInvalid(itemArray) || !cJSON_IsArray(itemArray)) {
        SLOGE("itemArray is invalid");
        cJSON_Delete(itemArray);
        return AVSESSION_ERROR;
    }
    for (int32_t g_val : array) {
        cJSON* valItem = cJSON_CreateNumber(g_val);
        if (valItem == nullptr) {
            SLOGE("fail create number");
            cJSON_Delete(itemArray);
            return AVSESSION_ERROR;
        }
        cJSON_AddItemToArray(itemArray, valItem);
    }
    cJSON_AddItemToObject(jsonObject, key.c_str(), itemArray);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetJsonCapability(const std::vector<std::vector<int32_t>>& capability, std::string& jsonCapability)
{
    cJSON* jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        SLOGE("create json object get nullptr");
        return AVSESSION_ERROR;
    }
    if (cJSON_IsInvalid(jsonObject)) {
        SLOGE("create json object get invalid");
        cJSON_Delete(jsonObject);
        return AVSESSION_ERROR;
    }

    // cjson jsonObject;
    for (uint32_t g_i = 0; g_i < capability.size(); g_i++) {
        if (g_i == SESSION_DATA_META) {
            SetIntVectorToCJSON(jsonObject, "metaData", capability[g_i]);
            continue;
        }
        if (g_i == SESSION_DATA_PLAYBACK_STATE) {
            SetIntVectorToCJSON(jsonObject, "playbackState", capability[g_i]);
            continue;
        }
        if (g_i == SESSION_DATA_CONTROL_COMMAND) {
            SetIntVectorToCJSON(jsonObject, "controlCommand", capability[g_i]);
            continue;
        }
    }
    if (cJSON_IsInvalid(jsonObject)) {
        SLOGE("get json object invalid aft addNumber");
        cJSON_Delete(jsonObject);
        return AVSESSION_ERROR;
    }

    char* g_jsonStr = cJSON_Print(jsonObject);
    if (g_jsonStr != nullptr) {
        jsonCapability = g_jsonStr;
        cJSON_free(g_jsonStr);
    } else {
        SLOGE("get json str with nullptr");
    }
    cJSON_Delete(jsonObject);
    return AVSESSION_SUCCESS;
}

bool JsonUtils::IsInt32(cJSON* jsonObj, const std::string& key)
{
    if (!cJSON_HasObjectItem(jsonObj, key.c_str())) {
        SLOGE("The key %{public}s of jsonObj is not found", key.c_str());
        return false;
    }
    cJSON* numberItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    bool g_res = numberItem != nullptr && !cJSON_IsInvalid(numberItem) && cJSON_IsNumber(numberItem) &&
        INT32_MIN <= numberItem->valueint && numberItem->valueint <= INT32_MAX;
    if (!g_res) {
        SLOGE("The key %{public}s of jsonObj is invalid", key.c_str());
    }
    return g_res;
}

bool JsonUtils::IsString(cJSON* jsonObj, const std::string& key)
{
    if (!cJSON_HasObjectItem(jsonObj, key.c_str())) {
        SLOGE("The key %{public}s of jsonObj is not found", key.c_str());
        return false;
    }
    cJSON* stringItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    bool res = stringItem != nullptr && !cJSON_IsInvalid(stringItem) && cJSON_IsString(stringItem);
    if (!res) {
        SLOGE("The key %{public}s of jsonObj is invalid", key.c_str());
    }
    return res;
}

bool JsonUtils::IsBool(cJSON* jsonObj, const std::string& key)
{
    if (!cJSON_HasObjectItem(jsonObj, key.c_str())) {
        SLOGE("The key %{public}s of jsonObj is not found", key.c_str());
        return false;
    }
    cJSON* boolItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    bool res = boolItem != nullptr && !cJSON_IsInvalid(boolItem) && cJSON_IsBool(boolItem);
    if (!res) {
        SLOGE("The key %{public}s of jsonObj is invalid", key.c_str());
    }
    return res;
}

int32_t JsonUtils::GetVectorCapability(const std::string& jsonCapability,
                                       std::vector<std::vector<int32_t>>& vectorCapability)
{
    CHECK_AND_RETURN_RET_LOG(!jsonCapability.empty(), AVSESSION_ERROR, "jsonCapability is empty");
    cJSON* jsonObj = cJSON_Parse(jsonCapability.c_str());
    CHECK_AND_RETURN_RET_LOG(jsonObj != nullptr, AVSESSION_ERROR, "parse json with nullptr");
    if (cJSON_IsInvalid(jsonObj)) {
        SLOGE("json obj is invalid");
        cJSON_Delete(jsonObj);
        return AVSESSION_ERROR;
    }
    cJSON* metaDataItemArray = cJSON_GetObjectItem(jsonObj, "metaData");
    int32_t g_ret = JsonToVector(metaDataItemArray, vectorCapability[SESSION_DATA_META]);
    CHECK_AND_CONTINUE_LOG(g_ret == AVSESSION_SUCCESS, "Get metaDataCapability error");

    cJSON* playbackStateItemArray = cJSON_GetObjectItem(jsonObj, "playbackState");
    g_ret = JsonToVector(playbackStateItemArray, vectorCapability[SESSION_DATA_PLAYBACK_STATE]);
    CHECK_AND_CONTINUE_LOG(g_ret == AVSESSION_SUCCESS, "Get playbackStateCapability error");

    cJSON* controlCommandArray = cJSON_GetObjectItem(jsonObj, "controlCommand");
    g_ret = JsonToVector(controlCommandArray, vectorCapability[SESSION_DATA_CONTROL_COMMAND]);
    CHECK_AND_CONTINUE_LOG(g_ret == AVSESSION_SUCCESS, "Get controlCommandCapability error");

    cJSON_Delete(jsonObj);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetAllCapability(const std::string& sessionInfo, std::string& jsonCapability)
{
    CHECK_AND_RETURN_RET_LOG(!sessionInfo.empty(), AVSESSION_ERROR, "sessionInfo is empty");
    cJSON* jsonSessionInfo = cJSON_Parse(sessionInfo.c_str());
    CHECK_AND_RETURN_RET_LOG(jsonSessionInfo != nullptr, AVSESSION_ERROR, "json object is null");
    if (cJSON_IsInvalid(jsonSessionInfo) || cJSON_IsNull(jsonSessionInfo)) {
        SLOGE("jsonSessionInfo get invalid");
        cJSON_Delete(jsonSessionInfo);
        return AVSESSION_ERROR;
    }
    cJSON* compatibilityItem = cJSON_GetObjectItem(jsonSessionInfo, "compatibility");
    if (compatibilityItem == nullptr || cJSON_IsInvalid(compatibilityItem) || cJSON_IsNull(compatibilityItem)) {
        SLOGE("GetCompatibility error");
        cJSON_Delete(jsonSessionInfo);
        return AVSESSION_ERROR;
    }
    cJSON* capabilitySetItem = cJSON_GetObjectItem(compatibilityItem, "capabilitySet");
    if (capabilitySetItem == nullptr || cJSON_IsInvalid(capabilitySetItem) || cJSON_IsNull(capabilitySetItem)) {
        SLOGE("GetCapabilitySet error");
        cJSON_Delete(jsonSessionInfo);
        return AVSESSION_ERROR;
    }

    char* g_capabilitySetStr = cJSON_Print(capabilitySetItem);
    if (g_capabilitySetStr != nullptr) {
        jsonCapability = g_capabilitySetStr;
        cJSON_free(g_capabilitySetStr);
    } else {
        SLOGE("get g_capabilitySetStr nullptr");
        cJSON_Delete(jsonSessionInfo);
        return AVSESSION_ERROR;
    }
    cJSON_Delete(jsonSessionInfo);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionCapabilitySet(cJSON* jsonObj, const AVSessionBasicInfo& basicInfo)
{
    CHECK_AND_RETURN_RET_LOG(jsonObj != nullptr && !cJSON_IsInvalid(jsonObj), AVSESSION_ERROR, "json object is err");
    cJSON* capabilitySetItem = cJSON_GetObjectItem(jsonObj, "capabilitySet");
    if (capabilitySetItem == nullptr || cJSON_IsInvalid(capabilitySetItem) || cJSON_IsNull(capabilitySetItem)) {
        capabilitySetItem = cJSON_CreateObject();
        cJSON_AddItemToObject(jsonObj, "capabilitySet", capabilitySetItem);
    }

    cJSON* metaDataCapArray = cJSON_CreateArray();
    for (int32_t g_val : basicInfo.metaDataCap_) {
        cJSON* valItem = cJSON_CreateNumber(g_val);
        if (valItem == nullptr) {
            SLOGE("fail create number for metaData");
            cJSON_Delete(metaDataCapArray);
            return AVSESSION_ERROR;
        }
        cJSON_AddItemToArray(metaDataCapArray, valItem);
    }
    cJSON_AddItemToObject(capabilitySetItem, "metaData", metaDataCapArray);
    cJSON* playBackStateCapArray = cJSON_CreateArray();
    for (int32_t val : basicInfo.playBackStateCap_) {
        cJSON* valItem = cJSON_CreateNumber(val);
        if (valItem == nullptr) {
            SLOGE("fail create number for playbackState");
            cJSON_Delete(playBackStateCapArray);
            return AVSESSION_ERROR;
        }
        cJSON_AddItemToArray(playBackStateCapArray, valItem);
    }
    cJSON_AddItemToObject(capabilitySetItem, "playbackState", playBackStateCapArray);
    cJSON* controlCommandCapArray = cJSON_CreateArray();
    for (int32_t val : basicInfo.controlCommandCap_) {
        cJSON* valItem = cJSON_CreateNumber(val);
        if (valItem == nullptr) {
            SLOGE("fail create number for controlCommand");
            cJSON_Delete(controlCommandCapArray);
            return AVSESSION_ERROR;
        }
        cJSON_AddItemToArray(controlCommandCapArray, valItem);
    }
    cJSON_AddItemToObject(capabilitySetItem, "controlCommand", controlCommandCapArray);

    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionCompatibility(cJSON* jsonObj, const AVSessionBasicInfo& basicInfo)
{
    CHECK_AND_RETURN_RET_LOG(jsonObj != nullptr && !cJSON_IsInvalid(jsonObj), AVSESSION_ERROR, "json object is err");
    cJSON* compatibilityItem = cJSON_GetObjectItem(jsonObj, "compatibility");
    if (compatibilityItem == nullptr || cJSON_IsInvalid(compatibilityItem) || cJSON_IsNull(compatibilityItem)) {
        compatibilityItem = cJSON_CreateObject();
        CHECK_AND_RETURN_RET_LOG(cJSON_AddItemToObject(jsonObj, "compatibility", compatibilityItem),
            AVSESSION_ERROR, "fail create compatibilityItem");
    }
    cJSON_AddStringToObject(compatibilityItem, "networkId", basicInfo.networkId_.c_str());
    cJSON_AddStringToObject(compatibilityItem, "vendorId", basicInfo.vendorId_.c_str());
    cJSON_AddStringToObject(compatibilityItem, "deviceType", basicInfo.deviceType_.c_str());
    cJSON_AddStringToObject(compatibilityItem, "systemVersion", basicInfo.systemVersion_.c_str());
    cJSON_AddNumberToObject(compatibilityItem, "avsessionVersion",
        static_cast<long long>(basicInfo.sessionVersion_));
    cJSON* reserveArray = cJSON_CreateArray();
    for (int32_t val : basicInfo.reserve_) {
        cJSON* valItem = cJSON_CreateNumber(val);
        if (valItem == nullptr) {
            SLOGE("fail create number for reserve");
            cJSON_Delete(reserveArray);
            return AVSESSION_ERROR;
        }
        cJSON_AddItemToArray(reserveArray, valItem);
    }
    cJSON_AddItemToObject(compatibilityItem, "reserve", reserveArray);
    cJSON* featuresArray = cJSON_CreateArray();
    for (int32_t val : basicInfo.feature_) {
        cJSON* valItem = cJSON_CreateNumber(val);
        if (valItem == nullptr) {
            SLOGE("fail create number for features");
            cJSON_Delete(featuresArray);
            return AVSESSION_ERROR;
        }
        cJSON_AddItemToArray(featuresArray, valItem);
    }
    cJSON_AddItemToObject(compatibilityItem, "features", featuresArray);
    SetSessionCapabilitySet(compatibilityItem, basicInfo);
    cJSON* extendCapabilityArray = cJSON_CreateArray();
    for (int32_t val : basicInfo.extendCapability_) {
        cJSON* valItem = cJSON_CreateNumber(val);
        if (valItem == nullptr) {
            SLOGE("fail create number for extendCapability");
            cJSON_Delete(extendCapabilityArray);
            return AVSESSION_ERROR;
        }
        cJSON_AddItemToArray(extendCapabilityArray, valItem);
    }
    cJSON_AddItemToObject(compatibilityItem, "extendCapability", extendCapabilityArray);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionData(cJSON* jsonObj, const AVSessionBasicInfo& basicInfo)
{
    CHECK_AND_RETURN_RET_LOG(jsonObj != nullptr && !cJSON_IsInvalid(jsonObj), AVSESSION_ERROR, "json object is err");
    cJSON* dataItem = cJSON_GetObjectItem(jsonObj, "data");
    if (dataItem == nullptr || cJSON_IsInvalid(dataItem) || cJSON_IsNull(dataItem)) {
        dataItem = cJSON_CreateObject();
        cJSON_AddItemToObject(jsonObj, "data", dataItem);
    }
    cJSON_AddNumberToObject(dataItem, "systemTime", static_cast<long long>(basicInfo.systemTime_));
    cJSON* extendArray = cJSON_CreateArray();
    for (int32_t val : basicInfo.extend_) {
        cJSON* valItem = cJSON_CreateNumber(val);
        if (valItem == nullptr) {
            SLOGE("fail create number for extend");
            cJSON_Delete(extendArray);
            return AVSESSION_ERROR;
        }
        cJSON_AddItemToArray(extendArray, valItem);
    }
    cJSON_AddItemToObject(dataItem, "extend", extendArray);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionBasicInfo(std::string& sessionInfo, const AVSessionBasicInfo& basicInfo)
{
    cJSON* jsonObj = nullptr;
    if (sessionInfo.empty()) {
        jsonObj = cJSON_CreateObject();
    } else {
        jsonObj = cJSON_Parse(sessionInfo.c_str());
    }
    CHECK_AND_RETURN_RET_LOG(jsonObj != nullptr, AVSESSION_ERROR, "json object is null");
    if (cJSON_IsInvalid(jsonObj)) {
        SLOGE("parse json invalid");
        cJSON_Delete(jsonObj);
        return AVSESSION_ERROR;
    }

    if (SetSessionCompatibility(jsonObj, basicInfo) != AVSESSION_SUCCESS) {
        SLOGE("SetSessionCompatibility fail");
        cJSON_Delete(jsonObj);
        return AVSESSION_ERROR;
    }

    if (SetSessionData(jsonObj, basicInfo) != AVSESSION_SUCCESS) {
        SLOGE("SetSessionData fail");
        cJSON_Delete(jsonObj);
        return AVSESSION_ERROR;
    }

    if (cJSON_IsNull(jsonObj) || cJSON_IsInvalid(jsonObj)) {
        SLOGE("parse json aft set with invalid");
        cJSON_Delete(jsonObj);
        return AVSESSION_ERROR;
    }

    char* jsonStr = cJSON_Print(jsonObj);
    if (jsonStr != nullptr) {
        sessionInfo = jsonStr;
        cJSON_free(jsonStr);
    } else {
        SLOGE("get jsonStr nullptr");
        cJSON_Delete(jsonObj);
        return AVSESSION_ERROR;
    }
    cJSON_Delete(jsonObj);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionCapabilitySet(cJSON* jsonObj, AVSessionBasicInfo& basicInfo)
{
    CHECK_AND_RETURN_RET_LOG(jsonObj != nullptr && !cJSON_IsInvalid(jsonObj), AVSESSION_ERROR, "json object is err");

    cJSON* metaDataItem = cJSON_GetObjectItem(jsonObj, "metaData");
    CHECK_AND_RETURN_RET_LOG(metaDataItem == nullptr || cJSON_IsInvalid(metaDataItem) ||
        !cJSON_IsArray(metaDataItem), AVSESSION_ERROR, "get metaDataItem err");
    int32_t ret = JsonToVector(metaDataItem, basicInfo.metaDataCap_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get metaDataCap error");

    cJSON* playbackStateItem = cJSON_GetObjectItem(jsonObj, "playbackState");
    CHECK_AND_RETURN_RET_LOG(playbackStateItem == nullptr || cJSON_IsInvalid(playbackStateItem) ||
        !cJSON_IsArray(playbackStateItem), AVSESSION_ERROR, "get playbackStateItem err");
    ret = JsonToVector(playbackStateItem, basicInfo.playBackStateCap_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get playBackStateCap error");

    cJSON* controlCommandItem = cJSON_GetObjectItem(jsonObj, "controlCommand");
    CHECK_AND_RETURN_RET_LOG(controlCommandItem == nullptr || cJSON_IsInvalid(controlCommandItem) ||
        !cJSON_IsArray(controlCommandItem), AVSESSION_ERROR, "get controlCommandItem err");
    ret = JsonToVector(controlCommandItem, basicInfo.controlCommandCap_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get controlCommandCap error");

    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionCompatibility(cJSON* jsonObj, AVSessionBasicInfo& basicInfo)
{
    CHECK_AND_RETURN_RET_LOG(jsonObj != nullptr && !cJSON_IsInvalid(jsonObj), AVSESSION_ERROR, "json object is err");

    cJSON* networkIdItem = cJSON_GetObjectItem(jsonObj, "networkId");
    CHECK_AND_RETURN_RET_LOG(networkIdItem == nullptr || cJSON_IsInvalid(networkIdItem) ||
        !cJSON_IsString(networkIdItem), AVSESSION_ERROR, "get networkIdItem err");
    basicInfo.networkId_ = std::string(networkIdItem->valuestring);
    cJSON* vendorIdItem = cJSON_GetObjectItem(jsonObj, "vendorId");
    CHECK_AND_RETURN_RET_LOG(vendorIdItem == nullptr || cJSON_IsInvalid(vendorIdItem) ||
        !cJSON_IsString(vendorIdItem), AVSESSION_ERROR, "get vendorIdItem err");
    basicInfo.vendorId_ = std::string(vendorIdItem->valuestring);
    cJSON* deviceTypeItem = cJSON_GetObjectItem(jsonObj, "deviceType");
    CHECK_AND_RETURN_RET_LOG(deviceTypeItem == nullptr || cJSON_IsInvalid(deviceTypeItem) ||
        !cJSON_IsString(deviceTypeItem), AVSESSION_ERROR, "get deviceTypeItem err");
    basicInfo.deviceType_ = std::string(deviceTypeItem->valuestring);
    cJSON* systemVersionItem = cJSON_GetObjectItem(jsonObj, "systemVersion");
    CHECK_AND_RETURN_RET_LOG(systemVersionItem == nullptr || cJSON_IsInvalid(systemVersionItem) ||
        !cJSON_IsString(systemVersionItem), AVSESSION_ERROR, "get systemVersionItem err");
    basicInfo.systemVersion_ = std::string(systemVersionItem->valuestring);
    cJSON* sessionVersionItem = cJSON_GetObjectItem(jsonObj, "avsessionVersion");
    CHECK_AND_RETURN_RET_LOG(sessionVersionItem == nullptr || cJSON_IsInvalid(sessionVersionItem) ||
        !cJSON_IsNumber(sessionVersionItem), AVSESSION_ERROR, "get sessionVersionItem err");
    basicInfo.sessionVersion_ = sessionVersionItem->valueint;

    cJSON* reserveItem = cJSON_GetObjectItem(jsonObj, "reserve");
    CHECK_AND_RETURN_RET_LOG(reserveItem == nullptr || cJSON_IsInvalid(reserveItem) ||
        !cJSON_IsArray(reserveItem), AVSESSION_ERROR, "get reserveItem err");
    int32_t ret = JsonToVector(reserveItem, basicInfo.reserve_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get reserve error");
    cJSON* featuresItem = cJSON_GetObjectItem(jsonObj, "features");
    CHECK_AND_RETURN_RET_LOG(featuresItem == nullptr || cJSON_IsInvalid(featuresItem) ||
        !cJSON_IsArray(featuresItem), AVSESSION_ERROR, "get featuresItem err");
    ret = JsonToVector(featuresItem, basicInfo.feature_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get features error");

    cJSON* capabilitySetItem = cJSON_GetObjectItem(jsonObj, "capabilitySet");
    CHECK_AND_RETURN_RET_LOG(capabilitySetItem == nullptr || cJSON_IsInvalid(capabilitySetItem),
        AVSESSION_ERROR, "get capabilitySetItem err");
    if (GetSessionCapabilitySet(capabilitySetItem, basicInfo) != AVSESSION_SUCCESS) {
        SLOGE("GetSessionCapabilitySet fail");
        return AVSESSION_ERROR;
    }

    cJSON* extendCapabilityItem = cJSON_GetObjectItem(jsonObj, "extendCapability");
    CHECK_AND_RETURN_RET_LOG(extendCapabilityItem == nullptr || cJSON_IsInvalid(extendCapabilityItem) ||
        !cJSON_IsArray(extendCapabilityItem), AVSESSION_ERROR, "get extendCapabilityItem err");
    ret = JsonToVector(extendCapabilityItem, basicInfo.extendCapability_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get extendCapability error");

    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionData(cJSON* jsonObj, AVSessionBasicInfo& basicInfo)
{
    CHECK_AND_RETURN_RET_LOG(jsonObj != nullptr && !cJSON_IsInvalid(jsonObj), AVSESSION_ERROR, "json object is err");

    cJSON* systemTimeItem = cJSON_GetObjectItem(jsonObj, "systemTime");
    CHECK_AND_RETURN_RET_LOG(systemTimeItem == nullptr || cJSON_IsInvalid(systemTimeItem) ||
        !cJSON_IsNumber(systemTimeItem), AVSESSION_ERROR, "get systemTimeItem err");
    basicInfo.systemTime_ = systemTimeItem->valueint;

    cJSON* extendItem = cJSON_GetObjectItem(jsonObj, "extend");
    CHECK_AND_RETURN_RET_LOG(extendItem == nullptr || cJSON_IsInvalid(extendItem) ||
        !cJSON_IsArray(extendItem), AVSESSION_ERROR, "get extendItem err");
    int32_t ret = JsonToVector(extendItem, basicInfo.extend_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get extend error");

    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionBasicInfo(const std::string& sessionInfo, AVSessionBasicInfo& basicInfo)
{
    CHECK_AND_RETURN_RET_LOG(!sessionInfo.empty(), AVSESSION_ERROR, "sessionInfo is empty");
    cJSON* sessionInfoItem = cJSON_Parse(sessionInfo.c_str());
    CHECK_AND_RETURN_RET_LOG(sessionInfoItem != nullptr, AVSESSION_ERROR, "sessionInfoItem is null");
    if (cJSON_IsInvalid(sessionInfoItem) || cJSON_IsNull(sessionInfoItem)) {
        SLOGE("get sessionInfoItem invalid");
        cJSON_free(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    if (!cJSON_HasObjectItem(sessionInfoItem, "compatibility") || !cJSON_HasObjectItem(sessionInfoItem, "data")) {
        SLOGE("The key of jsonObj is invalid");
        cJSON_free(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    cJSON* compatibilityItem = cJSON_GetObjectItem(sessionInfoItem, "compatibility");
    if (GetSessionCompatibility(compatibilityItem, basicInfo) != AVSESSION_SUCCESS) {
        SLOGE("GetSessionCompatibility fail");
        cJSON_free(sessionInfoItem);
        return AVSESSION_ERROR;
    }

    cJSON* dataItem = cJSON_GetObjectItem(sessionInfoItem, "data");
    if (GetSessionData(dataItem, basicInfo) != AVSESSION_SUCCESS) {
        SLOGE("GetSessionData fail");
        cJSON_free(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionDescriptorByCJSON(cJSON* sessionDescriptorItem,
    const AVSessionDescriptor& descriptor)
{
    if (sessionDescriptorItem == nullptr || cJSON_IsInvalid(sessionDescriptorItem) ||
        cJSON_IsNull(sessionDescriptorItem)) {
        SLOGE("get sessionDescriptorItem invalid");
        return AVSESSION_ERROR;
    }
    cJSON_AddStringToObject(sessionDescriptorItem, "sessionId", descriptor.sessionId_.c_str());
    cJSON_AddStringToObject(sessionDescriptorItem, "type", ConvertSessionType(descriptor.sessionType_).c_str());
    cJSON_AddStringToObject(sessionDescriptorItem, "bundleName", descriptor.elementName_.GetBundleName().c_str());
    cJSON_AddStringToObject(sessionDescriptorItem, "abilityName", descriptor.elementName_.GetAbilityName().c_str());
    cJSON_AddStringToObject(sessionDescriptorItem, "tag", descriptor.sessionTag_.c_str());
    cJSON_AddBoolToObject(sessionDescriptorItem, "isThirdPartyApp", descriptor.isThirdPartyApp_);
    if (cJSON_IsInvalid(sessionDescriptorItem)) {
        SLOGE("get sessionDescriptorItem aft add descriptor invalid");
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionDescriptors(std::string& sessionInfo, const std::vector<AVSessionDescriptor>& descriptors)
{
    cJSON* sessionInfoItem = nullptr;
    if (sessionInfo.empty()) {
        sessionInfoItem = cJSON_CreateObject();
    } else {
        sessionInfoItem = cJSON_Parse(sessionInfo.c_str());
    }
    CHECK_AND_RETURN_RET_LOG(sessionInfoItem != nullptr, AVSESSION_ERROR, "json object is null");
    if (cJSON_IsInvalid(sessionInfoItem)) {
        SLOGE("parse json invalid");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    cJSON* dataItem = cJSON_GetObjectItem(sessionInfoItem, "data");
    if (dataItem == nullptr || cJSON_IsInvalid(dataItem) || cJSON_IsNull(dataItem)) {
        dataItem = cJSON_CreateObject();
        cJSON_AddItemToObject(sessionInfoItem, "data", dataItem);
    }
    cJSON* descriptorsArray = cJSON_GetObjectItem(dataItem, "sessionDescriptors");
    if (descriptorsArray == nullptr || cJSON_IsInvalid(descriptorsArray) || !cJSON_IsArray(descriptorsArray)) {
        descriptorsArray = cJSON_CreateArray();
        cJSON_AddItemToObject(dataItem, "sessionDescriptors", descriptorsArray);
    }
    for (uint32_t i = 0; i < descriptors.size(); i++) {
        cJSON* sessionDescriptorItem = cJSON_CreateObject();
        CHECK_AND_CONTINUE(sessionDescriptorItem != nullptr);
        if (cJSON_IsInvalid(sessionDescriptorItem) ||
            SetSessionDescriptorByCJSON(sessionDescriptorItem, descriptors[i]) != AVSESSION_SUCCESS) {
            SLOGE("get sessionDescriptorItem and set descriptor fail");
            cJSON_Delete(sessionDescriptorItem);
            continue;
        }
        cJSON_InsertItemInArray(descriptorsArray, i, sessionDescriptorItem);
    }
    char* g_sessionInfoStr = cJSON_Print(sessionInfoItem);
    if (g_sessionInfoStr != nullptr) {
        sessionInfo = g_sessionInfoStr;
        cJSON_free(g_sessionInfoStr);
    }
    cJSON_Delete(sessionInfoItem);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionDescriptorByCJSON(cJSON* sessionDescriptorItem,
    AVSessionDescriptor& descriptor)
{
    CHECK_AND_RETURN_RET_LOG(sessionDescriptorItem != nullptr, AVSESSION_ERROR, "json object is null");
    CHECK_AND_RETURN_RET_LOG(!cJSON_IsInvalid(sessionDescriptorItem), AVSESSION_ERROR, "json object is invalid");

    CHECK_AND_RETURN_RET_LOG(IsString(sessionDescriptorItem, "sessionId") && IsString(sessionDescriptorItem, "type")
        && IsString(sessionDescriptorItem, "bundleName") && IsString(sessionDescriptorItem, "abilityName")
        && IsString(sessionDescriptorItem, "tag") && IsBool(sessionDescriptorItem, "isThirdPartyApp"), AVSESSION_ERROR,
        "The key of cjson is invalid");

    cJSON* sessionIdItem = cJSON_GetObjectItem(sessionDescriptorItem, "sessionId");
    CHECK_AND_RETURN_RET_LOG(sessionIdItem != nullptr && !cJSON_IsInvalid(sessionIdItem) &&
        cJSON_IsString(sessionIdItem), AVSESSION_ERROR, "sessionIdItem is invalid");
    descriptor.sessionId_.assign(sessionIdItem->valuestring);

    cJSON* sessionTypeItem = cJSON_GetObjectItem(sessionDescriptorItem, "type");
    CHECK_AND_RETURN_RET_LOG(sessionTypeItem != nullptr && !cJSON_IsInvalid(sessionTypeItem) &&
        cJSON_IsString(sessionTypeItem), AVSESSION_ERROR, "sessionTypeItem is invalid");
    descriptor.sessionType_ = ConvertSessionType(std::string(sessionTypeItem->valuestring));

    cJSON* bundleNameItem = cJSON_GetObjectItem(sessionDescriptorItem, "bundleName");
    CHECK_AND_RETURN_RET_LOG(bundleNameItem != nullptr && !cJSON_IsInvalid(bundleNameItem) &&
        cJSON_IsString(bundleNameItem), AVSESSION_ERROR, "bundleNameItem is invalid");
    descriptor.elementName_.SetBundleName(std::string(bundleNameItem->valuestring));

    cJSON* abilityNameItem = cJSON_GetObjectItem(sessionDescriptorItem, "abilityName");
    CHECK_AND_RETURN_RET_LOG(abilityNameItem != nullptr && !cJSON_IsInvalid(abilityNameItem) &&
        cJSON_IsString(abilityNameItem), AVSESSION_ERROR, "abilityNameItem is invalid");
    descriptor.elementName_.SetAbilityName(std::string(abilityNameItem->valuestring));

    cJSON* sessionTagItem = cJSON_GetObjectItem(sessionDescriptorItem, "tag");
    CHECK_AND_RETURN_RET_LOG(sessionTagItem != nullptr && !cJSON_IsInvalid(sessionTagItem) &&
        cJSON_IsString(sessionTagItem), AVSESSION_ERROR, "sessionTagItem is invalid");
    descriptor.sessionTag_.assign(sessionTagItem->valuestring);

    cJSON* isThirdPartyAppItem = cJSON_GetObjectItem(sessionDescriptorItem, "isThirdPartyApp");
    CHECK_AND_RETURN_RET_LOG(isThirdPartyAppItem != nullptr && !cJSON_IsInvalid(isThirdPartyAppItem) &&
        cJSON_IsBool(isThirdPartyAppItem), AVSESSION_ERROR, "isThirdPartyAppItem is invalid");
    descriptor.isThirdPartyApp_ = cJSON_IsTrue(isThirdPartyAppItem);

    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionDescriptors(const std::string& sessionInfo, std::vector<AVSessionDescriptor>& descriptors)
{
    CHECK_AND_RETURN_RET_LOG(!sessionInfo.empty(), AVSESSION_ERROR, "sessionInfo is empty");
    cJSON* sessionInfoItem = cJSON_Parse(sessionInfo.c_str());
    CHECK_AND_RETURN_RET_LOG(sessionInfoItem != nullptr, AVSESSION_ERROR, "json object is null");
    if (cJSON_IsInvalid(sessionInfoItem)) {
        SLOGE("parse json invalid");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    if (!cJSON_HasObjectItem(sessionInfoItem, "data")) {
        SLOGE("json object data is null");
        cJSON_free(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    cJSON* dataItem = cJSON_GetObjectItem(sessionInfoItem, "data");
    CHECK_AND_RETURN_RET_LOG(dataItem != nullptr, AVSESSION_ERROR, "json dataItem is null");
    if (cJSON_IsInvalid(dataItem)) {
        SLOGE("get dataItem invalid");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    if (!cJSON_HasObjectItem(dataItem, "sessionDescriptors")) {
        SLOGE("json object sessionDescriptors is null");
        cJSON_free(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    cJSON* descriptorsArray = cJSON_GetObjectItem(dataItem, "sessionDescriptors");
    CHECK_AND_RETURN_RET_LOG(descriptorsArray != nullptr, AVSESSION_ERROR, "json descriptorsArray is null");
    if (cJSON_IsInvalid(descriptorsArray) || !cJSON_IsArray(descriptorsArray)) {
        SLOGE("get descriptorsArray invalid");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }

    cJSON* sessionDescriptorItem = nullptr;
    cJSON_ArrayForEach(sessionDescriptorItem, descriptorsArray) {
        AVSessionDescriptor descriptor;
        if (GetSessionDescriptorByCJSON(sessionDescriptorItem, descriptor) != AVSESSION_SUCCESS) {
            SLOGE("GetSessionDescriptorByCJSON fail");
            cJSON_Delete(sessionInfoItem);
            return AVSESSION_ERROR;
        }
        descriptors.push_back(descriptor);
    }

    cJSON_Delete(sessionInfoItem);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionDescriptor(std::string& sessionInfo, const AVSessionDescriptor& descriptor)
{
    cJSON* sessionInfoItem = nullptr;
    if (sessionInfo.empty()) {
        sessionInfoItem = cJSON_CreateObject();
    } else {
        sessionInfoItem = cJSON_Parse(sessionInfo.c_str());
    }
    CHECK_AND_RETURN_RET_LOG(sessionInfoItem != nullptr, AVSESSION_ERROR, "json object is null");
    if (cJSON_IsInvalid(sessionInfoItem)) {
        SLOGE("parse json invalid");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    cJSON* dataItem = cJSON_GetObjectItem(sessionInfoItem, "data");
    if (dataItem == nullptr || cJSON_IsInvalid(dataItem) || cJSON_IsNull(dataItem)) {
        dataItem = cJSON_CreateObject();
        cJSON_AddItemToObject(sessionInfoItem, "data", dataItem);
    }
    cJSON* descriptorItem = cJSON_GetObjectItem(dataItem, "sessionDescriptor");
    if (descriptorItem == nullptr || cJSON_IsInvalid(descriptorItem) || cJSON_IsNull(descriptorItem)) {
        descriptorItem = cJSON_CreateObject();
        cJSON_AddItemToObject(dataItem, "sessionDescriptor", descriptorItem);
    }
    if (SetSessionDescriptorByCJSON(descriptorItem, descriptor) != AVSESSION_SUCCESS) {
        SLOGE("get descriptorItem and set descriptor fail");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    char* sessionInfoStr = cJSON_Print(sessionInfoItem);
    if (sessionInfoStr != nullptr) {
        sessionInfo = sessionInfoStr;
        cJSON_free(sessionInfoStr);
    } else {
        SLOGE("get sessionInfoStr with nullptr");
    }

    cJSON_Delete(sessionInfoItem);
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionDescriptor(const std::string& sessionInfo, AVSessionDescriptor& descriptor)
{
    CHECK_AND_RETURN_RET_LOG(!sessionInfo.empty(), AVSESSION_ERROR, "sessionInfo is empty");
    cJSON* sessionInfoItem = cJSON_Parse(sessionInfo.c_str());
    CHECK_AND_RETURN_RET_LOG(sessionInfoItem != nullptr, AVSESSION_ERROR, "json object is null");
    if (cJSON_IsInvalid(sessionInfoItem)) {
        SLOGE("parse json invalid");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    if (!cJSON_HasObjectItem(sessionInfoItem, "data")) {
        SLOGE("json object data is null");
        cJSON_free(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    cJSON* dataItem = cJSON_GetObjectItem(sessionInfoItem, "data");
    CHECK_AND_RETURN_RET_LOG(dataItem != nullptr, AVSESSION_ERROR, "json dataItem is null");
    if (cJSON_IsInvalid(dataItem)) {
        SLOGE("get dataItem invalid");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    if (!cJSON_HasObjectItem(dataItem, "sessionDescriptor")) {
        SLOGE("json object sessionDescriptor is null");
        cJSON_free(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    cJSON* descriptorItem = cJSON_GetObjectItem(dataItem, "sessionDescriptor");
    CHECK_AND_RETURN_RET_LOG(descriptorItem != nullptr, AVSESSION_ERROR, "json descriptorItem is null");
    if (cJSON_IsInvalid(descriptorItem)) {
        SLOGE("get descriptorItem invalid");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }
    if (GetSessionDescriptorByCJSON(descriptorItem, descriptor) != AVSESSION_SUCCESS) {
        SLOGE("GetSessionDescriptorByCJSON fail");
        cJSON_Delete(sessionInfoItem);
        return AVSESSION_ERROR;
    }

    cJSON_Delete(sessionInfoItem);
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
