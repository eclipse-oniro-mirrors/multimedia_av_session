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
    int32_t type =  AVSession::SESSION_TYPE_INVALID;
    if (typeString == "audio") {
        type = AVSession::SESSION_TYPE_AUDIO;
    } else if (typeString == "video") {
        type = AVSession::SESSION_TYPE_VIDEO;
    }
    return type;
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

int32_t JsonUtils::JsonToVector(json object, std::vector<int32_t>& out)
{
    CHECK_AND_RETURN_RET_LOG(!object.is_null(), AVSESSION_ERROR, "json object is null");
    CHECK_AND_RETURN_RET_LOG(object.is_array(), AVSESSION_ERROR, "json object is not array");
    for (json::iterator it = object.begin(); it != object.end(); ++it) {
        out.push_back(it.value());
    }
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetJsonCapability(const std::vector<std::vector<int32_t>>& capability, std::string& jsonCapability)
{
    json jsonObject;
    for (uint32_t i = 0; i < capability.size(); i++) {
        if (i == SESSION_DATA_META) {
            jsonObject["metaData"] = capability[i];
            continue;
        }
        if (i == SESSION_DATA_PLAYBACK_STATE) {
            jsonObject["playbackState"] = capability[i];
            continue;
        }
        if (i == SESSION_DATA_CONTROL_COMMAND) {
            jsonObject["controlCommand"] = capability[i];
            continue;
        }
    }
    jsonCapability = jsonObject.dump();
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetVectorCapability(const std::string& jsonCapability,
                                       std::vector<std::vector<int32_t>>& vectorCapability)
{
    CHECK_AND_RETURN_RET_LOG(!jsonCapability.empty(), AVSESSION_ERROR, "jsonCapability is empty");
    json jsonObj = json::parse(jsonCapability);
    CHECK_AND_RETURN_RET_LOG(!jsonObj.is_discarded() && !jsonObj.is_null(), AVSESSION_ERROR, "json object is null");
    int32_t ret = JsonToVector(jsonObj["metaData"], vectorCapability[SESSION_DATA_META]);
    CHECK_AND_CONTINUE_LOG(ret == AVSESSION_SUCCESS, "Get metaDataCapability error");
    ret = JsonToVector(jsonObj["playbackState"], vectorCapability[SESSION_DATA_PLAYBACK_STATE]);
    CHECK_AND_CONTINUE_LOG(ret == AVSESSION_SUCCESS, "Get playbackStateCapability error");
    ret = JsonToVector(jsonObj["controlCommand"], vectorCapability[SESSION_DATA_CONTROL_COMMAND]);
    CHECK_AND_CONTINUE_LOG(ret == AVSESSION_SUCCESS, "Get controlCommandCapability error");
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetAllCapability(const std::string& sessionInfo, std::string& jsonCapability)
{
    CHECK_AND_RETURN_RET_LOG(!sessionInfo.empty(), AVSESSION_ERROR, "sessionInfo is empty");
    json jsonSessionInfo = json::parse(sessionInfo);
    CHECK_AND_RETURN_RET_LOG(!jsonSessionInfo.is_discarded() && !jsonSessionInfo.is_null(), AVSESSION_ERROR,
        "json object is null");
    json compatibility = jsonSessionInfo["compatibility"];
    CHECK_AND_RETURN_RET_LOG(!compatibility.is_null(), AVSESSION_ERROR, "Getcompatibility error");
    json capabilitySet = compatibility["capabilitySet"];
    CHECK_AND_RETURN_RET_LOG(!capabilitySet.is_null(), AVSESSION_ERROR, "GetCapabilitySet error");
    jsonCapability = capabilitySet.dump();
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionBasicInfo(std::string& sessionInfo, const AVSessionBasicInfo& basicInfo)
{
    json jsonObj = sessionInfo.empty() ? json::parse(R"({})") : json::parse(sessionInfo);
    jsonObj["compatibility"]["networkId"] = basicInfo.networkId_;
    jsonObj["compatibility"]["vendorId"] = basicInfo.vendorId_;
    jsonObj["compatibility"]["deviceType"] = basicInfo.deviceType_;
    jsonObj["compatibility"]["systemVersion"] = basicInfo.systemVersion_;
    jsonObj["compatibility"]["avsessionVersion"] = basicInfo.sessionVersion_;
    jsonObj["compatibility"]["reserve"] = basicInfo.reserve_;
    jsonObj["compatibility"]["features"] = basicInfo.feature_;
    jsonObj["compatibility"]["capabilitySet"]["metaData"] = basicInfo.metaDataCap_;
    jsonObj["compatibility"]["capabilitySet"]["playbackState"] = basicInfo.playBackStateCap_;
    jsonObj["compatibility"]["capabilitySet"]["controlCommand"] = basicInfo.controlCommandCap_;
    jsonObj["compatibility"]["extendCapability"] = basicInfo.extendCapability_;
    jsonObj["data"]["systemTime"] = basicInfo.systemTime_;
    jsonObj["data"]["extend"] = basicInfo.extend_;
    CHECK_AND_RETURN_RET_LOG(!jsonObj.empty(), AVSESSION_ERROR, "SetBasicInfo error");
    sessionInfo = jsonObj.dump();
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionBasicInfo(const std::string& sessionInfo, AVSessionBasicInfo& basicInfo)
{
    CHECK_AND_RETURN_RET_LOG(!sessionInfo.empty(), AVSESSION_ERROR, "sessionInfo is empty");
    json jsonObj = json::parse(sessionInfo);
    CHECK_AND_RETURN_RET_LOG(!jsonObj.is_discarded() && !jsonObj.is_null(), AVSESSION_ERROR, "json object is null");
    json compatibility = jsonObj["compatibility"];
    CHECK_AND_RETURN_RET_LOG(!compatibility.empty(), AVSESSION_ERROR, "Getcompatibility error");
    basicInfo.networkId_ = compatibility["networkId"];
    basicInfo.vendorId_ = compatibility["vendorId"];
    basicInfo.deviceType_ = compatibility["deviceType"];
    basicInfo.systemVersion_ = compatibility["systemVersion"];
    basicInfo.sessionVersion_ = compatibility["avsessionVersion"];
    int32_t ret = JsonToVector(compatibility["reserve"], basicInfo.reserve_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get reserve error");
    ret = JsonToVector(compatibility["features"], basicInfo.feature_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get feature error");
    json capabilitySet = compatibility["capabilitySet"];
    CHECK_AND_RETURN_RET_LOG(!capabilitySet.empty(), AVSESSION_ERROR, "GetCapabilitySet error");
    ret = JsonToVector(capabilitySet["metaData"], basicInfo.metaDataCap_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get metaData error");
    ret = JsonToVector(capabilitySet["playbackState"], basicInfo.playBackStateCap_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get playbackState error");
    ret = JsonToVector(capabilitySet["controlCommand"], basicInfo.controlCommandCap_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get controlCommand error");
    ret = JsonToVector(compatibility["extendCapability"], basicInfo.extendCapability_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get extendCapability error");
    basicInfo.systemTime_ = jsonObj["data"]["systemTime"];
    ret = JsonToVector(jsonObj["data"]["extend"], basicInfo.extend_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "Get data extend error");
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionDescriptors(std::string& sessionInfo, const std::vector<AVSessionDescriptor>& descriptors)
{
    json jsonObj = sessionInfo.empty() ? json::parse(R"({})") : json::parse(sessionInfo);
    for (uint32_t i = 0; i < descriptors.size(); i++) {
        jsonObj["data"]["sessionDescriptors"][i]["sessionId"] = descriptors[i].sessionId_;
        jsonObj["data"]["sessionDescriptors"][i]["type"] = ConvertSessionType(descriptors[i].sessionType_);
        jsonObj["data"]["sessionDescriptors"][i]["bundleName"] = descriptors[i].elementName_.GetBundleName();
        jsonObj["data"]["sessionDescriptors"][i]["abilityName"] = descriptors[i].elementName_.GetAbilityName();
        jsonObj["data"]["sessionDescriptors"][i]["tag"] = descriptors[i].sessionTag_;
        jsonObj["data"]["sessionDescriptors"][i]["isThirdPartyApp"] = descriptors[i].isThirdPartyApp_;
    }
    sessionInfo = jsonObj.dump();
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionDescriptors(const std::string& sessionInfo, std::vector<AVSessionDescriptor>& descriptors)
{
    CHECK_AND_RETURN_RET_LOG(!sessionInfo.empty(), AVSESSION_ERROR, "sessionInfo is empty");
    json jsonObj = json::parse(sessionInfo);
    CHECK_AND_RETURN_RET_LOG(!jsonObj.is_discarded() && !jsonObj.is_null(), AVSESSION_ERROR, "json object is null");
    CHECK_AND_RETURN_RET_LOG(jsonObj.contains("data"), AVSESSION_ERROR, "json object data is null");
    json sessionDescriptors = jsonObj["data"]["sessionDescriptors"];
    CHECK_AND_RETURN_RET_LOG(!sessionDescriptors.is_null(), AVSESSION_ERROR, "sessionDescriptors is null");
    CHECK_AND_RETURN_RET_LOG(sessionDescriptors.is_array(), AVSESSION_ERROR, "json sessionDescriptors is not array");
    for (json::iterator it = sessionDescriptors.begin(); it != sessionDescriptors.end(); ++it) {
        AVSessionDescriptor descriptor;
        descriptor.sessionId_ = it.value()["sessionId"];
        std::string type = it.value()["type"];
        descriptor.sessionType_ = ConvertSessionType(type);
        descriptor.elementName_.SetBundleName(it.value()["bundleName"]);
        descriptor.elementName_.SetAbilityName(it.value()["abilityName"]);
        descriptor.sessionTag_ = it.value()["tag"];
        descriptor.isThirdPartyApp_ = it.value()["isThirdPartyApp"];
        descriptors.push_back(descriptor);
    }
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::SetSessionDescriptor(std::string& sessionInfo, const AVSessionDescriptor& descriptor)
{
    json jsonObj = sessionInfo.empty() ? json::parse(R"({})") : json::parse(sessionInfo);
    json jsonObj = json::parse(sessionInfo);
    jsonObj["data"]["sessionDescriptor"]["sessionId"] = descriptor.sessionId_;
    jsonObj["data"]["sessionDescriptor"]["type"] = ConvertSessionType(descriptor.sessionType_);
    jsonObj["data"]["sessionDescriptor"]["bundleName"] = descriptor.elementName_.GetBundleName();
    jsonObj["data"]["sessionDescriptor"]["abilityName"] = descriptor.elementName_.GetAbilityName();
    jsonObj["data"]["sessionDescriptor"]["tag"] = descriptor.sessionTag_;
    jsonObj["data"]["sessionDescriptor"]["isThirdPartyApp"] = descriptor.isThirdPartyApp_;
    sessionInfo = jsonObj.dump();
    return AVSESSION_SUCCESS;
}

int32_t JsonUtils::GetSessionDescriptor(const std::string& sessionInfo, AVSessionDescriptor& descriptor)
{
    CHECK_AND_RETURN_RET_LOG(!sessionInfo.empty(), AVSESSION_ERROR, "sessionInfo is empty");
    json jsonObj = json::parse(sessionInfo);
    CHECK_AND_RETURN_RET_LOG(!jsonObj.is_discarded() && !jsonObj.is_null(), AVSESSION_ERROR, "json object is null");
    CHECK_AND_RETURN_RET_LOG(jsonObj.contains("data"), AVSESSION_ERROR, "json object data is null");
    json sessionDescriptor = jsonObj["data"]["sessionDescriptor"];
    CHECK_AND_RETURN_RET_LOG(!sessionDescriptor.is_null(), AVSESSION_ERROR, "sessionDescriptor is null");

    descriptor.sessionId_ = sessionDescriptor["sessionId"];
    std::string type = sessionDescriptor["type"];
    descriptor.sessionType_ = ConvertSessionType(type);
    descriptor.elementName_.SetBundleName(sessionDescriptor["bundleName"]);
    descriptor.elementName_.SetAbilityName(sessionDescriptor["abilityName"]);
    descriptor.sessionTag_ = sessionDescriptor["tag"];
    descriptor.isThirdPartyApp_ = sessionDescriptor["isThirdPartyApp"];
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession