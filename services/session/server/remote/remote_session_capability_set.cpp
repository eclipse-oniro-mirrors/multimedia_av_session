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

#include "remote_session_capability_set.h"
#include "avcontrol_command.h"
#include "avmeta_data.h"
#include "avplayback_state.h"

namespace OHOS::AVSession {
RemoteSessionCapabilitySet& RemoteSessionCapabilitySet::GetInstance()
{
    static RemoteSessionCapabilitySet sessionCapabilitySet;
    return sessionCapabilitySet;
}

std::string RemoteSessionCapabilitySet::GetLocalCapability()
{
    std::vector<std::vector<int32_t>> localCapability(SESSION_DATA_CATEGORY_MAX);
    localCapability[SESSION_DATA_META] = AVMetaData::localCapability;
    localCapability[SESSION_DATA_PLAYBACK_STATE] = AVPlaybackState::localCapability;
    localCapability[SESSION_DATA_CONTROL_COMMAND] = AVControlCommand::localCapability;
    std::string jsonSinkCap;
    int32_t ret = JsonUtils::GetJsonCapability(localCapability, jsonSinkCap);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, "", "AddRemoteCapability error");
    return jsonSinkCap;
}

void RemoteSessionCapabilitySet::AddRemoteCapability(const std::string& sessionId, const std::string& sinkDeviceId,
                                                     const std::string& sinkCapability)
{
    std::string key = sessionId + "-" + sinkDeviceId;
    std::vector<std::vector<int32_t>> value(SESSION_DATA_CATEGORY_MAX);
    int32_t ret = JsonUtils::GetVectorCapability(sinkCapability, value);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "AddRemoteCapability error");
    capabilitys_[key] = value;
}

void RemoteSessionCapabilitySet::RemoveRemoteCapability(const std::string& sessionId, const std::string& sinkDevice)
{
    CHECK_AND_RETURN_LOG(capabilitys_.size() > 0, " Don't have Capability");
    std::string key = sessionId + "-" + sinkDevice;
    capabilitys_.erase(key);
}

bool RemoteSessionCapabilitySet::HasCapability(const std::string& sessionId, const std::string& sinkDevice,
                                               SessionDataCategory category, int32_t key)
{
    CHECK_AND_RETURN_RET_LOG(capabilitys_.size() > 0, false, "Don't have Capability");
    std::string strKey = sessionId + "-" + sinkDevice;
    auto iter = capabilitys_.find(strKey);
    CHECK_AND_RETURN_RET_LOG(iter != capabilitys_.end(), false, "Don't have the key");
    std::vector<std::vector<int32_t>> capability = iter->second;
    CHECK_AND_RETURN_RET_LOG(capability[category].size() > 0, false, "Don't have Capability");
    for (const auto &item : capability[category]) {
        if (item == key) {
            return true;
        }
    }
    return false;
}
} // namespace OHOS::AVSession