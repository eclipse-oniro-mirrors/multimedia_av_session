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

#ifndef OHOS_REMOTE_SESSION_CAPABILITY_SET_H
#define OHOS_REMOTE_SESSION_CAPABILITY_SET_H

#include "avsession_info.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "json_utils.h"

namespace OHOS::AVSession {
class RemoteSessionCapabilitySet {
public:
    static RemoteSessionCapabilitySet& GetInstance();

    static std::string GetLocalCapability();

    void AddRemoteCapability(const std::string& sessionId, const std::string& sinkDeviceId,
                             const std::string& sinkCapability);

    void RemoveRemoteCapability(const std::string& sessionId, const std::string& sinkDevice);

    bool HasCapability(const std::string& sessionId, const std::string& sinkDevice, SessionDataCategory category,
                       int32_t key);

private:
    std::map<std::string, std::vector<std::vector<int32_t>>> capabilitys_ {};
};
} // namespace OHOS::AVSession
#endif // OHOS_REMOTE_SESSION_CAPABILITY_SET_H