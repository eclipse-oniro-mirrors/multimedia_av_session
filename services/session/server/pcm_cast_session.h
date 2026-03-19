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

#ifndef OHOS_PCM_CAST_SESSION_H
#define OHOS_PCM_CAST_SESSION_H

#include "avsession_info.h"
#include "cJSON.h"
#include "avsession_users_manager.h"

namespace OHOS::AVSession {
class PcmCastSession : public IAVRouterListener, public std::enable_shared_from_this<PcmCastSession> {
public:
    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove) override;

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg) override;

    int32_t StartCast(const OutputDeviceInfo& outputDeviceInfo,
        std::pair<std::string, std::string>& serviceNameStatePair, const SessionToken& sessionToken);

    void StopCast();

    void ExecuteCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs);

    void DestroyTask();

    int32_t GetCastMode() const;
    pid_t GetUid() const;
    int32_t GetCastState() const;
    AVSessionDescriptor GetDescriptor();

    void OnSystemCommonEvent(const std::string& args);

    void BypassCommandParams(const AAFwk::WantParams& commandArgs);

    void QueryCommandParams(const AAFwk::WantParams& commandArgs);

private:
    int64_t castHandle_ = 0;
    int32_t castMode_ = HiPlayCastMode::DEVICE_LEVEL;
    int32_t castState_ = CastState::DISCONNECTED;
    std::recursive_mutex castLock_;
    AVSessionDescriptor descriptor_;
    std::string castHandleDeviceId_ = "-100";

    const std::string COMMAND_TYPE = "command_type";
    const std::string COMMAND_BODY = "command_body";

    const std::string CHANGE_CAST_MODE = "CHANGE_CAST_MODE";
    const std::string BYPASS_COMMAND = "BYPASS_COMMAND";
    const std::string QUERY_COMMAND = "QUERY_COMMAND";

    const std::string BYPASS_TO_CAST = "BYPASS_TO_CAST";

    const std::string QUERY_TO_CAST = "QUERY_TO_CAST";

    enum {
        CAST_MODE_CHANGE_COMMAND = 0,
        BYPASS_NUM_COMMAND = 1,
        QUERY_NUM_COMMAND = 2,
    };

    enum CastState {
        DISCONNECTED = 0,
        CONNECTED = 1,
    };

    const std::map<const std::string, int32_t> COMMON_COMMAND_MAPS = {
        {CHANGE_CAST_MODE, CAST_MODE_CHANGE_COMMAND},
        {BYPASS_COMMAND, BYPASS_NUM_COMMAND},
        {QUERY_COMMAND, QUERY_NUM_COMMAND},
    };

    enum {
        BYPASS_NUM_TO_CAST = 0,
    };

    const std::map<const std::string, int32_t> BYPASS_COMMAND_MAPS = {
        {BYPASS_TO_CAST, BYPASS_NUM_TO_CAST},
    };

    enum {
        QUERY_NUM_TO_CAST = 0,
    };

    const std::map<const std::string, int32_t> QUERY_COMMAND_MAPS = {
        {QUERY_TO_CAST, QUERY_NUM_TO_CAST},
    };

    void WriteCastPairToFile(const std::string& deviceId, int32_t castMode);
    int32_t SendStateChangeRequest(const SessionToken& sessionToken);
    void CastStateCommandParams(const AAFwk::WantParams& commandArgs);
    static AVSessionUsersManager& GetUsersManager();
};
} // namespace OHOS::AVSession
#endif // OHOS_PCM_CAST_SESSION_H