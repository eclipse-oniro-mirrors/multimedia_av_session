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
    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove, int32_t reasonCode) override;

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg) override;

    int32_t StartCast(const OutputDeviceInfo& outputDeviceInfo,
        std::pair<std::string, std::string>& serviceNameStatePair, const SessionToken& sessionToken);
    
    int32_t StartScreenCast(const OutputDeviceInfo& outputDeviceInfo,
        std::pair<std::string, std::string>& serviceNameStatePair, const SessionToken& sessionToken);

    void StopCast(const DeviceRemoveAction deviceRemoveAction = DeviceRemoveAction::ACTION_DISCONNECT);

    int32_t SubStartCast(const OutputDeviceInfo& outputDeviceInfo,
        std::pair<std::string, std::string>& serviceNameStatePair, const SessionToken& sessionToken);

    void ExecuteCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs);

    void DestroyTask();

    int32_t GetCastMode() const;
    pid_t GetUid() const;
    int32_t GetCastState() const;
    int64_t GetCastHandle() const;
    AVSessionDescriptor GetDescriptor();

    void OnSystemCommonEvent(const std::string& args);

    void OnDeviceNameSystemCommonEvent(const std::string& args);

    void BypassCommandParams(const AAFwk::WantParams& commandArgs);

    void QueryCommandParams(const AAFwk::WantParams& commandArgs);

    void ControlCommandParams(const AAFwk::WantParams& commandArgs);

    void UpdateDeviceNameCommandParams(const AAFwk::WantParams& commandArgs);

    void QueryData(const AAFwk::WantParams& commandArgs);
    void QueryCastSessionId();
    void SaveDataInPcm(const AAFwk::WantParams& commandBody);
    void SavePinCode(const AAFwk::WantParams& commandBody);

    void CreateStreamPlayer(const AAFwk::WantParams& commandBody);
    void ReleaseStreamPlayer();

    void CreateExtraInfo(std::string deviceType, std::string scenario);

    void SendModeChangeToCast(int32_t screenMode);

private:
    int64_t castHandle_ = 0;
    int32_t castState_ = CastState::DISCONNECTED;
    std::recursive_mutex castLock_;
    std::mutex screenLock_;
    std::condition_variable startCastCondition_;

    AVSessionDescriptor descriptor_;
    std::string pinCode_ = "";
    std::string castHandleDeviceId_ = "-100";
    std::string collaborationNeedDeviceId_;
    std::string collaborationNeedNetworkId_;
    const std::string MEDIA_CAST_ERROR = "usual.event.MEDIA_CAST_ERROR";

    std::atomic<MultiDeviceState> multiDeviceState_ = MultiDeviceState::DEFAULT;
    OutputDeviceInfo newOutputDeviceInfo_;
    SessionToken newSessionToken_;
    std::pair<std::string, std::string> newServiceNameStatePair_;
    DeviceInfo tempDeviceInfo_;
    std::string streamCastingSessionId_;
    std::string extraInfo_;

    const std::string COMMAND_TYPE = "command_type";
    const std::string COMMAND_BODY = "command_body";

    const std::string CHANGE_CAST_MODE = "CHANGE_CAST_MODE";
    const std::string BYPASS_COMMAND = "BYPASS_COMMAND";
    const std::string QUERY_COMMAND = "QUERY_COMMAND";
    const std::string CONTROL_COMMAND = "CONTROL_COMMAND";
    const std::string UPDATE_DEVICE_NAME = "UPDATE_DEVICE_NAME";

    const std::string BYPASS_TO_CAST = "BYPASS_TO_CAST";

    const std::string QUERY_TO_CAST = "QUERY_TO_CAST";
    const std::string QUERY_TO_AVSESSION = "QUERY_TO_AVSESSION";

    const std::string SAVE_TO_PCM = "SAVE_TO_PCM";
    const std::string CREATE_STREAM_PLAYER = "CREATE_STREAM_PLAYER";
    const std::string RELEASE_STREAM_PLAYER = "RELEASE_STREAM_PLAYER";
    const std::string CHANGE_SCREEN_MODE = "CHANGE_SCREEN_MODE";

    const std::string KEY = "KEY";
    const std::string VALUE = "VALUE";
    const std::string CAST_SESSION_ID = "CAST_SESSION_ID";
    const std::string PIN_CODE = "PIN_CODE";
    const std::string QUERY_PINCODE = "QUERY_PINCODE";
    const std::string SESSION_ID = "SESSION_ID";

    enum {
        CAST_MODE_CHANGE_COMMAND = 0,
        BYPASS_COMMAND_NUM = 1,
        QUERY_COMMAND_NUM = 2,
        CONTROL_COMMAND_NUM = 3,
        UPDATE_DEVICE_NAME_COMMAND = 4,
    };

    enum CastState {
        DISCONNECTED = 0,
        CONNECTED = 1,
    };

    const std::map<const std::string, int32_t> COMMON_COMMAND_MAPS = {
        {CHANGE_CAST_MODE, CAST_MODE_CHANGE_COMMAND},
        {BYPASS_COMMAND, BYPASS_COMMAND_NUM},
        {QUERY_COMMAND, QUERY_COMMAND_NUM},
        {CONTROL_COMMAND, CONTROL_COMMAND_NUM},
        {UPDATE_DEVICE_NAME, UPDATE_DEVICE_NAME_COMMAND}
    };

    enum {
        BYPASS_TO_CAST_NUM = 0,
    };

    const std::map<const std::string, int32_t> BYPASS_COMMAND_MAPS = {
        {BYPASS_TO_CAST, BYPASS_TO_CAST_NUM},
    };

    enum {
        QUERY_TO_CAST_NUM = 0,
        QUERY_TO_AVSESSION_NUM = 1,
    };

    const std::map<const std::string, int32_t> QUERY_COMMAND_MAPS = {
        {QUERY_TO_CAST, QUERY_TO_CAST_NUM},
        {QUERY_TO_AVSESSION, QUERY_TO_AVSESSION_NUM},
    };

    enum {
        SAVE_TO_PCM_NUM = 0,
        CREATE_STREAM_PLAYER_NUM = 1,
        RELEASE_STREAM_PLAYER_NUM = 2,
        CHANGE_SCREEN_MODE_NUM = 3,
    };

    const std::map<const std::string, int32_t> CONTROL_COMMAND_MAPS = {
        {SAVE_TO_PCM, SAVE_TO_PCM_NUM},
        {CREATE_STREAM_PLAYER, CREATE_STREAM_PLAYER_NUM},
        {RELEASE_STREAM_PLAYER, RELEASE_STREAM_PLAYER_NUM},
        {CHANGE_SCREEN_MODE, CHANGE_SCREEN_MODE_NUM},
    };

    enum {
        CAST_SESSION_ID_NUM = 0,
        PIN_CODE_NUM = 1,
    };

    const std::map<const std::string, int32_t> DATA_KEY_MAPS = {
        {CAST_SESSION_ID, CAST_SESSION_ID_NUM},
        {PIN_CODE, PIN_CODE_NUM},
    };

    void WriteCastPairToFile(const std::string& deviceId, int32_t castMode);
    int32_t SendStateChangeRequest(const SessionToken& sessionToken);
    void CastStateCommandParams(const AAFwk::WantParams& commandArgs);
    void DealCollaborationPublishState(int32_t castState, DeviceInfo deviceInfo);
    void ReportSessionCast(int32_t castState, int32_t reasonCode);
    const std::string PCM_CAST_SESSION = "PCMCast";
    int32_t noReasonCode_ = 0;
    int32_t reasonDeviceIsUntrusted_ = 10014;
};
} // namespace OHOS::AVSession
#endif // OHOS_PCM_CAST_SESSION_H