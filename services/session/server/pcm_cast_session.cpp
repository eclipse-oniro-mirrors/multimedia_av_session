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

#include "pcm_cast_session.h"

#include "avsession_log.h"
#include "avsession_utils.h"
#include "av_router.h"
#include "cast_engine_common.h"
#include "ipc_skeleton.h"
#include "string_wrapper.h"
#include "int_wrapper.h"
#include "avsession_errors.h"
#include "json_utils.h"

namespace OHOS::AVSession {

const std::map<const std::string, int32_t> COMMON_COMMAND_MAPS = {
    {"CHANGE_CAST_MODE", PcmCastSession::CAST_MODE_CHANGE_COMMAND},
};

void PcmCastSession::OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove)
{
    SLOGI("PcmCastSession OnCastStateChange state %{public}d id %{public}s", castState,
        AVSessionUtils::GetAnonymousDeviceId(deviceInfo.deviceId_).c_str());
    if (castState == static_cast<int32_t>(CastEngine::DeviceState::DISCONNECTED)) {
        AVRouter::GetInstance().UnRegisterCallback(castHandle_, shared_from_this(), "pcmCastSession");
        AVRouter::GetInstance().StopCastSession(castHandle_);
        castHandle_ = -1;
        castState_ = CastState::DISCONNECTED;
        castHandleDeviceId_ = "-100";
    }
    
    deviceInfo.hiPlayDeviceInfo_.castMode_ = castMode_;
    deviceInfo.hiPlayDeviceInfo_.castUid_ = GetUid();
    SLOGI("PcmCastSession OnCastStateChange castUid %{public}d", deviceInfo.hiPlayDeviceInfo_.castUid_);
    OutputDeviceInfo outputDeviceInfo;
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    if (castState == static_cast<int32_t>(CastEngine::DeviceState::STREAM)) {
        descriptor_.outputDeviceInfo_ = outputDeviceInfo;
        castState_ = CastState::CONNECTED;
    }
}
 
void PcmCastSession::OnSystemCommonEvent(const std::string& args)
{
    int32_t code = JsonUtils::GetIntParamFromJsonString(args, "code");
    CHECK_AND_RETURN_RET_LOG(castState_ != 0, void(), "First connection, castState is 0.");
    CHECK_AND_RETURN_RET_LOG(code == 0, void(), "Castmode changes fail, code is %{public}d", code);
    int32_t castMode = JsonUtils::GetIntParamFromJsonString(args, "mode");
    int32_t uid = JsonUtils::GetIntParamFromJsonString(args, "uid");
    std::string deviceId = JsonUtils::GetStringParamFromJsonString(args, "deviceId");
    SLOGI("Received HIPLAY_CONFIG_MODE_DATA: castMode=%{public}d, uid=%{public}d, deviceId:%{public}s",
        castMode, uid, AVSessionUtils::GetAnonymousDeviceId(deviceId).c_str());
 
    if (castMode == HiPlayCastMode::DEVICE_LEVEL) {
        castMode_ = HiPlayCastMode::DEVICE_LEVEL;
        descriptor_.uid_ = 0;
        descriptor_.outputDeviceInfo_.deviceInfos_[0].hiPlayDeviceInfo_.castUid_ = 0;
    } else if (castMode == HiPlayCastMode::APP_LEVEL) {
        castMode_ = HiPlayCastMode::APP_LEVEL;
        descriptor_.uid_ = uid;
        descriptor_.outputDeviceInfo_.deviceInfos_[0].hiPlayDeviceInfo_.castUid_ = uid;
    }
 
    WriteCastPairToFile(deviceId, castMode_);
}

void PcmCastSession::OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
{
    SLOGI("PcmCastSession OnCastEventRecv errorCode %{public}d errorMsg %{public}s", errorCode, errorMsg.c_str());
}

int32_t PcmCastSession::StartCast(const OutputDeviceInfo& outputDeviceInfo,
    std::pair<std::string, std::string>& serviceNameStatePair, const SessionToken& sessionToken)
{
    if (sessionToken.sessionId == "pcmCastSession") {
        castMode_ = HiPlayCastMode::DEVICE_LEVEL;
        SLOGI("PcmCastSession isDeviceLevel: true");
    } else {
        castMode_ = HiPlayCastMode::APP_LEVEL;
        descriptor_.uid_ = sessionToken.uid;
        SLOGI("PcmCastSession isDeviceLevel: false, sessionId: %{public}s", AVSessionUtils::GetAnonySessionId(
            sessionToken.sessionId).c_str());
    }
    if (castHandle_ > 0) {
        if (castHandleDeviceId_ == outputDeviceInfo.deviceInfos_[0].deviceId_) {
            SLOGI("repeat startcast %{public}lld", (long long)castHandle_);
            SendStateChangeRequest(sessionToken);
            
            descriptor_.uid_ = sessionToken.uid;
            descriptor_.outputDeviceInfo_.deviceInfos_[0].hiPlayDeviceInfo_.castUid_ = sessionToken.uid;
 
            return ERR_REPEAT_CAST;
        }
    }
 
    castHandle_ = AVRouter::GetInstance().StartCast(outputDeviceInfo, serviceNameStatePair, "pcmCastSession");
    SLOGI("PcmCastSession StartCast-castHandle_ %{public}lld", (long long)castHandle_);
    AVRouter::GetInstance().RegisterCallback(castHandle_, shared_from_this(),
        "pcmCastSession", outputDeviceInfo.deviceInfos_[0]);
 
    SendStateChangeRequest(sessionToken);
    WriteCastPairToFile(outputDeviceInfo.deviceInfos_[0].deviceId_, castMode_);
 
    int32_t castId = static_cast<int32_t>(castHandle_);
    int32_t ret = AVRouter::GetInstance().AddDevice(castId, outputDeviceInfo, 0);
    if (ret == AVSESSION_SUCCESS) {
        castHandleDeviceId_ = outputDeviceInfo.deviceInfos_[0].deviceId_;
        SLOGI("PcmCastSession StartCast castHandleDeviceId_: %{public}s", castHandleDeviceId_.c_str());
    }
    SLOGI("PcmCastSession StartCast ret %{public}d", ret);
    return ret;
}

void PcmCastSession::StopCast()
{
    SLOGI("PcmCastSession StopCast");
    AVRouter::GetInstance().UnRegisterCallback(castHandle_, shared_from_this(), "pcmCastSession");
    AVRouter::GetInstance().StopCastSession(castHandle_);
}
 
void PcmCastSession::WriteCastPairToFile(const std::string& deviceId, int32_t castMode)
{
    CHECK_AND_RETURN_RET_LOG(!deviceId.empty(), void(), "deviceId is empty.");
    SLOGI("PcmCastSession start write file");
    std::pair<std::string, int32_t> castPair = { deviceId, castMode };
    SLOGI("PcmCastSession castPair: deviceId=%{public}s, castMode=%{public}d",
        AVSessionUtils::GetAnonymousDeviceId(castPair.first).c_str(), castPair.second);
 
    std::string fileDir = AVSessionUtils::GetCachePathName();
    std::string fileName = deviceId + "_cast_pair" + AVSessionUtils::GetPairFileSuffix();
 
    AVSessionUtils::WritePairToFile(castPair, fileDir, fileName);
    SLOGI("PcmCastSession ExecuteCommonCommand finished.");
}
 
int32_t PcmCastSession::SendStateChangeRequest(const SessionToken& sessionToken)
{
    cJSON* jsonObj = cJSON_CreateObject();
    if (!jsonObj) {
        SLOGE("Failed to create cJSON object");
        return AVSESSION_ERROR;
    }
 
    cJSON_AddItemToObject(jsonObj, "mode", cJSON_CreateNumber(castMode_));
    cJSON_AddItemToObject(jsonObj, "sessionId", cJSON_CreateString(sessionToken.sessionId.c_str()));
    cJSON_AddItemToObject(jsonObj, "uid", cJSON_CreateNumber(sessionToken.uid));
    SLOGI("SendStateChangeRequest, sessionId=%{public}s, uid=%{public}d, castMode=%{public}d",
        AVSessionUtils::GetAnonySessionId(sessionToken.sessionId).c_str(), sessionToken.uid, castMode_);
 
    char* jsonStr = cJSON_Print(jsonObj);
    if (jsonStr != nullptr) {
        std::string params(jsonStr);
        cJSON_free(jsonStr);
        AVRouter::GetInstance().SendCommandArgsToCast(castHandle_, CAST_MODE_CHANGE_COMMAND, params);
    } else {
        SLOGE("get jsonStr nullptr");
        cJSON_Delete(jsonObj);
        return AVSESSION_ERROR;
    }
    cJSON_Delete(jsonObj);
    return AVSESSION_SUCCESS;
}
 
void PcmCastSession::ExecuteCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    const auto& it = COMMON_COMMAND_MAPS.find(commonCommand);
    CHECK_AND_RETURN_LOG(it != COMMON_COMMAND_MAPS.end(), "commonCommand is not support");
 
    switch (it->second) {
        case CAST_MODE_CHANGE_COMMAND:
            CastStateCommandParams(commandArgs);
            break;
        default:
            break;
    }
}
 
void PcmCastSession::CastStateCommandParams(const AAFwk::WantParams& commandArgs)
{
    SLOGI("PcmCastSession ExecuteCommonCommand process");
    std::string params = commandArgs.ToString();
    AVRouter::GetInstance().SendCommandArgsToCast(castHandle_, CAST_MODE_CHANGE_COMMAND, params);
}
 
void PcmCastSession::DestroyTask()
{
    SLOGI("PcmCastSession DestroyTask process");
    AVRouter::GetInstance().UnRegisterCallback(castHandle_, shared_from_this(), "pcmCastSession");
    AVRouter::GetInstance().StopCastSession(castHandle_);
}
 
int32_t PcmCastSession::GetCastMode() const
{
    return castMode_;
}
 
pid_t PcmCastSession::GetUid() const
{
    return descriptor_.uid_;
}
 
int32_t PcmCastSession::GetCastState() const
{
    return castState_;
}
 
AVSessionDescriptor PcmCastSession::GetDescriptor()
{
    return descriptor_;
}
 
} // namespace OHOS::AVSession