/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_NAPI_AVSESSION_MANAGER_H
#define OHOS_NAPI_AVSESSION_MANAGER_H

#include <map>
#include <list>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "napi_session_listener.h"

namespace OHOS::AVSession {
class NapiAVSessionManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

    using OnEventHandlerType = std::function<napi_status(napi_env, napi_value)>;
    using OffEventHandlerType = std::function<napi_status(napi_env, napi_value)>;
    static std::map<int32_t, int32_t> errcode_;

private:
    static napi_value CreateAVSession(napi_env env, napi_callback_info info);
    static napi_value GetAllSessionDescriptors(napi_env env, napi_callback_info info);
    static napi_value GetHistoricalSessionDescriptors(napi_env env, napi_callback_info info);
    static napi_value GetHistoricalAVQueueInfos(napi_env env, napi_callback_info info);
    static napi_value StartAVPlayback(napi_env env, napi_callback_info info);
    static napi_value GetDistributedSessionControllers(napi_env env, napi_callback_info info);
    static napi_value CreateController(napi_env env, napi_callback_info info);
    static napi_value GetAVCastController(napi_env env, napi_callback_info info);
    static napi_value CastAudio(napi_env env, napi_callback_info info);
    static napi_value SendSystemAVKeyEvent(napi_env env, napi_callback_info info);
    static napi_value SendSystemControlCommand(napi_env env, napi_callback_info info);
    static napi_value StartCastDiscovery(napi_env env, napi_callback_info info);
    static napi_value StopCastDiscovery(napi_env env, napi_callback_info info);
    static napi_value SetDiscoverable(napi_env env, napi_callback_info info);
    static napi_value StartDeviceLogging(napi_env env, napi_callback_info info);
    static napi_value StopDeviceLogging(napi_env env, napi_callback_info info);
    static napi_value StartCast(napi_env env, napi_callback_info info);
    static napi_value StopCast(napi_env env, napi_callback_info info);

    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);
    static napi_value OnDistributedSessionChangeEvent(napi_env env, napi_callback_info info);
    static napi_value OffDistributedSessionChangeEvent(napi_env env, napi_callback_info info);

    static napi_status OnSessionCreate(napi_env env, napi_value callback);
    static napi_status OnSessionDestroy(napi_env env, napi_value callback);
    static napi_status OnTopSessionChange(napi_env env, napi_value callback);
    static napi_status OnAudioSessionChecked(napi_env env, napi_value callback);
    static napi_status OnDeviceAvailable(napi_env env, napi_value callback);
    static napi_status OnDeviceLogEvent(napi_env env, napi_value callback);
    static napi_status OnDeviceOffline(napi_env env, napi_value callback);
    static napi_status OnServiceDie(napi_env env, napi_value callback);
    static napi_status OnRemoteDistributedSessionChange(napi_env env, napi_value callback);

    static napi_status OffSessionCreate(napi_env env, napi_value callback);
    static napi_status OffSessionDestroy(napi_env env, napi_value callback);
    static napi_status OffTopSessionChange(napi_env env, napi_value callback);
    static napi_status OffAudioSessionChecked(napi_env env, napi_value callback);
    static napi_status OffDeviceAvailable(napi_env env, napi_value callback);
    static napi_status OffDeviceLogEvent(napi_env env, napi_value callback);
    static napi_status OffDeviceOffline(napi_env env, napi_value callback);
    static napi_status OffServiceDie(napi_env env, napi_value callback);
    static napi_status OffRemoteDistributedSessionChange(napi_env env, napi_value callback);

    static void HandleServiceDied();

    static void HandleServiceStart();
    
    static bool JudgeNumString(std::string str);

    static napi_status RegisterNativeSessionListener(napi_env env);

    static void ErrCodeToMessage(int32_t errCode, const std::string& tag, std::string& message);

    static napi_status ProcessCastDiscoveryParams(
        napi_env env, size_t argc, napi_value* argv,
        int32_t& castDeviceCapability, std::vector<std::string>& drmSchemes);

    static void ReportStartCastDiscoveryFailInfo(std::string func, int32_t error);

    static void ReportStopCastDiscoveryFailInfo(std::string func, int32_t error);

    static void ReportStartCastFailInfo(int32_t error);

    static void ReportStartCastFailInfo(int32_t error, const OutputDeviceInfo &outputDeviceInfo);

    static void ReportStopCastFailInfo(int32_t error);

    static std::string GetStartCastErrMsg(int32_t error);

    static void CheckStartCastReportRadar(bool condition, int32_t error);

    static void CheckStopCastReportRadar(bool condition, int32_t error);

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> eventHandlers_;

    static std::shared_ptr<NapiSessionListener> listener_;
    static std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    static std::list<napi_ref> serviceDiedCallbacks_;
    static std::map<DistributedSessionType, std::pair<OnEventHandlerType, OffEventHandlerType>>
        distributedControllerEventHandlers_;

    static constexpr size_t ARGC_ZERO = 0;
    static constexpr size_t ARGC_ONE = 1;
    static constexpr size_t ARGC_TWO = 2;
    static constexpr size_t ARGC_THREE = 3;

    static constexpr size_t ARGV_FIRST = 0;
    static constexpr size_t ARGV_SECOND = 1;
    static constexpr size_t ARGV_THIRD = 2;

    static constexpr size_t HISTORICAL_UNSET_NUM = 3;
    static constexpr size_t HISTORICAL_MIN_NUM = 0;
    static constexpr size_t HISTORICAL_MAX_NUM = 10;

    static const std::string DISTRIBUTED_SESSION_CHANGE_EVENT;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVSESSION_MANAGER_H