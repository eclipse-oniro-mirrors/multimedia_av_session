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
    static napi_value CreateController(napi_env env, napi_callback_info info);
    static napi_value CastAudio(napi_env env, napi_callback_info info);
    static napi_value SendSystemAVKeyEvent(napi_env env, napi_callback_info info);
    static napi_value SendSystemControlCommand(napi_env env, napi_callback_info info);

    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);

    static napi_status OnSessionCreate(napi_env env, napi_value callback);
    static napi_status OnSessionDestroy(napi_env env, napi_value callback);
    static napi_status OnTopSessionChange(napi_env env, napi_value callback);
    static napi_status OnAudioSessionChecked(napi_env env, napi_value callback);
    static napi_status OnServiceDie(napi_env env, napi_value callback);

    static napi_status OffSessionCreate(napi_env env, napi_value callback);
    static napi_status OffSessionDestroy(napi_env env, napi_value callback);
    static napi_status OffTopSessionChange(napi_env env, napi_value callback);
    static napi_status OffAudioSessionChecked(napi_env env, napi_value callback);
    static napi_status OffServiceDie(napi_env env, napi_value callback);

    static void HandleServiceDied();

    static napi_status RegisterNativeSessionListener(napi_env env);

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> eventHandlers_;

    static std::shared_ptr<NapiSessionListener> listener_;
    static std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    static std::list<napi_ref> serviceDiedCallbacks_;

    static constexpr size_t ARGC_ONE = 1;
    static constexpr size_t ARGC_TWO = 2;
    static constexpr size_t ARGC_THERE = 3;

    static constexpr size_t ARGV_FIRST = 0;
    static constexpr size_t ARGV_SECOND = 1;
    static constexpr size_t ARGV_THIRD = 2;

    static constexpr size_t HISTORICAL_UNSET_NUM = 3;
    static constexpr size_t HISTORICAL_MIN_NUM = 0;
    static constexpr size_t HISTORICAL_MAX_NUM = 10;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVSESSION_MANAGER_H