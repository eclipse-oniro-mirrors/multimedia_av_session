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
    using OffEventHandlerType = std::function<napi_status(napi_env)>;

private:
    static napi_value CreateAVSession(napi_env env, napi_callback_info info);
    static napi_value GetAllSessionDescriptors(napi_env env, napi_callback_info info);
    static napi_value CreateController(napi_env env, napi_callback_info info);
    static napi_value CastAudio(napi_env env, napi_callback_info info);
    static napi_value SendSystemAVKeyEvent(napi_env env, napi_callback_info info);
    static napi_value SendSystemControlCommand(napi_env env, napi_callback_info info);


    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);

    static napi_status OnSessionCreated(napi_env env, napi_value callback);
    static napi_status OnSessionDestroyed(napi_env env, napi_value callback);
    static napi_status OnTopSessionChanged(napi_env env, napi_value callback);
    static napi_status OnServiceDied(napi_env env, napi_value callback);

    static napi_status OffSessionCreated(napi_env env);
    static napi_status OffSessionDestroyed(napi_env env);
    static napi_status OffTopSessionChanged(napi_env env);
    static napi_status OffServiceDied(napi_env env);

    static void HandleServiceDied();

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> eventHandlers_;

    static std::shared_ptr<NapiSessionListener> listener_;
    static std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    static napi_ref serviceDiedCallback_;

    static constexpr size_t ARGC_ONE = 1;
    static constexpr size_t ARGC_TWO = 2;
    static constexpr size_t ARGC_THERE = 3;

    static constexpr size_t ARGV_FIRST = 0;
    static constexpr size_t ARGV_SECOND = 1;
    static constexpr size_t ARGV_THIRD = 2;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVSESSION_MANAGER_H