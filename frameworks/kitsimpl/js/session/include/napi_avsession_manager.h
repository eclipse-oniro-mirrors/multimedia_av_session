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

#include "avsession_log.h"
#include "avsession_manager.h"
#include "callback/napi_sessionlistener_callback.h"
#include "napi_avsession.h"
#include "napi_avsession_controller.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "utils/avsession_napi_utils.h"
#include "utils/napi_async_proxy.h"

namespace OHOS::AVSession {
class NapiAVSessionManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

    NapiAVSessionManager();
    ~NapiAVSessionManager();

private:
    static void Destructor(napi_env env, void *nativeObject, void *finalizeHint);
    static napi_value CreateAVSession(napi_env env, napi_callback_info info);
    static napi_value GetAllSessionDescriptors(napi_env env, napi_callback_info info);
    static napi_value CreateController(napi_env env, napi_callback_info info);
    static napi_value SendSystemAVKeyEvent(napi_env env, napi_callback_info info);
    static napi_value SendSystemControlCommand(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value CreateLoopModeObject(napi_env env);
    static napi_value CreatePlaybackStateObject(napi_env env);
    static napi_value CastAudio(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;
    static napi_ref loopModeTypeRef_;
    static napi_ref playbackStateTypeRef_;
    std::shared_ptr<AVSessionController> avSessionController_;
    std::shared_ptr<NapiSessionListenerCallback> sessionListenerCallback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVSESSION_MANAGER_H