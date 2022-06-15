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

#ifndef OHOS_NAPI_AVSESSION_H
#define OHOS_NAPI_AVSESSION_H

#include "ability.h"
#include "avsession_info.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "callback/napi_avsession_callback.h"
#include "napi_base_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "utils/avsession_napi_utils.h"
#include "utils/napi_async_proxy.h"

namespace OHOS::AVSession {
class NapiAVSession{
public:
    NapiAVSession();
    ~NapiAVSession();
    static napi_value Init(napi_env env, napi_value exports);
    static napi_status NewInstance(napi_env env, napi_value* result, std::string tag, int32_t type);

private:
    static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);
    static napi_value JsObjectConstruct(napi_env env, napi_callback_info info);
    static napi_value SetAVMetadata(napi_env env, napi_callback_info info);
    static napi_value SetAVPlaybackState(napi_env env, napi_callback_info info);
    static napi_value SetLaunchAbility(napi_env env, napi_callback_info info);
    static napi_value GetController(napi_env env, napi_callback_info info);
    static napi_value Activate(napi_env env, napi_callback_info info);
    static napi_value Deactivate(napi_env env, napi_callback_info info);
    static napi_value Destroy(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value SetAudioStreamId(napi_env env, napi_callback_info info);
    static napi_value GetOutputDevice(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;
    std::shared_ptr<AVSession> avsession_;
    std::shared_ptr<AVSessionCallback> avsessionCallback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVSESSION_H