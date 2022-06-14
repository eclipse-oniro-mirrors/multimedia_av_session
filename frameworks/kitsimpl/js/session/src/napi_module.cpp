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

#include "napi_avsession.h"
#include "napi_avsession_controller.h"
#include "napi_avsession_manager.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS::AVSession {
static napi_value Export(napi_env env, napi_value exports)
{
    NapiAVSessionManager::Init(env, exports);
    NapiAVSession::Init(env, exports);
    NapiAVSessionController::Init(env, exports);

    return exports;
}

static napi_module module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Export,
    .nm_modname = "multimedia.avsession",
    .nm_priv = ((void*)0),
    .reserved = { 0 }
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&module);
}
} // namespace OHOS::AVSession