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

#ifndef AV_SESSION_NAPI_CONST_PROPERTIES_H
#define AV_SESSION_NAPI_CONST_PROPERTIES_H

#include "napi/native_api.h"

namespace OHOS::AVSession {
napi_status InitEnums(napi_env env, napi_value exports);
static void AVSessionControlErrorCode(napi_env env, napi_value result);
static void AVSessionIOErrorCode(napi_env env, napi_value result);
static void AVSessionParsingErrorCode(napi_env env, napi_value result);
static void AVSessionDecodingErrorCode(napi_env env, napi_value result);
static void AVSessionAudioRenderErrorCode(napi_env env, napi_value result);
static void AVSessionDRMErrorCode(napi_env env, napi_value result);
}

#endif