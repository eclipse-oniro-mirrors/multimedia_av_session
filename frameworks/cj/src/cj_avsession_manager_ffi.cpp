/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_avsession_manager_ffi.h"

#include "ability_context.h"
#include "avsession_errors.h"
#include "cj_avsession_manager_impl.h"
#include "cj_avsession_impl.h"

extern "C" {
int32_t FfiMultimediaAVSessionManagerCreateAVSession(void* abilityContext,
    char** tag, int32_t* type, int64_t* session, char** sessionId)
{
    if (abilityContext == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto context = static_cast<OHOS::AbilityRuntime::AbilityContext*>(abilityContext);
    return CJ_AVSESSION_MANAGER_IMPL->CreateAVSession(*context, std::string(*tag), *type, *session, *sessionId);
}

int32_t FfiMultimediaAVSessionManagerCreateController(int64_t *sessionId)
{
    return CJ_AVSESSION_MANAGER_IMPL->CreateController(
        OHOS::FFI::FFIData::GetData<OHOS::AVSession::CJAVSessionImpl>(*sessionId)->GetSessionId());
}
}