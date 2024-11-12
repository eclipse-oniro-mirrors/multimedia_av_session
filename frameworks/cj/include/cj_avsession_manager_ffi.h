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

#ifndef OHOS_CJ_AVSESSION_MANAGER_FFI_H
#define OHOS_CJ_AVSESSION_MANAGER_FFI_H

#include <cstdint>

#include "cj_avsession_prototypes.h"

#ifndef FFI_EXPORT
#ifndef WINDOWS_PLATFORM
#define FFI_EXPORT __attribute__((visibility("default")))
#else
#define FFI_EXPORT __declspec(dllexport)
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

FFI_EXPORT int32_t FfiMultimediaAVSessionManagerCreateAVSession(
    void* abilityContext, char** tag, int32_t* type, int64_t* session, char** sessionId);
FFI_EXPORT int32_t FfiMultimediaAVSessionManagerCreateController(int64_t *sessionId);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* OHOS_CJ_AVSESSION_MANAGER_FFI_H */
/**< @} */