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

#ifndef OHOS_CJ_AVSESSION_FFI_H
#define OHOS_CJ_AVSESSION_FFI_H

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

FFI_EXPORT int32_t FfiMultimediaAVSessionSetAVMetaData(int64_t sessionId, CAVMetaData* data);
FFI_EXPORT int32_t FfiMultimediaAVSessionSetAVCallMetaData(int64_t sessionId, CAVCallMetaData* data);
FFI_EXPORT int32_t FfiMultimediaAVSessionSetAVCallState(int64_t sessionId, CAVCallState* state);
FFI_EXPORT int32_t FfiMultimediaAVSessionSetAVPlaybackState(int64_t sessionId, CAVPlaybackState* state);
FFI_EXPORT int32_t FfiMultimediaAVSessionSetAVQueueItems(int64_t sessionId, CArray* items);
FFI_EXPORT int32_t FfiMultimediaAVSessionSetAVQueueTitle(int64_t sessionId, char** title);
FFI_EXPORT int32_t FfiMultimediaAVSessionSetExtras(int64_t sessionId, CArray* extras);
FFI_EXPORT int32_t FfiMultimediaAVSessionSetLaunchAbility(int64_t sessionId, int64_t abilityId);
FFI_EXPORT int32_t FfiMultimediaAVSessionGetController(int64_t sessionId);
FFI_EXPORT int32_t FfiMultimediaAVSessionGetAVCastController(int64_t sessionId);
FFI_EXPORT int32_t FfiMultimediaAVSessionGetOutputDevice(int64_t sessionId, COutputDeviceInfo* outputDeviceInfo);
FFI_EXPORT int32_t FfiMultimediaAVSessionGetAllCastDisplays(int64_t sessionId, CArray* infos);
FFI_EXPORT int32_t FfiMultimediaAVSessionActivate(int64_t sessionId);
FFI_EXPORT int32_t FfiMultimediaAVSessionDeactivate(int64_t sessionId);
FFI_EXPORT int32_t FfiMultimediaAVSessionDestroy(int64_t sessionId);
FFI_EXPORT int32_t FfiMultimediaAVSessionStopCasting(int64_t sessionId);
FFI_EXPORT int32_t FfiMultimediaAVSessionDispatchSessionEvent(int64_t sessionId, char** event, CArray* args);
FFI_EXPORT int32_t FfiMultimediaAVSessionOn(int64_t sessionId, int32_t eventType, int64_t id);
FFI_EXPORT int32_t FfiMultimediaAVSessionOff(int64_t sessionId, int32_t eventType);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* OHOS_CJ_AVSESSION_FFI_H */
/**< @} */