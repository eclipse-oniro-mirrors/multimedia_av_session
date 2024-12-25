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

#ifndef OHOS_CJ_AVSESSION_CONTROLLER_FFI_H
#define OHOS_CJ_AVSESSION_CONTROLLER_FFI_H

#include <cstdint>

#include "cj_avsession_prototypes.h"
#include "cj_common_ffi.h"

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

FFI_EXPORT int32_t FfiMultimediaAVSessionControllerDestroy(char *sessionId);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetAVCallState(char *sessionId, CAVCallState* avCallState);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetAVCallMetaData(
    char *sessionId, CAVCallMetaData* avCallMetadata);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetAVPlaybackState(
    char *sessionId, CAVPlaybackState* avPlaybackState);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetAVMetaData(char *sessionId, CAVMetaData* avMetadata);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetOutputDevice(
    char *sessionId, COutputDeviceInfo* outputDeviceInfo);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetRealPlaybackPosition(
    char *sessionId, int64_t* position);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerIsActive(char *sessionId, bool* isActive);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetValidCommands(char *sessionId, CArray* commands);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetAVQueueItems(char *sessionId, CArray* items);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetAVQueueTitle(char *sessionId, char** title);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetExtras(char *sessionId, CArray* extras);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerGetLaunchAbility(char *sessionId, int64_t* abilityId);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerSendCommonCommand(
    char *sessionId, char* command, CArray* args);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerSendControlCommand(
    char *sessionId, CAVSessionCommand* command);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerSendAVKeyEvent(char *sessionId, CKeyEvent* eventPtr);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerSkipToQueueItem(char *sessionId, int32_t* itemId);

FFI_EXPORT int32_t FfiMultimediaAVSessionControllerOn(char *sessionId, int32_t type, int64_t id);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerOff(char *sessionId, int32_t type);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerOnCallMetadataChange(
    char *sessionId, int32_t type, CParameters* filter, int64_t id);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerOnCallStateChange(
    char *sessionId, int32_t type, CParameters* filter, int64_t id);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerOnPlaybackStateChange(
    char *sessionId, int32_t type, CParameters* filter, int64_t id);
FFI_EXPORT int32_t FfiMultimediaAVSessionControllerOnMetaDataChange(
    char *sessionId, int32_t type, CParameters* filter, int64_t id);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* OHOS_CJ_SENSOR_FFI_H */
/**< @} */