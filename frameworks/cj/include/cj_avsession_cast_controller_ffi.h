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

#ifndef OHOS_CJ_AVSESSION_CAST_CONTROLLER_FFI_H
#define OHOS_CJ_AVSESSION_CAST_CONTROLLER_FFI_H

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

typedef void (*DoCallFunc)(CCallbackData*);

int32_t FfiMultimediaAVSessionCastControllerSubscribeCallbackWithExtras(
    char* sessionId, int32_t type, CParameters* extras, DoCallFunc doCall);
int32_t FfiMultimediaAVSessionCastControllerSubscribeCallback(char* sessionId, int32_t type, DoCallFunc doCall);

int32_t FfiMultimediaAVSessionCastControllerStart(char* sessionId, CAVQueueItem* item);
int32_t FfiMultimediaAVSessionCastControllerPrepare(char* sessionId, CAVQueueItem* item);
int32_t FfiMultimediaAVSessionCastControllerSendControlCommand(char* sessionId, CAVSessionCommand* command);
int32_t FfiMultimediaAVSessionCastControllerGetAVPlaybackState(char* sessionId, CAVPlaybackState* avPlaybackState);
int32_t FfiMultimediaAVSessionCastControllerGetCurrentItem(char* sessionId, CAVQueueItem* item);
int32_t FfiMultimediaAVSessionCastControllerGetValidCommands(char* sessionId, CArray* commands);
int32_t FfiMultimediaAVSessionCastControllerRelease(char* sessionId);
int32_t FfiMultimediaAVSessionCastControllerProcessMediaKeyResponse(char* sessionId, char** assetId, CArray* response);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* OHOS_CJ_AVSESSION_CAST_CONTROLLER_FFI_H */
/**< @} */