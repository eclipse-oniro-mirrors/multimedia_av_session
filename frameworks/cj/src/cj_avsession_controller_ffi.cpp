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

#include "cj_avsession_controller_ffi.h"

#include "avsession_errors.h"
#include "cj_avsession_controller_impl.h"

#define CJ_AVSESSION_CONTROLLER_IMPL_STRING \
    OHOS::AVSession::CJAVSessionControllerImpl::GetInstance(std::string(sessionId))

extern "C" {
int32_t FfiMultimediaAVSessionControllerDestroy(char *sessionId)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->Destroy();
}

int32_t FfiMultimediaAVSessionControllerGetAVCallState(char* sessionId, CAVCallState* avCallState)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetAVCallState(*avCallState);
}

int32_t FfiMultimediaAVSessionControllerGetAVCallMetaData(char* sessionId, CAVCallMetaData* avCallMetadata)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetAVCallMetaData(*avCallMetadata);
}

int32_t FfiMultimediaAVSessionControllerGetAVPlaybackState(char *sessionId, CAVPlaybackState* avPlaybackState)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetAVPlaybackState(*avPlaybackState);
}

int32_t FfiMultimediaAVSessionControllerGetAVMetaData(char* sessionId, CAVMetaData* avMetadata)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetAVMetaData(*avMetadata);
}

int32_t FfiMultimediaAVSessionControllerGetOutputDevice(char* sessionId, COutputDeviceInfo* outputDeviceInfo)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetOutputDevice(*outputDeviceInfo);
}

int32_t FfiMultimediaAVSessionControllerGetRealPlaybackPosition(char* sessionId, int64_t* position)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetRealPlaybackPosition(*position);
}

int32_t FfiMultimediaAVSessionControllerIsActive(char* sessionId, bool* isActive)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->IsActive(*isActive);
}

int32_t FfiMultimediaAVSessionControllerGetValidCommands(char* sessionId, CArray* commands)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetValidCommands(*commands);
}

int32_t FfiMultimediaAVSessionControllerGetAVQueueItems(char* sessionId, CArray* items)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetAVQueueItems(*items);
}

int32_t FfiMultimediaAVSessionControllerGetAVQueueTitle(char* sessionId, char** title)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetAVQueueTitle(*title);
}

int32_t FfiMultimediaAVSessionControllerGetExtras(char* sessionId, CArray* extras)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->GetExtras(*extras);
}

int32_t FfiMultimediaAVSessionControllerSendCommonCommand(char *sessionId, char* command, CArray* args)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->SendCommonCommand(command, *args);
}

int32_t FfiMultimediaAVSessionControllerSkipToQueueItem(char *sessionId, int32_t* itemId)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJ_AVSESSION_CONTROLLER_IMPL_STRING->SkipToQueueItem(*itemId);
}
}