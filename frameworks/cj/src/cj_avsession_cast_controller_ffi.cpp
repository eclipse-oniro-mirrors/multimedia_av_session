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

#include "cj_avsession_cast_controller_ffi.h"

#include "avsession_errors.h"
#include "cj_avsession_cast_controller_impl.h"

#define CJ_CAST_CONTROLLER_IMPL_STRING \
    OHOS::AVSession::CJAVCastControllerImpl::GetInstance(std::string(sessionId))

extern "C" {
int32_t FfiMultimediaAVSessionCastControllerSubscribeCallbackWithExtras(
    char* sessionId, int32_t type, CParameters* extras, DoCallFunc doCall)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->SubscribeCallback(type, extras, doCall);
}

int32_t FfiMultimediaAVSessionCastControllerSubscribeCallback(char* sessionId, int32_t type, DoCallFunc doCall)
{
    return FfiMultimediaAVSessionCastControllerSubscribeCallbackWithExtras(sessionId, type, nullptr, doCall);
}

int32_t FfiMultimediaAVSessionCastControllerStart(char* sessionId, CAVQueueItem* item)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->Start(*item);
}

int32_t FfiMultimediaAVSessionCastControllerPrepare(char* sessionId, CAVQueueItem* item)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->Prepare(*item);
}

int32_t FfiMultimediaAVSessionCastControllerSendControlCommand(char* sessionId, CAVSessionCommand* command)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->SendControlCommand(*command);
}

int32_t FfiMultimediaAVSessionCastControllerGetAVPlaybackState(char* sessionId, CAVPlaybackState* avPlaybackState)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->GetAVPlaybackState(*avPlaybackState);
}

int32_t FfiMultimediaAVSessionCastControllerGetCurrentItem(char* sessionId, CAVQueueItem* item)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->GetCurrentItem(*item);
}

int32_t FfiMultimediaAVSessionCastControllerGetValidCommands(char* sessionId, CArray* commands)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->GetValidCommands(*commands);
}

int32_t FfiMultimediaAVSessionCastControllerRelease(char* sessionId)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->Release();
}

int32_t FfiMultimediaAVSessionCastControllerProcessMediaKeyResponse(char* sessionId, char** assetId, CArray* response)
{
    if (sessionId == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return CJ_CAST_CONTROLLER_IMPL_STRING->ProcessMediaKeyResponse(*assetId, *response);
}
}