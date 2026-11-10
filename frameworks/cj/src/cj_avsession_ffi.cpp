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

#include "cj_avsession_ffi.h"

#include "avsession_errors.h"
#include "cj_avsession_impl.h"

extern "C" {
static OHOS::AVSession::CJAVSessionImpl* GetSessionImpl(int64_t sessionId)
{
    return OHOS::FFI::FFIData::GetData<OHOS::AVSession::CJAVSessionImpl>(sessionId);
}

int32_t FfiMultimediaAVSessionSetAVMetaData(int64_t sessionId, CAVMetaData* data)
{
    if (data == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->SetAVMetaData(*data);
}

int32_t FfiMultimediaAVSessionSetAVCallMetaData(int64_t sessionId, CAVCallMetaData* data)
{
    if (data == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->SetAVCallMetaData(*data);
}

int32_t FfiMultimediaAVSessionSetAVCallState(int64_t sessionId, CAVCallState* state)
{
    if (state == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->SetAVCallState(*state);
}

int32_t FfiMultimediaAVSessionSetAVPlaybackState(int64_t sessionId, CAVPlaybackState* state)
{
    if (state == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->SetAVPlaybackState(*state);
}

int32_t FfiMultimediaAVSessionSetAVQueueItems(int64_t sessionId, CArray* items)
{
    if (items == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->SetAVQueueItems(*items);
}

int32_t FfiMultimediaAVSessionSetAVQueueTitle(int64_t sessionId, char** title)
{
    if (title == nullptr || *title == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->SetAVQueueTitle(*title);
}

int32_t FfiMultimediaAVSessionSetExtras(int64_t sessionId, CArray* extras)
{
    if (extras == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->SetExtras(*extras);
}

int32_t FfiMultimediaAVSessionSetLaunchAbility(int64_t sessionId, int64_t abilityId)
{
    if (abilityId == 0) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->SetLaunchAbility(abilityId);
}

int32_t FfiMultimediaAVSessionGetController(int64_t sessionId)
{
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->GetController();
}

int32_t FfiMultimediaAVSessionGetAVCastController(int64_t sessionId)
{
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->GetAVCastController();
}

int32_t FfiMultimediaAVSessionGetOutputDevice(int64_t sessionId, COutputDeviceInfo* outputDeviceInfo)
{
    if (outputDeviceInfo == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->GetOutputDevice(*outputDeviceInfo);
}

int32_t FfiMultimediaAVSessionGetAllCastDisplays(int64_t sessionId, CArray* infos)
{
    if (infos == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->GetAllCastDisplays(*infos);
}

int32_t FfiMultimediaAVSessionActivate(int64_t sessionId)
{
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->Activate();
}

int32_t FfiMultimediaAVSessionDeactivate(int64_t sessionId)
{
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->Deactivate();
}

int32_t FfiMultimediaAVSessionDestroy(int64_t sessionId)
{
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->Destroy();
}

int32_t FfiMultimediaAVSessionStopCasting(int64_t sessionId)
{
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->StopCasting();
}

int32_t FfiMultimediaAVSessionDispatchSessionEvent(int64_t sessionId, char** event, CArray* args)
{
    if (event == nullptr || *event == nullptr || args == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->DispatchSessionEvent(*event, *args);
}

int32_t FfiMultimediaAVSessionOn(int64_t sessionId, int32_t eventType, int64_t callbackId)
{
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->OnEvent(eventType, callbackId);
}

int32_t FfiMultimediaAVSessionOff(int64_t sessionId, int32_t eventType)
{
    auto session = GetSessionImpl(sessionId);
    if (session == nullptr) { return OHOS::AVSession::ERR_SESSION_NOT_EXIST; }
    return session->OffEvent(eventType);
}
}
