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

#define CJGET_FFIDATA_AVSESSION OHOS::FFI::FFIData::GetData<OHOS::AVSession::CJAVSessionImpl>(sessionId)

extern "C" {
int32_t FfiMultimediaAVSessionSetAVMetaData(int64_t sessionId, CAVMetaData* data)
{
    if (data == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJGET_FFIDATA_AVSESSION->SetAVMetaData(*data);
}

int32_t FfiMultimediaAVSessionSetAVCallMetaData(int64_t sessionId, CAVCallMetaData* data)
{
    if (data == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJGET_FFIDATA_AVSESSION->SetAVCallMetaData(*data);
}

int32_t FfiMultimediaAVSessionSetAVCallState(int64_t sessionId, CAVCallState* state)
{
    if (state == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJGET_FFIDATA_AVSESSION->SetAVCallState(*state);
}

int32_t FfiMultimediaAVSessionSetAVPlaybackState(int64_t sessionId, CAVPlaybackState* state)
{
    if (state == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJGET_FFIDATA_AVSESSION->SetAVPlaybackState(*state);
}

int32_t FfiMultimediaAVSessionSetAVQueueItems(int64_t sessionId, CArray* items)
{
    if (items == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJGET_FFIDATA_AVSESSION->SetAVQueueItems(*items);
}

int32_t FfiMultimediaAVSessionSetAVQueueTitle(int64_t sessionId, char** title)
{
    if (title == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJGET_FFIDATA_AVSESSION->SetAVQueueTitle(*title);
}

int32_t FfiMultimediaAVSessionSetExtras(int64_t sessionId, CArray* extras)
{
    if (extras == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJGET_FFIDATA_AVSESSION->SetExtras(*extras);
}

int32_t FfiMultimediaAVSessionGetController(int64_t sessionId)
{
    return CJGET_FFIDATA_AVSESSION->GetController();
}

int32_t FfiMultimediaAVSessionGetOutputDevice(int64_t sessionId, COutputDeviceInfo* outputDeviceInfo)
{
    if (outputDeviceInfo == nullptr) { return OHOS::AVSession::ERR_INVALID_PARAM; }
    return CJGET_FFIDATA_AVSESSION->GetOutputDevice(*outputDeviceInfo);
}

int32_t FfiMultimediaAVSessionActivate(int64_t sessionId)
{
    return CJGET_FFIDATA_AVSESSION->Activate();
}

int32_t FfiMultimediaAVSessionDeactivate(int64_t sessionId)
{
    return CJGET_FFIDATA_AVSESSION->Deactivate();
}

int32_t FfiMultimediaAVSessionDestroy(int64_t sessionId)
{
    return CJGET_FFIDATA_AVSESSION->Destroy();
}

int32_t FfiMultimediaAVSessionStopCasting(int64_t sessionId)
{
    return CJGET_FFIDATA_AVSESSION->StopCasting();
}
}