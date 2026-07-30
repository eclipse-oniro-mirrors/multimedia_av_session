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

#include "cj_avsession_cast_controller_callback.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "cj_avsession_utils.h"
namespace OHOS::AVSession {

static void FreeCallbackDataInternal(CCallbackData* callbackData)
{
    if (callbackData == nullptr) { return; }
    if (callbackData->data != nullptr) {
        free(callbackData->data);
        callbackData->data = nullptr;
    }
    free(callbackData);
}

template<class T, class CT> CCallbackData* convertToCallbackData(
    const T& native, int32_t eventType, bool convert = true)
{
    CCallbackData *callbackData = static_cast<CCallbackData *>(malloc(sizeof(CCallbackData)));
    if (callbackData == nullptr) { return nullptr; }
    callbackData->kind = eventType;
    if (!convert) {
        callbackData->error = CJNO_ERROR;
        callbackData->data = nullptr;
        return callbackData;
    }
    CT* cData = static_cast<CT *>(malloc(sizeof(CT)));
    if (cData == nullptr) {
        callbackData->error = ERR_NO_MEMORY;
        callbackData->data = nullptr;
        return callbackData;
    }
    callbackData->error = ConvertNativeToCJStruct(native, *cData);
    if (callbackData->error != CJNO_ERROR) {
        cjStructHeapFree(*cData);
        free(cData);
        cData = nullptr;
    }
    callbackData->data = static_cast<void *>(cData);
    return callbackData;
}

template<class T, class CT, class T2, class CT2> CCallbackData* convertToCallbackData(
    const T& native, const T2& native2, int32_t eventType)
{
    CCallbackData *callbackData = static_cast<CCallbackData *>(malloc(sizeof(CCallbackData)));
    if (callbackData == nullptr) { return nullptr; }
    callbackData->kind = eventType;
    CT* cData = static_cast<CT *>(malloc(sizeof(CT)));
    if (cData == nullptr) {
        callbackData->error = ERR_NO_MEMORY;
        callbackData->data = nullptr;
        callbackData->data2 = nullptr;
        return callbackData;
    }
    callbackData->error = ConvertNativeToCJStruct(native, *cData);
    if (callbackData->error != CJNO_ERROR) {
        cjStructHeapFree(*cData);
        free(cData);
        callbackData->data = nullptr;
        callbackData->data2 = nullptr;
        return callbackData;
    }
    callbackData->data = static_cast<void *>(cData);
    CT2* cData2 = static_cast<CT2 *>(malloc(sizeof(CT2)));
    if (cData2 == nullptr) {
        callbackData->error = ERR_NO_MEMORY;
        cjStructHeapFree(*cData);
        free(cData);
        callbackData->data = nullptr;
        callbackData->data2 = nullptr;
        return callbackData;
    }
    callbackData->error = ConvertNativeToCJStruct(native2, *cData2);
    callbackData->data2 = static_cast<void *>(cData2);
    return callbackData;
}

CCallbackData* convertToCallbackData(int32_t eventType)
{
    int32_t nothing = 0;
    return convertToCallbackData<int32_t, int32_t>(nothing, eventType, false);
}

template<class CT> void freeCallbackData(CCallbackData* callbackData)
{
    FreeCallbackDataInternal(callbackData);
}

template<class CT, class CT2> void freeCallbackData(CCallbackData* callbackData)
{
    if (callbackData == nullptr) { return; }
    if (callbackData->data != nullptr) {
        free(static_cast<CT *>(callbackData->data));
        callbackData->data = nullptr;
    }
    if (callbackData->data2 != nullptr) {
        free(static_cast<CT2 *>(callbackData->data2));
        callbackData->data2 = nullptr;
    }
    free(callbackData);
}

CJAVCastControllerCallback::CJAVCastControllerCallback()
{
    doCall_ = [](CCallbackData* data) {
        SLOGE("Callback of CJAVCastControllerCallback is not initialized yet!");
        FreeCallbackDataInternal(data);
    };
}

void CJAVCastControllerCallback::AddCallback(DoCallFunc doCall)
{
    doCall_ = doCall;
}

void CJAVCastControllerCallback::OnCastPlaybackStateChange(const AVPlaybackState& state)
{
    CCallbackData* callbackData = convertToCallbackData<AVPlaybackState, CAVPlaybackState>(
        state, EVENT_CAST_PLAYBACK_STATE_CHANGE);
    doCall_(callbackData);
    if (callbackData != nullptr && callbackData->data != nullptr) {
        cjStructHeapFree(*static_cast<CAVPlaybackState*>(callbackData->data));
    }
    FreeCallbackDataInternal(callbackData);
}

void CJAVCastControllerCallback::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    CCallbackData* callbackData = convertToCallbackData<AVQueueItem, CAVQueueItem>(
        avQueueItem, EVENT_CAST_MEDIA_ITEM_CHANGE);
    doCall_(callbackData);
    if (callbackData != nullptr && callbackData->data != nullptr) {
        cjStructHeapFree(*static_cast<CAVQueueItem*>(callbackData->data));
    }
    FreeCallbackDataInternal(callbackData);
}

void CJAVCastControllerCallback::OnPlayNext()
{
    CCallbackData* callbackData = convertToCallbackData(EVENT_CAST_PLAY_NEXT);
    doCall_(callbackData);
    free(callbackData);
}

void CJAVCastControllerCallback::OnPlayPrevious()
{
    CCallbackData* callbackData = convertToCallbackData(EVENT_CAST_PLAY_PREVIOUS);
    doCall_(callbackData);
    free(callbackData);
}

void CJAVCastControllerCallback::OnSeekDone(const int32_t seekNumber)
{
    CCallbackData* callbackData = convertToCallbackData<int32_t, int32_t>(
        seekNumber, EVENT_CAST_SEEK_DONE);
    doCall_(callbackData);
    freeCallbackData<int32_t>(callbackData);
}

void CJAVCastControllerCallback::OnVideoSizeChange(const int32_t width, const int32_t height)
{}

void CJAVCastControllerCallback::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{
    CCallbackData* callbackData = convertToCallbackData<std::string, char*>(
        errorMsg, EVENT_CAST_ERROR);
    if (callbackData != nullptr) { callbackData->error = errorCode; }
    doCall_(callbackData);
    if (callbackData != nullptr && callbackData->data != nullptr) {
        cjStructHeapFree(*static_cast<char**>(callbackData->data));
    }
    FreeCallbackDataInternal(callbackData);
}

void CJAVCastControllerCallback::OnEndOfStream(const int32_t isLooping)
{
    CCallbackData* callbackData = convertToCallbackData<int32_t, int32_t>(
        isLooping, EVENT_CAST_END_OF_STREAM);
    doCall_(callbackData);
    freeCallbackData<int32_t>(callbackData);
}

void CJAVCastControllerCallback::OnPlayRequest(const AVQueueItem& avQueueItem)
{
    CCallbackData* callbackData = convertToCallbackData<AVQueueItem, CAVQueueItem>(
        avQueueItem, EVENT_CAST_REQUEST_PLAY);
    doCall_(callbackData);
    if (callbackData != nullptr && callbackData->data != nullptr) {
        cjStructHeapFree(*static_cast<CAVQueueItem*>(callbackData->data));
    }
    FreeCallbackDataInternal(callbackData);
}

void CJAVCastControllerCallback::OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData)
{
    CCallbackData* callbackData = convertToCallbackData<std::string, char*, std::vector<uint8_t>, CArray>(
        assetId, keyRequestData, EVENT_CAST_KEY_REQUEST);
    doCall_(callbackData);
    if (callbackData != nullptr && callbackData->data != nullptr) {
        cjStructHeapFree(*static_cast<char**>(callbackData->data));
    }
    if (callbackData != nullptr && callbackData->data2 != nullptr) {
        cjStructHeapFree(*static_cast<CArray*>(callbackData->data2));
    }
    freeCallbackData<char*, CArray>(callbackData);
}

void CJAVCastControllerCallback::OnCastValidCommandChanged(const std::vector<int32_t> &cmds)
{
    CCallbackData* callbackData = convertToCallbackData<std::vector<int32_t>, CArray>(
        cmds, EVENT_CAST_VALID_COMMAND_CHANGED);
    doCall_(callbackData);
    if (callbackData != nullptr && callbackData->data != nullptr) {
        cjStructHeapFree(*static_cast<CArray*>(callbackData->data));
    }
    FreeCallbackDataInternal(callbackData);
}

} // namespace AVSession::OHOS
