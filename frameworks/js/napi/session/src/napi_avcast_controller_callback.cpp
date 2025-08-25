/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_avcast_controller_callback.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "napi_control_command.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_media_description.h"
#include "napi_queue_item.h"
#include "napi_utils.h"
#include "napi_cast_control_command.h"

namespace OHOS::AVSession {
NapiAVCastControllerCallback::NapiAVCastControllerCallback()
{
    SLOGI("construct");
}

NapiAVCastControllerCallback::~NapiAVCastControllerCallback()
{
    if (dataSrcRef_ != nullptr) {
        napi_ref ref = dataSrcRef_;
        dataSrcRef_ = nullptr;
        napi_delete_reference(env_, ref);
    }
    SLOGI("destroy");
}

void NapiAVCastControllerCallback::HandleEvent(int32_t event)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->Call(*ref);
    }
}

std::function<bool()> NapiAVCastControllerCallback::CheckCallbackValid(int32_t event,
    const std::list<napi_ref>::iterator& ref)
{
    return [this, event, ref]() {
        std::lock_guard<std::mutex> lockGuard(lock_);
        if (callbacks_[event].empty()) {
            SLOGE("checkCallbackValid with empty list for event %{public}d", event);
            return false;
        }
        bool hasFunc = false;
        for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
            hasFunc = (ref == it ? true : hasFunc);
        }
        SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
        return hasFunc;
    };
}

template<typename T>
void NapiAVCastControllerCallback::HandleEvent(int32_t event, const T& param)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        SLOGI("call with flag for event %{public}d", event);
        asyncCallback_->CallWithFunc(*ref, isValid_, CheckCallbackValid(event, ref),
            [param](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_ONE;
                auto status = NapiUtils::SetValue(env, param, *argv);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
    }
}

template<typename T>
void NapiAVCastControllerCallback::HandleEvent(int32_t event, const std::string& firstParam, const T& secondParam)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_, CheckCallbackValid(event, ref),
            [firstParam, secondParam](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_TWO;
                auto status = NapiUtils::SetValue(env, firstParam, argv[0]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
                status = NapiUtils::SetValue(env, secondParam, argv[1]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
    }
}

template<typename T>
void NapiAVCastControllerCallback::HandleEvent(int32_t event, const int32_t firstParam, const T& secondParam)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_, CheckCallbackValid(event, ref),
            [firstParam, secondParam](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_TWO;
                auto status = NapiUtils::SetValue(env, firstParam, argv[0]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
                status = NapiUtils::SetValue(env, secondParam, argv[1]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
    }
}

void NapiAVCastControllerCallback::HandleEvent(int32_t event,
    const int32_t firstParam, const int32_t secondParam, const int32_t thirdParam)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_, CheckCallbackValid(event, ref),
            [firstParam, secondParam, thirdParam](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_THREE;
                auto status = NapiUtils::SetValue(env, firstParam, argv[NapiUtils::ARGV_FIRST]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
                status = NapiUtils::SetValue(env, secondParam, argv[NapiUtils::ARGV_SECOND]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
                status = NapiUtils::SetValue(env, thirdParam, argv[NapiUtils::ARGV_THIRD]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
    }
}

void NapiAVCastControllerCallback::HandleErrorEvent(int32_t event, const int32_t errorCode,
    const std::string& errorMsg)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_, CheckCallbackValid(event, ref),
            [errorCode, errorMsg](napi_env env, int& argc, napi_value *argv) {
                napi_status status = napi_create_object(env, argv);
                CHECK_RETURN_VOID((status == napi_ok) && (argv != nullptr), "create object failed");

                napi_value property = nullptr;
                status = NapiUtils::SetValue(env, errorCode, property);
                CHECK_RETURN_VOID((status == napi_ok) && (property != nullptr), "create property failed");
                status = napi_set_named_property(env, *argv, "code", property);
                CHECK_RETURN_VOID(status == napi_ok, "napi_set_named_property failed");

                status = NapiUtils::SetValue(env, errorMsg, property);
                CHECK_RETURN_VOID((status == napi_ok) && (property != nullptr), "create property failed");
                status = napi_set_named_property(env, *argv, "message", property);
                CHECK_RETURN_VOID(status == napi_ok, "napi_set_named_property failed");
            });
    }
}

void NapiAVCastControllerCallback::OnCastPlaybackStateChange(const AVPlaybackState& state)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnCastPlaybackStateChange");
    SLOGI("Start handle OnCastPlaybackStateChange event with state: %{public}d", state.GetState());
    HandleEvent(EVENT_CAST_PLAYBACK_STATE_CHANGE, state);
}

void NapiAVCastControllerCallback::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnMediaItemChange");
    SLOGI("Start handle OnMediaItemChange event");
    HandleEvent(EVENT_CAST_MEDIA_ITEM_CHANGE, avQueueItem);
}

void NapiAVCastControllerCallback::OnCustomData(const AAFwk::WantParams& data)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnCustomData");
    SLOGI("Start handle OnCustomData event");
    HandleEvent(EVENT_CAST_CUSTOM_DATA, data);
}

void NapiAVCastControllerCallback::OnPlayNext()
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnPlayNext");
    SLOGI("Start handle OnPlayNext event");
    HandleEvent(EVENT_CAST_PLAY_NEXT);
}

void NapiAVCastControllerCallback::OnPlayPrevious()
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnPlayPrevious");
    SLOGI("Start handle OnPlayPrevious event");
    HandleEvent(EVENT_CAST_PLAY_PREVIOUS);
}

void NapiAVCastControllerCallback::OnSeekDone(const int32_t seekNumber)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnSeekDone");
    SLOGI("Start handle OnSeekDone event");
    HandleEvent(EVENT_CAST_SEEK_DONE, seekNumber);
}

void NapiAVCastControllerCallback::OnVideoSizeChange(const int32_t width, const int32_t height)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnVideoSizeChange");
    SLOGI("Start handle OnVideoSizeChange event");
    HandleEvent(EVENT_CAST_VIDEO_SIZE_CHANGE, width, height);
}

void NapiAVCastControllerCallback::HandlePlayerErrorAPI13(const int32_t errorCode, const std::string& errorMsg)
{
    CastExtErrCodeAPI13 jsErr;
    if (CAST_GENERIC_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // Generic error
        jsErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(jsErr));
        HandleErrorEvent(EVENT_CAST_GENERIC_ERR, static_cast<int32_t>(jsErr), errorMsg);
    } else if (CAST_IO_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // Input/Output errors
        jsErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(jsErr));
        HandleErrorEvent(EVENT_CAST_IO_ERR, static_cast<int32_t>(jsErr), errorMsg);
    } else if (CAST_PARSING_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // Content parsing errors
        jsErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(jsErr));
        HandleErrorEvent(EVENT_CAST_PARSING_ERR, static_cast<int32_t>(jsErr), errorMsg);
    } else if (CAST_DECODE_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // Decoding errors
        jsErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(jsErr));
        HandleErrorEvent(EVENT_CAST_DECOD_EERR, static_cast<int32_t>(jsErr), errorMsg);
    } else if (CAST_RENDER_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // AudioRender errors
        jsErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(jsErr));
        HandleErrorEvent(EVENT_CAST_RENDER_ERR, static_cast<int32_t>(jsErr), errorMsg);
    } else if (CAST_DRM_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // DRM errors
        jsErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(jsErr));
        HandleErrorEvent(EVENT_CAST_DRM_ERR, static_cast<int32_t>(jsErr), errorMsg);
    } else {
        SLOGW("Can not match error code, use default");
        // If error not in map, need add error and should not return default ERROR_CODE_UNSPECIFIED.
        jsErr = CAST_GENERICERR_EXT_API13_UNSPECIFIED;
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(jsErr));
        HandleErrorEvent(EVENT_CAST_GENERIC_ERR, static_cast<int32_t>(jsErr), errorMsg);
    }
}

void NapiAVCastControllerCallback::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnPlayerError");
    SLOGI("Start handle OnPlayerError event");
    if (static_cast<MediaServiceErrCode>(errorCode) >= MSERR_NO_MEMORY &&
        static_cast<MediaServiceErrCode>(errorCode) <= MSERR_EXTEND_START) {
        MediaServiceExtErrCodeAPI9 jsErr;
        if (MSERRCODE_INFOS.count(static_cast<MediaServiceErrCode>(errorCode)) != 0 &&
            MSERRCODE_TO_EXTERRORCODEAPI9.count(static_cast<MediaServiceErrCode>(errorCode)) != 0) {
            jsErr = MSERRCODE_TO_EXTERRORCODEAPI9.at(static_cast<MediaServiceErrCode>(errorCode));
        } else {
            SLOGW("Can not match error code, use default");
            // If error not in map, need add error and should not return default MSERR_EXT_API9_IO.
            jsErr = MSERR_EXT_API9_IO;
        }
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(jsErr));
        HandleErrorEvent(EVENT_CAST_ERROR, static_cast<int32_t>(jsErr), errorMsg);
    } else {
        HandlePlayerErrorAPI13(errorCode, errorMsg);
    }
}

void NapiAVCastControllerCallback::OnEndOfStream(const int32_t isLooping)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnEndOfStream");
    SLOGI("Start handle OnEndOfStream event");
    HandleEvent(EVENT_CAST_END_OF_STREAM, isLooping);
}

void NapiAVCastControllerCallback::OnPlayRequest(const AVQueueItem& avQueueItem)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnPlayRequest");
    SLOGI("Start handle OnPlayRequest event");
    HandleEvent(EVENT_CAST_PLAY_REQUEST, avQueueItem);
}

void NapiAVCastControllerCallback::OnKeyRequest(const std::string &assetId, const std::vector<uint8_t> &keyRequestData)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnKeyRequest");
    SLOGI("Start handle OnKeyRequest event");
    HandleEvent(EVENT_CAST_KEY_REQUEST, assetId, keyRequestData);
}

void NapiAVCastControllerCallback::OnCastValidCommandChanged(const std::vector<int32_t>& cmds)
{
    SLOGI("Start handle OnValidCommandChanged event. cmd size:%{public}zd", cmds.size());
    std::vector<std::string> stringCmds = NapiCastControlCommand::ConvertCommands(cmds);
    HandleEvent(EVENT_CAST_VALID_COMMAND_CHANGED, stringCmds);
}

int32_t NapiAVCastControllerCallback::onDataSrcRead(const std::shared_ptr<AVSharedMemoryBase>& mem,
                                                    uint32_t length, int64_t pos, int32_t& result)
{
    SLOGI("napi onDataSrcRead length %{public}d", length);
    return readDataSrc(env_, mem, length, pos, result);
}

napi_status NapiAVCastControllerCallback::saveDataSrc(napi_env env, napi_value avQueueItem)
{
    napi_value fileSize;
    napi_value callback {};
    napi_status status = NapiQueueItem::GetDataSrc(env, avQueueItem, &fileSize, &callback);
    CHECK_RETURN(status == napi_ok, "GetDataSrc value failed", status);
    if (status != napi_ok) {
        SLOGI("no saveDataSrc, reset");
        return status;
    }

    napi_env preEnv = env_;
    env_ = env;
    if (dataSrcRef_ != nullptr) {
        napi_ref ref = dataSrcRef_;
        dataSrcRef_ = nullptr;
        napi_delete_reference(preEnv, ref);
    }
    status = napi_create_reference(env, callback, 1, &dataSrcRef_);
    CHECK_RETURN(status == napi_ok, "napi_create_reference failed", status);

    if (threadSafeReadDataSrcFunc_ == nullptr) {
        napi_value resourceName = nullptr;
        napi_create_string_utf8(env, "ThreadSafeFunction in NapiAVCastControllerCallback",
            NAPI_AUTO_LENGTH, &resourceName);
        napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 0, 1, nullptr, nullptr,
            nullptr, threadSafeReadDataSrcCb, &threadSafeReadDataSrcFunc_);
    }
    return napi_ok;
}

void NapiAVCastControllerCallback::threadSafeReadDataSrcCb(napi_env env, napi_value js_cb, void* context, void* data)
{
    std::shared_ptr<DataContextForThreadSafe> appData(static_cast<DataContextForThreadSafe*>(data),
        [](DataContextForThreadSafe* ptr) {
        delete ptr;
        ptr = nullptr;
    });

    napi_status status;
    napi_value global {};
    napi_get_global(env, &global);

    napi_value callback {};
    napi_get_reference_value(env, appData->callback, &callback);

    napi_value argv[3] = { nullptr };

    status = napi_create_external_arraybuffer(env, appData->buffer, appData->length,
        [](napi_env env, void *data, void *hint) {}, nullptr, &argv[NapiUtils::ARGV_FIRST]);
    CHECK_RETURN_VOID(status == napi_ok, "get napi_create_external_arraybuffer value failed");

    status = napi_create_uint32(env, appData->length, &argv[NapiUtils::ARGV_SECOND]);
    CHECK_RETURN_VOID(status == napi_ok, "get napi_create_uint32 value failed");

    status = napi_create_int64(env, appData->pos, &argv[NapiUtils::ARGV_THIRD]);
    CHECK_RETURN_VOID(status == napi_ok, "get napi_create_int64 value failed");

    napi_value result;
    status = napi_call_function(env, global, callback, NapiUtils::ARGC_THREE, argv, &result);
    if (status != napi_ok) {
        SLOGE("call function failed status=%{public}d.", status);
    }
    napi_get_value_int32(env, result, appData->result);

    appData->dataSrcSyncCond.notify_one();
    return;
}

int32_t NapiAVCastControllerCallback::readDataSrc(napi_env env, const std::shared_ptr<AVSharedMemoryBase>& mem,
    uint32_t length, int64_t pos, int32_t& result)
{
    if (dataSrcRef_ == nullptr) {
        SLOGE("dataSrcRef_ nullptr");
        return 0;
    }
    DataContextForThreadSafe* data =
        new DataContextForThreadSafe { dataSrcRef_, mem->GetBase(), length, pos, &result, dataSrcSyncCond_ };
    napi_status status = napi_call_threadsafe_function(threadSafeReadDataSrcFunc_, data, napi_tsfn_blocking);
    if (status != napi_ok) {
        SLOGE("readDataSrc function call failed %{public}d", status);
        delete data;
        return 0;
    }

    std::unique_lock<std::mutex> lock(dataSrcSyncLock_);
    auto waitStatus = dataSrcSyncCond_.wait_for(lock, std::chrono::milliseconds(500));
    if (waitStatus == std::cv_status::timeout) {
        SLOGE("readDataSrc dataSrcSyncCond_ timeout");
    }
    SLOGI("readDataSrc result %{public}d", result);
    return result;
}

napi_status NapiAVCastControllerCallback::AddCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_CAST_TYPE_MAX, napi_generic_failure, "has no event");
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
        napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref == nullptr, napi_ok, "callback has been registered");
    napi_status status = napi_create_reference(env, callback, NapiUtils::ARGC_ONE, &ref);
    if (status != napi_ok) {
        SLOGE("napi_create_reference failed");
        return status;
    }
    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<NapiAsyncCallback>(env);
        if (asyncCallback_ == nullptr) {
            SLOGE("no memory");
            return napi_generic_failure;
        }
    }
    SLOGI("addCallback isValidSet to prevent off, with ref %{public}d", event);
    callbacks_[event].push_back(ref);
    if (isValid_ == nullptr) {
        SLOGI("addCallback with no isValid_ init");
        isValid_ = std::make_shared<bool>(true);
    } else {
        SLOGI("addCallback with isValid_ set true");
        *isValid_ = true;
    }
    return napi_ok;
}

napi_status NapiAVCastControllerCallback::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    SLOGI("try remove callback for event %{public}d", event);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_CAST_TYPE_MAX, napi_generic_failure, "has no event");
    if (callback == nullptr) {
        SLOGD("Remove callback, the callback is nullptr");
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(ret == napi_ok, ret, "delete callback reference failed");
            *callbackRef = nullptr;
        }
        callbacks_[event].clear();
        // not remove this logic for play button will not valid when stopcast at media control second page
        SLOGE("RemoveCallback with isvalid set false when playbackstatechange off");
        if (event == EVENT_CAST_PLAYBACK_STATE_CHANGE) {
            if (isValid_ == nullptr) {
                SLOGE("remove callback with no isValid_ init");
                return napi_ok;
            }
            SLOGI("removeCallback with isValid_ set false");
            *isValid_ = false;
        }
        return napi_ok;
    }
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
        napi_generic_failure, "get callback reference failed");
    SLOGI("remove single callback with ref %{public}d", event);
    CHECK_AND_RETURN_RET_LOG(ref != nullptr, napi_ok, "callback has been remove");
    callbacks_[event].remove(ref);
    return napi_delete_reference(env, ref);
}

bool NapiAVCastControllerCallback::IsCallbacksEmpty(int32_t event)
{
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_CAST_TYPE_MAX, true, "has no event");
    return callbacks_[event].empty();
}
} // namespace OHOS::AVSession
