/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                SLOGI("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
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
        asyncCallback_->Call(*ref, [firstParam, secondParam](napi_env env, int& argc, napi_value *argv) {
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
        asyncCallback_->Call(*ref, [firstParam, secondParam](napi_env env, int& argc, napi_value *argv) {
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
        asyncCallback_->Call(*ref, [firstParam, secondParam, thirdParam](napi_env env, int& argc, napi_value *argv) {
            argc = NapiUtils::ARGC_TWO;
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
        asyncCallback_->Call(*ref, [errorCode, errorMsg](napi_env env, int& argc, napi_value *argv) {
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

void NapiAVCastControllerCallback::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnPlayerError");
    SLOGI("Start handle OnPlayerError event");
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
    HandleEvent(EVENT_KEY_REQUEST, assetId, keyRequestData);
}

void NapiAVCastControllerCallback::OnCastValidCommandChanged(const std::vector<int32_t>& cmds)
{
    SLOGI("Start handle OnValidCommandChanged event. cmd size:%{public}zd", cmds.size());
    std::vector<std::string> stringCmds = NapiCastControlCommand::ConvertCommands(cmds);
    HandleEvent(EVENT_CAST_VALID_COMMAND_CHANGED, stringCmds);
}

napi_status NapiAVCastControllerCallback::AddCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
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
    SLOGI("add callback with ref %{public}d, %{public}p, %{public}p", event, &ref, *(&ref));
    callbacks_[event].push_back(ref);
    if (event == EVENT_CAST_PLAYBACK_STATE_CHANGE) {
        isValid_ = std::make_shared<bool>(true);
    }
    return napi_ok;
}

napi_status NapiAVCastControllerCallback::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    SLOGI("try remove callback for event %{public}d", event);
    if (callback == nullptr) {
        SLOGD("Remove callback, the callback is nullptr");
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(ret == napi_ok, ret, "delete callback reference failed");
            *callbackRef = nullptr;
        }
        callbacks_[event].clear();
        if (event == EVENT_CAST_PLAYBACK_STATE_CHANGE) {
            if (isValid_ == nullptr) {
                SLOGE("remove callback with never listen on");
                return napi_ok;
            }
            *isValid_ = false;
        }
        return napi_ok;
    }
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
        napi_generic_failure, "get callback reference failed");
    SLOGI("remove single callback with ref %{public}d, %{public}p, %{public}p", event, &ref, *(&ref));
    CHECK_AND_RETURN_RET_LOG(ref != nullptr, napi_ok, "callback has been remove");
    callbacks_[event].remove(ref);
    return napi_delete_reference(env, ref);
}

bool NapiAVCastControllerCallback::IsCallbacksEmpty(int32_t event)
{
    return callbacks_[event].empty();
}
} // namespace OHOS::AVSession
