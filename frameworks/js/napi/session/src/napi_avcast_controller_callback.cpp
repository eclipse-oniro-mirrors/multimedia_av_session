/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
        asyncCallback_->Call(*ref, [param](napi_env env, int& argc, napi_value *argv) {
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

void NapiAVCastControllerCallback::OnStateChange(const AVCastPlayerState& state)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnStateChange");
    HandleEvent(EVENT_CAST_STATE_CHANGE, state);
}

void NapiAVCastControllerCallback::OnVolumeChange(const int32_t volume)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnVolumeChange");
    HandleEvent(EVENT_CAST_VOLUME_CHANGE, volume);
}

void NapiAVCastControllerCallback::OnSeekDone(const int32_t seek)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnSeekDone");
    HandleEvent(EVENT_CAST_SEEK_DONE, seek);
}

void NapiAVCastControllerCallback::OnSpeedDone(const int32_t speed)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnSpeedDone");
    HandleEvent(EVENT_CAST_SPEED_DONE, speed);
}

void NapiAVCastControllerCallback::OnTimeUpdate(const int32_t time)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnTimeUpdate");
    HandleEvent(EVENT_CAST_TIME_UPDATE, time);
}

void NapiAVCastControllerCallback::OnError(const int32_t errorCode, const std::string& errorMsg)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastControllerCallback::OnError");
    HandleEvent(EVENT_CAST_ERROR, errorCode, errorMsg);
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
    callbacks_[event].push_back(ref);
    return napi_ok;
}

napi_status NapiAVCastControllerCallback::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callback == nullptr) {
        SLOGD("Remove callback, the callback is nullptr");
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(ret == napi_ok, ret, "delete callback reference failed");
        }
        callbacks_[event].clear();
        return napi_ok;
    }
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref != nullptr, napi_ok, "callback has been remove");
    callbacks_[event].remove(ref);
    return napi_delete_reference(env, ref);
}
}
