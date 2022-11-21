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

#include "napi_avsession_callback.h"
#include "avsession_log.h"
#include "napi_utils.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
NapiAVSessionCallback::NapiAVSessionCallback()
{
    SLOGI("construct");
}

NapiAVSessionCallback::~NapiAVSessionCallback()
{
    SLOGI("destroy");
}

void NapiAVSessionCallback::HandleEvent(int32_t event)
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
void NapiAVSessionCallback::HandleEvent(int32_t event, const T& param)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->Call(*ref, [param](napi_env env, int& argc, napi_value* argv) {
            argc = NapiUtils::ARGC_ONE;
            NapiUtils::SetValue(env, param, *argv);
        });
    }
}

void NapiAVSessionCallback::OnPlay()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlay");
    HandleEvent(EVENT_PLAY);
}

void NapiAVSessionCallback::OnPause()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPause");
    HandleEvent(EVENT_PAUSE);
}

void NapiAVSessionCallback::OnStop()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnStop");
    HandleEvent(EVENT_STOP);
}

void NapiAVSessionCallback::OnPlayNext()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayNext");
    HandleEvent(EVENT_PLAY_NEXT);
}

void NapiAVSessionCallback::OnPlayPrevious()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayPrevious");
    HandleEvent(EVENT_PLAY_PREVIOUS);
}

void NapiAVSessionCallback::OnFastForward()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnFastForward");
    HandleEvent(EVENT_FAST_FORWARD);
}

void NapiAVSessionCallback::OnRewind()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnRewind");
    HandleEvent(EVENT_REWIND);
}

void NapiAVSessionCallback::OnSeek(int64_t time)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSeek");
    HandleEvent(EVENT_SEEK, time);
}

void NapiAVSessionCallback::OnSetSpeed(double speed)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSetSpeed");
    HandleEvent(EVENT_SET_SPEED, speed);
}

void NapiAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSetLoopMode");
    HandleEvent(EVENT_SET_LOOP_MODE, loopMode);
}

void NapiAVSessionCallback::OnToggleFavorite(const std::string& assertId)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnToggleFavorite");
    HandleEvent(EVENT_TOGGLE_FAVORITE, assertId);
}

void NapiAVSessionCallback::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnMediaKeyEvent");
    HandleEvent(EVENT_MEDIA_KEY_EVENT, std::make_shared<MMI::KeyEvent>(keyEvent));
}

void NapiAVSessionCallback::OnOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnOutputDeviceChange");
    HandleEvent(EVENT_OUTPUT_DEVICE_CHANGE, outputDeviceInfo);
}

napi_status NapiAVSessionCallback::AddCallback(napi_env env, int32_t event, napi_value callback)
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

napi_status NapiAVSessionCallback::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callback == nullptr) {
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(napi_ok == ret, ret, "delete callback reference failed");
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

bool NapiAVSessionCallback::IsCallbacksEmpty(int32_t event)
{
    return callbacks_[event].empty();
}
}