/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <memory>

#include "avsession_log.h"
#include "avsession_info.h"
#include "avsession_trace.h"
#include "napi_session_listener.h"

namespace OHOS::AVSession {
NapiSessionListener::NapiSessionListener()
{
    SLOGI("construct");
}

NapiSessionListener::~NapiSessionListener()
{
    SLOGI("destroy");
}

template<typename T>
void NapiSessionListener::HandleEvent(int32_t event, const T& param)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    for (auto& ref : callbacks_[event]) {
        asyncCallback_->Call(ref, [param](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            NapiUtils::SetValue(env, param, *argv);
        });
    }
}

void NapiSessionListener::OnSessionCreate(const AVSessionDescriptor& descriptor)
{
    AVSESSION_TRACE_SYNC_START("NapiSessionListener::OnSessionCreate");
    SLOGI("sessionId=%{public}s", descriptor.sessionId_.c_str());
    HandleEvent(EVENT_SESSION_CREATED, descriptor);
}

void NapiSessionListener::OnSessionRelease(const AVSessionDescriptor& descriptor)
{
    SLOGI("sessionId=%{public}s", descriptor.sessionId_.c_str());
    HandleEvent(EVENT_SESSION_DESTROYED, descriptor);
}

void NapiSessionListener::OnTopSessionChange(const AVSessionDescriptor& descriptor)
{
    AVSESSION_TRACE_SYNC_START("NapiSessionListener::OnTopSessionChange");
    SLOGI("sessionId=%{public}s", descriptor.sessionId_.c_str());
    HandleEvent(EVENT_TOP_SESSION_CHANGED, descriptor);
}

void NapiSessionListener::OnAudioSessionChecked(const int32_t uid)
{
    AVSESSION_TRACE_SYNC_START("NapiSessionListener::OnAudioSessionCheck");
    SLOGI("uid=%{public}d checked", uid);
    HandleEvent(EVENT_AUDIO_SESSION_CHECKED, uid);
}

void NapiSessionListener::OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo)
{
    AVSESSION_TRACE_SYNC_START("NapiSessionListener::OnDeviceAvailable");
    SLOGI("Start handle device found event");
    HandleEvent(EVENT_DEVICE_AVAILABLE, castOutputDeviceInfo);
}

napi_status NapiSessionListener::AddCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref == nullptr, napi_ok, "callback has been registered");
    napi_status status = napi_create_reference(env, callback, 1, &ref);
    if (status != napi_ok) {
        SLOGE("napi_create_reference failed");
        return status;
    }
    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<NapiAsyncCallback>(env);
    }
    callbacks_[event].push_back(ref);
    return napi_ok;
}

napi_status NapiSessionListener::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callback == nullptr) {
        for (auto& callbackRef : callbacks_[event]) {
            napi_status ret = napi_delete_reference(env, callbackRef);
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
}