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

#include "avsession_log.h"
#include "napi_avsession_callback.h"

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
    if (callbacks_[event] == nullptr) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }

    asyncCallback_->Call(callbacks_[event]);
}

void NapiAVSessionCallback::OnPlay()
{
    HandleEvent(EVENT_PLAY);
}

void NapiAVSessionCallback::OnPause()
{
    HandleEvent(EVENT_PAUSE);
}

void NapiAVSessionCallback::OnStop()
{
    HandleEvent(EVENT_STOP);
}

void NapiAVSessionCallback::OnPlayNext()
{
    HandleEvent(EVENT_PLAY_NEXT);
}

void NapiAVSessionCallback::OnPlayPrevious()
{
    HandleEvent(EVENT_PLAY_PREVIOUS);
}

void NapiAVSessionCallback::OnFastForward()
{
    HandleEvent(EVENT_FAST_FORWARD);
}

void NapiAVSessionCallback::OnRewind()
{
    HandleEvent(EVENT_REWIND);
}

void NapiAVSessionCallback::OnSeek(int64_t time)
{
}

void NapiAVSessionCallback::OnSetSpeed(double speed)
{
}

void NapiAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
}

void NapiAVSessionCallback::OnToggleFavorite(const std::string &assertId)
{
}

void NapiAVSessionCallback::OnMediaKeyEvent(const MMI::KeyEvent &keyEvent)
{
}

napi_status NapiAVSessionCallback::AddCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    napi_ref ref = nullptr;
    napi_status status = napi_create_reference(env, callback, 1, &ref);
    if (status != napi_ok) {
        SLOGE("napi_create_reference failed");
        return status;
    }
    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<NapiAsyncCallback>(env);
    }
    callbacks_[event] = ref;
    return napi_ok;
}

napi_status NapiAVSessionCallback::RemoveCallback(napi_env env, int32_t event)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto ref = callbacks_[event];
    callbacks_[event] = nullptr;
    return napi_delete_reference(env, ref);
}
}