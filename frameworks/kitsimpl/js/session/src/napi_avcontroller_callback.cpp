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
#include "napi_avcontroller_callback.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_utils.h"

namespace OHOS::AVSession {
NapiAVControllerCallback::NapiAVControllerCallback()
{
    SLOGI("construct");
}

NapiAVControllerCallback::~NapiAVControllerCallback()
{
    SLOGI("destroy");
}

void NapiAVControllerCallback::OnSessionDestroy()
{
    if (callbacks_[EVENT_SESSION_DESTROY] == nullptr) {
        SLOGE("not register callback event=%{public}d", EVENT_SESSION_DESTROY);
        return;
    }

    asyncCallback_->Call(callbacks_[EVENT_SESSION_DESTROY]);
}

void NapiAVControllerCallback::OnPlaybackStateChange(const AVPlaybackState& state)
{
    if (callbacks_[EVENT_PLAYBACK_STATE_CHANGE] == nullptr) {
        SLOGE("not register callback event=%{public}d", EVENT_PLAYBACK_STATE_CHANGE);
        return;
    }

    auto getter = [state](napi_env env, int &argc, napi_value *argv) {
        argc = 1;
        NapiPlaybackState::SetValue(env, state, *argv);
    };
    asyncCallback_->Call(callbacks_[EVENT_PLAYBACK_STATE_CHANGE], getter);
}

void NapiAVControllerCallback::OnMetaDataChange(const AVMetaData& data)
{
    if (callbacks_[EVENT_META_DATA_CHANGE] == nullptr) {
        SLOGE("not register callback event=%{public}d", EVENT_META_DATA_CHANGE);
        return;
    }

    auto getter = [data](napi_env env, int &argc, napi_value *argv) {
        argc = 1;
        NapiMetaData::SetValue(env, data, *argv);
    };
    asyncCallback_->Call(callbacks_[EVENT_META_DATA_CHANGE], getter);
}

void NapiAVControllerCallback::OnActiveStateChange(bool isActive)
{
    if (callbacks_[EVENT_ACTIVE_STATE_CHANGE] == nullptr) {
        SLOGE("not register callback event=%{public}d", EVENT_ACTIVE_STATE_CHANGE);
        return;
    }

    auto getter = [isActive](napi_env env, int &argc, napi_value *argv) {
        argc = 1;
        NapiUtils::SetValue(env, isActive, *argv);
    };
    asyncCallback_->Call(callbacks_[EVENT_ACTIVE_STATE_CHANGE], getter);
}

void NapiAVControllerCallback::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    if (callbacks_[EVENT_VALID_COMMAND_CHANGE] == nullptr) {
        SLOGE("not register callback event=%{public}d", EVENT_VALID_COMMAND_CHANGE);
        return;
    }

    auto getter = [cmds](napi_env env, int &argc, napi_value *argv) {
        argc = 1;
        NapiUtils::SetValue(env, cmds, *argv);
    };
    asyncCallback_->Call(callbacks_[EVENT_VALID_COMMAND_CHANGE], getter);
}

napi_status NapiAVControllerCallback::AddCallback(napi_env env, int32_t event, napi_value callback)
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

napi_status NapiAVControllerCallback::RemoveCallback(napi_env env, int32_t event)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto ref = callbacks_[event];
    callbacks_[event] = nullptr;
    return napi_delete_reference(env, ref);
}
}