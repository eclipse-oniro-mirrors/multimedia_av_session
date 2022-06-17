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
#include "callback/napi_sessionlistener_callback.h"

namespace OHOS::AVSession {
NapiSessionListenerCallback::NapiSessionListenerCallback()
{
    SLOGI("NapiSessionListenerCallback::Constructor");
}

NapiSessionListenerCallback::~NapiSessionListenerCallback()
{
    SLOGI("NapiSessionListenerCallback::Destructor");
}

void NapiSessionListenerCallback::OnSessionCreate(const AVSessionDescriptor& descriptor)
{
    SLOGI("NapiSessionListenerCallback::OnSessionCreate");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiSessionListenerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiSessionListenerCallback->sessionCreate_callback_ == nullptr) {
                SLOGE("NapiSessionListenerCallback::OnSessionCreate no sessionCreate_callback_");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiSessionListenerCallback->sessionCreate_callback_, &callback);
            return callback;
        },
        [descriptor](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            AVSessionNapiUtils::WrapAVSessionDescriptorToNapi(env, descriptor, argv[0]);
        });
}

void NapiSessionListenerCallback::OnSessionRelease(const AVSessionDescriptor& descriptor)
{
    SLOGI("NapiSessionListenerCallback::OnSessionRelease");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiSessionListenerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiSessionListenerCallback->sessionReleased_callback_ == nullptr) {
                SLOGE("NapiSessionListenerCallback::OnSessionRelease no sessionReleased_callback_");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiSessionListenerCallback->sessionReleased_callback_, &callback);
            return callback;
        },
        [descriptor](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            AVSessionNapiUtils::WrapAVSessionDescriptorToNapi(env, descriptor, argv[0]);
        });
}

void NapiSessionListenerCallback::OnTopSessionChanged(const AVSessionDescriptor& descriptor)
{
    SLOGI("NapiSessionListenerCallback::OnTopSessionChanged");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiSessionListenerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiSessionListenerCallback->topSessionChanged_callback_ == nullptr) {
                SLOGE("NapiSessionListenerCallback::OnTopSessionChanged no topSessionChanged_callback_");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiSessionListenerCallback->topSessionChanged_callback_, &callback);
            return callback;
        },
        [descriptor](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            AVSessionNapiUtils::WrapAVSessionDescriptorToNapi(env, descriptor, argv[0]);
        });
}

void NapiSessionListenerCallback::OnSessionServiceDied()
{
    SLOGI("NapiSessionListenerCallback::OnSessionServiceDied");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiSessionListenerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiSessionListenerCallback->sessionServiceDied_callback_ == nullptr) {
                SLOGE("NapiSessionListenerCallback::OnSessionServiceDied no sessionServiceDied_callback_");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiSessionListenerCallback->sessionServiceDied_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiSessionListenerCallback::SaveCallbackReference(const std::string& callbackName, napi_value args, napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callback = nullptr;
    napi_status status = napi_create_reference(env, args, 1, &callback);
    env_ = env;
    uvQueue_ = std::make_shared<UvQueue>(env);
    if (status == napi_ok) {
        if (!callbackName.compare(SESSIONCREATED_CALLBACK)) {
            sessionCreate_callback_ = callback;
        } else if (!callbackName.compare(SESSIONRELEASED_CALLBACK)) {
            sessionReleased_callback_ = callback;
        } else if (!callbackName.compare(TOPSESSIONCHANGED_CALLBACK)) {
            topSessionChanged_callback_ = callback;
        } else if (!callbackName.compare(SESSIONSERVICEDIED_CALLBACK)) {
            sessionServiceDied_callback_ = callback;
            AVSessionManager::RegisterServiceDeathCallback(
                std::bind(&NapiSessionListenerCallback::OnSessionServiceDied, shared_from_this()));
        }
    }
}

void NapiSessionListenerCallback::ReleaseCallbackReference(const std::string& callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callbackName.compare(SESSIONCREATED_CALLBACK)) {
        sessionCreate_callback_ = nullptr;
    } else if (!callbackName.compare(SESSIONRELEASED_CALLBACK)) {
        sessionReleased_callback_ = nullptr;
    } else if (!callbackName.compare(TOPSESSIONCHANGED_CALLBACK)) {
        topSessionChanged_callback_ = nullptr;
    } else if (!callbackName.compare(SESSIONSERVICEDIED_CALLBACK)) {
        sessionServiceDied_callback_ = nullptr;
        AVSessionManager::UnregisterServiceDeathCallback();
    }
}
}