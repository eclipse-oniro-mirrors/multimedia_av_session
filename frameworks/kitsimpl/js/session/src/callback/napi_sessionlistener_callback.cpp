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
            if (napiSessionListenerCallback->bindCallbackMap[SESSIONCREATED_CALLBACK] == nullptr) {
                SLOGE("sessionCreate_callback is nullptr");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiSessionListenerCallback->bindCallbackMap[SESSIONCREATED_CALLBACK],
                                     &callback);
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
            if (napiSessionListenerCallback->bindCallbackMap[SESSIONRELEASED_CALLBACK] == nullptr) {
                SLOGE("sessionReleased_callback is nullptr");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiSessionListenerCallback->bindCallbackMap[SESSIONRELEASED_CALLBACK],
                                     &callback);
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
            if (napiSessionListenerCallback->bindCallbackMap[TOPSESSIONCHANGED_CALLBACK] == nullptr) {
                SLOGE("topSessionChanged_callback is nullptr");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiSessionListenerCallback->bindCallbackMap[TOPSESSIONCHANGED_CALLBACK],
                                     &callback);
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
            if (napiSessionListenerCallback->bindCallbackMap[SESSIONSERVICEDIED_CALLBACK] == nullptr) {
                SLOGE("sessionServiceDied_callback is nullptr");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiSessionListenerCallback->bindCallbackMap[SESSIONSERVICEDIED_CALLBACK],
                                     &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiSessionListenerCallback::SaveCallbackReference(const std::string& callbackName, napi_value args, napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callback = nullptr;
    napi_status status = napi_create_reference(env, args, 1, &callback);
    env_ = env;
    CHECK_AND_RETURN_LOG(status == napi_ok && callback != nullptr, "get callback fail ");
    CHECK_AND_RETURN_LOG(bindCallbackMap.count(callbackName) != 0, "The callbackName parameter is invalid ");
    bindCallbackMap[callbackName] = callback ;
    if (!SESSIONSERVICEDIED_CALLBACK.compare(callbackName)) {
        AVSessionManager::RegisterServiceDeathCallback(
            std::bind(&NapiSessionListenerCallback::OnSessionServiceDied, shared_from_this()));
    }
}

void NapiSessionListenerCallback::ReleaseCallbackReference(const std::string& callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(bindCallbackMap.count(callbackName) != 0, "The callbackName parameter is invalid ");
    napi_delete_reference(env_, bindCallbackMap[callbackName]);
    if (!SESSIONSERVICEDIED_CALLBACK.compare(callbackName)) {
        AVSessionManager::UnregisterServiceDeathCallback();
    }
}

bool NapiSessionListenerCallback::hasCallback(const std::string& callbackName)
{
    return bindCallbackMap.count(callbackName) != 0 ;
}
}