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
#include "callback/napi_avsession_callback.h"

namespace OHOS::AVSession {
NapiAVSessionCallback::NapiAVSessionCallback()
{
    SLOGI("NapiAVSessionCallback::Constructor");
}

NapiAVSessionCallback::~NapiAVSessionCallback()
{
    SLOGI("NapiAVSessionCallback::Destructor");
}

void NapiAVSessionCallback::OnPlay()
{
    SLOGI("NapiAVSessionCallback::OnPlay");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[PLAY_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[PLAY_CALLBACK], &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiAVSessionCallback::OnPause()
{
    SLOGI("NapiAVSessionCallback::OnPause");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[PAUSE_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[PAUSE_CALLBACK], &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiAVSessionCallback::OnStop()
{
    SLOGD("NapiAVSessionCallback::OnStop");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[STOP_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[STOP_CALLBACK], &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiAVSessionCallback::OnPlayNext()
{
    SLOGD("NapiAVSessionCallback::OnPlayNext");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[PLAYNEXT_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[PLAYNEXT_CALLBACK], &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiAVSessionCallback::OnPlayPrevious()
{
    SLOGD("NapiAVSessionCallback::OnPlayPrevious");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[PLAYPREVIOUS_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[PLAYPREVIOUS_CALLBACK], &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiAVSessionCallback::OnFastForward()
{
    SLOGD("NapiAVSessionCallback::OnFastForward");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[FASTFORWARD_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[FASTFORWARD_CALLBACK], &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiAVSessionCallback::OnRewind()
{
    SLOGD("NapiAVSessionCallback::OnRewind");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[REWIND_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[REWIND_CALLBACK], &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiAVSessionCallback::OnSeek(int64_t time)
{
    SLOGD("NapiAVSessionCallback::OnSeek");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[SEEK_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[SEEK_CALLBACK], &callback);
            return callback;
        },
        [time](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            napi_create_int64(env, time, &argv[0]);
        });
}

void NapiAVSessionCallback::OnSetSpeed(double speed)
{
    SLOGD("NapiAVSessionCallback::OnSetSpeed");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[SETSPEED_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[SETSPEED_CALLBACK], &callback);
            return callback;
        },
        [speed](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            napi_create_double(env, speed, &argv[0]);
        });
}

void NapiAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
    SLOGD("NapiAVSessionCallback::OnSetLoopMode");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[SETLOOPMODE_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[SETLOOPMODE_CALLBACK], &callback);
            return callback;
        },
        [loopMode](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            napi_create_int32(env, loopMode, &argv[0]);
        });
}

void NapiAVSessionCallback::OnToggleFavorite(const std::string& mediald)
{
    SLOGD("NapiAVSessionCallback::OnToggleFavorite");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[TOGGLEFAVORITE_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[TOGGLEFAVORITE_CALLBACK], &callback);
            return callback;
        },
        [mediald](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            napi_create_string_utf8(env, mediald.c_str(), NAPI_AUTO_LENGTH, &argv[0]);
        });
}

void NapiAVSessionCallback::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    SLOGD("NapiAVSessionCallback::OnMediaKeyEvent");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    keyEvent_ = std::shared_ptr<MMI::KeyEvent>(new (std::nothrow) MMI::KeyEvent(keyEvent));
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->bindCallbackMap[HANDLEKEYEVENT_CALLBACK] == nullptr) {
                SLOGE("NapiAVSessionCallback::OnMediaKeyEvent callback is null");
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->bindCallbackMap[HANDLEKEYEVENT_CALLBACK], &callback);
            return callback;
        },
        [napiAVSessionCallback = shared_from_this()](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            AVSessionNapiUtils::WrapKeyEventToNapi(env, napiAVSessionCallback->keyEvent_, argv[0]);
        });
}

void NapiAVSessionCallback::SaveCallbackReference(const std::string& callbackName, napi_value args, napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callback = nullptr;
    napi_status status = napi_create_reference(env, args, 1, &callback);
    env_ = env;
    CHECK_AND_RETURN_LOG(status == napi_ok && callback != nullptr , "get callback fail ");
    CHECK_AND_RETURN_LOG(bindCallbackMap.count(callbackName) != 0, "The callbackName parameter is invalid ");
    bindCallbackMap[callbackName] = callback ;
}

void NapiAVSessionCallback::ReleaseCallbackReference(const std::string& callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(bindCallbackMap.count(callbackName) != 0, "The callbackName parameter is invalid ");
    napi_delete_reference(env_, bindCallbackMap[callbackName]);
}

bool NapiAVSessionCallback::hasCallback(const std::string& callbackName)
{
    return bindCallbackMap.count(callbackName) != 0 ;
}
}