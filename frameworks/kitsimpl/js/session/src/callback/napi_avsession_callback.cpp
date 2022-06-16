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
    SLOGD("NapiAVSessionCallback::Constructor");
}

NapiAVSessionCallback::~NapiAVSessionCallback()
{
    SLOGD("NapiAVSessionCallback::Destructor");
}

void NapiAVSessionCallback::OnPlay()
{
    SLOGD("NapiAVSessionCallback::OnPlay");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->play_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->play_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiAVSessionCallback::OnPause()
{
    SLOGD("NapiAVSessionCallback::OnPause");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->pause_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->pause_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiAVSessionCallback::OnStop()
{
    SLOGD("NapiAVSessionCallback::OnStop");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->stop_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->stop_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiAVSessionCallback::OnPlayNext()
{
    SLOGD("NapiAVSessionCallback::OnPlayNext");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->playnext_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->playnext_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiAVSessionCallback::OnPlayPrevious()
{
    SLOGD("NapiAVSessionCallback::OnPlayPrevious");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->playprevious_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->playprevious_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiAVSessionCallback::OnFastForward()
{
    SLOGD("NapiAVSessionCallback::OnFastForward");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->fastforward_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->fastforward_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiAVSessionCallback::OnRewind()
{
    SLOGD("NapiAVSessionCallback::OnRewind");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->rewind_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->rewind_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiAVSessionCallback::OnSeek(int64_t time)
{
    SLOGD("NapiAVSessionCallback::OnSeek");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->seek_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->seek_callback_, &callback);
            return callback;
        },
        [time](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            napi_create_int64(env, time, &argv[0]);
        });
}

void NapiAVSessionCallback::OnSetSpeed(int32_t speed)
{
    SLOGD("NapiAVSessionCallback::OnSetSpeed");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->setspeed_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->setspeed_callback_, &callback);
            return callback;
        },
        [speed](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            napi_create_int32(env, speed, &argv[0]);
        });
}

void NapiAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
    SLOGD("NapiAVSessionCallback::OnSetLoopMode");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->setloopmode_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->setloopmode_callback_, &callback);
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
            if (napiAVSessionCallback->togglefavorite_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->togglefavorite_callback_, &callback);
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
    uvQueue_->AsyncCall(
        [napiAVSessionCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVSessionCallback->mediakeyevent_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVSessionCallback->mediakeyevent_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) { argc = 0; });
}

void NapiAVSessionCallback::SaveCallbackReference(const std::string& callbackName, napi_value args, napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callback = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env, args, refCount, &callback);
    env_ = env;
    if (status == napi_ok) {
        if (!callbackName.compare(PLAY_CALLBACK)) {
            play_callback_ = callback;
        } else if (!callbackName.compare(PAUSE_CALLBACK)) {
            pause_callback_ = callback;
        } else if (!callbackName.compare(STOP_CALLBACK)) {
            stop_callback_ = callback;
        } else if (!callbackName.compare(PLAYNEXT_CALLBACK)) {
            playnext_callback_ = callback;
        } else if (!callbackName.compare(PLAYPREVIOUS_CALLBACK)) {
            playprevious_callback_ = callback;
        } else if (!callbackName.compare(FASTFORWARD_CALLBACK)) {
            fastforward_callback_ = callback;
        } else if (!callbackName.compare(REWIND_CALLBACK)) {
            rewind_callback_ = callback;
        } else if (!callbackName.compare(HANDLEKEYEVENT_CALLBACK)) {
            mediakeyevent_callback_ = callback;
        } else if (!callbackName.compare(SEEK_CALLBACK)) {
            seek_callback_ = callback;
        } else if (!callbackName.compare(SETSPEED_CALLBACK)) {
            setspeed_callback_ = callback;
        } else if (!callbackName.compare(SETLOOPMODE_CALLBACK)) {
            setloopmode_callback_ = callback;
        } else if (!callbackName.compare(TOGGLEFAVORITE_CALLBACK)) {
            togglefavorite_callback_ = callback;
        } else if (!callbackName.compare(OUTPUTDEVICECHANGED_CALLBACK)) {
            outputDeviceChanged_callback_ = callback;
        }
    }
}

void NapiAVSessionCallback::ReleaseCallbackReference(const std::string& callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callbackName.compare(PLAY_CALLBACK)) {
        play_callback_ = nullptr;
    } else if (!callbackName.compare(PAUSE_CALLBACK)) {
        pause_callback_ = nullptr;
    } else if (!callbackName.compare(STOP_CALLBACK)) {
        stop_callback_ = nullptr;
    } else if (!callbackName.compare(PLAYNEXT_CALLBACK)) {
        playnext_callback_ = nullptr;
    } else if (!callbackName.compare(PLAYPREVIOUS_CALLBACK)) {
        playprevious_callback_ = nullptr;
    } else if (!callbackName.compare(FASTFORWARD_CALLBACK)) {
        fastforward_callback_ = nullptr;
    } else if (!callbackName.compare(REWIND_CALLBACK)) {
        rewind_callback_ = nullptr;
    } else if (!callbackName.compare(HANDLEKEYEVENT_CALLBACK)) {
        mediakeyevent_callback_ = nullptr;
    } else if (!callbackName.compare(SEEK_CALLBACK)) {
        seek_callback_ = nullptr;
    } else if (!callbackName.compare(SETSPEED_CALLBACK)) {
        setspeed_callback_ = nullptr;
    } else if (!callbackName.compare(SETLOOPMODE_CALLBACK)) {
        setloopmode_callback_ = nullptr;
    } else if (!callbackName.compare(TOGGLEFAVORITE_CALLBACK)) {
        togglefavorite_callback_ = nullptr;
    } else if (!callbackName.compare(OUTPUTDEVICECHANGED_CALLBACK)) {
        outputDeviceChanged_callback_ = nullptr;
    }
}
}