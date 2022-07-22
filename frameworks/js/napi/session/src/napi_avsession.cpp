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

#include "napi_avsession.h"
#include "avsession_controller.h"
#include "napi_async_work.h"
#include "napi_utils.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "want_agent.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
static __thread napi_ref AVSessionConstructorRef = nullptr;
std::map<std::string, NapiAVSession::OnEventHandlerType> NapiAVSession::onEventHandlers_ = {
    { "play", OnPlay },
    { "pause", OnPause },
    { "stop", OnStop },
    { "playNext", OnPlayNext },
    { "playPrevious", OnPlayPrevious },
    { "fastForward", OnFastForward },
    { "rewind", OnRewind },
    { "seek", OnSeek },
    { "setSpeed", OnSetSpeed },
    { "setLoopMode", OnSetLoopMode },
    { "toggleFavorite", OnToggleFavorite },
    { "handleKeyEvent", OnMediaKeyEvent },
    { "outputDeviceChange", OnOutputDeviceChange },
};
std::map<std::string, NapiAVSession::OffEventHandlerType> NapiAVSession::offEventHandlers_ = {
    { "play", OffPlay },
    { "pause", OffPause },
    { "stop", OffStop },
    { "playNext", OffPlayNext },
    { "playPrevious", OffPlayPrevious },
    { "fastForward", OffFastForward },
    { "rewind", OffRewind },
    { "seek", OffSeek },
    { "setSpeed", OffSetSpeed },
    { "setLoopMode", OffSetLoopMode },
    { "toggleFavorite", OffToggleFavorite },
    { "handleKeyEvent", OffMediaKeyEvent },
    { "outputDeviceChange", OffOutputDeviceChange }
};

NapiAVSession::NapiAVSession()
{
    SLOGI("construct");
}

NapiAVSession::~NapiAVSession()
{
    SLOGI("destroy");
}

napi_value NapiAVSession::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("setAVMetadata", SetAVMetaData),
        DECLARE_NAPI_FUNCTION("setAVPlaybackState", SetAVPlaybackState),
        DECLARE_NAPI_FUNCTION("setLaunchAbility", SetLaunchAbility),
        DECLARE_NAPI_FUNCTION("setAudioStreamId", SetAudioStreamId),
        DECLARE_NAPI_FUNCTION("getController", GetController),
        DECLARE_NAPI_FUNCTION("activate", Activate),
        DECLARE_NAPI_FUNCTION("deactivate", Deactivate),
        DECLARE_NAPI_FUNCTION("destroy", Destroy),
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
        DECLARE_NAPI_FUNCTION("getOutputDevice", GetOutputDevice)
    };
    auto property_count = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor{};
    auto status = napi_define_class(env, "AVSession", NAPI_AUTO_LENGTH, ConstructorCallback, nullptr,
                                    property_count, descriptors, &constructor);
    if (status != napi_ok) {
        SLOGE("define class failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_create_reference(env, constructor, 1, &AVSessionConstructorRef);
    return exports;
}

napi_value NapiAVSession::ConstructorCallback(napi_env env, napi_callback_info info)
{
    AVSessionTrace avSessionTrace("NapiAVSession::ConstructorCallback");
    napi_value self;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr), nullptr);
    auto finalize = [](napi_env env, void *data, void *hint) {
        auto *napiSession = reinterpret_cast<NapiAVSession *>(data);
        napi_delete_reference(env, napiSession->wrapperRef_);
        delete napiSession;
    };
    auto *napiSession = new(std::nothrow) NapiAVSession();
    if (napiSession == nullptr) {
        SLOGE("no memory");
        return nullptr;
    }
    if (napi_wrap(env, self, static_cast<void *>(napiSession), finalize, nullptr,
                  &(napiSession->wrapperRef_)) != napi_ok) {
        SLOGE("wrap failed");
        return nullptr;
    }
    return self;
}

napi_status NapiAVSession::NewInstance(napi_env env, std::shared_ptr<AVSession> &nativeSession, napi_value &out)
{
    AVSessionTrace avSessionTrace("NapiAVSession::NewInstance");
    napi_value constructor{};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, AVSessionConstructorRef, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);
    NapiAVSession *napiAvSession{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void **>(&napiAvSession)), napi_generic_failure);
    napiAvSession->session_ = std::move(nativeSession);
    napiAvSession->sessionId_ = napiAvSession->session_->GetSessionId();
    SLOGI("sessionId=%{public}s", napiAvSession->sessionId_.c_str());

    napi_value property {};
    auto status = NapiUtils::SetValue(env, napiAvSession->sessionId_, property);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    NAPI_CALL_BASE(env, napi_set_named_property(env, instance, "sessionId", property), napi_generic_failure);
    out = instance;
    return napi_ok;
}

napi_value NapiAVSession::OnEvent(napi_env env, napi_callback_info info)
{
    AVSessionTrace avSessionTrace("NapiAVSession::OnEvent");
    auto context = std::make_shared<ContextBase>();
    std::string eventName;
    napi_value callback {};
    auto input = [&eventName, &callback, env, &context](size_t argc, napi_value* argv) {
        /* require 2 arguments <event, callback> */
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid argument number");
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed");
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                               "callback type invalid");
        callback = argv[ARGV_SECOND];
    };
    context->GetCbInfo(env, info, input, true);
    AVSessionTrace trace("NapiAVSession::OnEvent_" + eventName);
    if (context->status != napi_ok) {
        napi_throw_error(env, nullptr, context->error.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }
    auto it = onEventHandlers_.find(eventName);
    if (it == onEventHandlers_.end()) {
        SLOGE("event name invalid");
        napi_throw_error(env, nullptr, "event name invalid");
        return NapiUtils::GetUndefinedValue(env);
    }
    auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
    if (napiSession->session_ == nullptr) {
        SLOGE("native session is nullptr");
        napi_throw_error(env, nullptr, "native session is nullptr");
        return NapiUtils::GetUndefinedValue(env);
    }
    if (napiSession->callback_ == nullptr) {
        napiSession->callback_ = std::make_shared<NapiAVSessionCallback>();
        if (napiSession->callback_ == nullptr) {
            SLOGE("no memory");
            napi_throw_error(env, nullptr, "no memory");
            return NapiUtils::GetUndefinedValue(env);
        }
        int32_t ret = napiSession->session_->RegisterCallback(napiSession->callback_);
        if (ret != AVSESSION_SUCCESS) {
            napi_throw_error(env, nullptr, "native register callback failed");
            return NapiUtils::GetUndefinedValue(env);
        }
    }
    if (it->second(env, napiSession, callback) != napi_ok) {
        napi_throw_error(env, nullptr, "add event callback failed");
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSession::OffEvent(napi_env env, napi_callback_info info)
{
    AVSessionTrace avSessionTrace("NapiAVSession::OffEvent");
    auto context = std::make_shared<ContextBase>();
    std::string eventName;
    napi_value callback = nullptr;
    auto input = [&eventName, env, &context, &callback](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE || argc == ARGC_TWO, "invalid argument number");
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed");
        if (argc == ARGC_TWO) {
            callback = argv[ARGV_SECOND];
        }
    };
    context->GetCbInfo(env, info, input, true);
    AVSessionTrace trace("NapiAVSession::OffEvent_" +  eventName);
    if (context->status != napi_ok) {
        napi_throw_error(env, nullptr, context->error.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }
    auto it = offEventHandlers_.find(eventName);
    if (it == offEventHandlers_.end()) {
        SLOGE("event name invalid");
        napi_throw_error(env, nullptr, "event name invalid");
        return NapiUtils::GetUndefinedValue(env);
    }
    auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
    if (napiSession->session_ == nullptr) {
        SLOGE("native session is nullptr");
        napi_throw_error(env, nullptr, "native session is nullptr");
        return NapiUtils::GetUndefinedValue(env);
    }
    if (napiSession != nullptr && it->second(env, napiSession, callback) != napi_ok) {
        napi_throw_error(env, nullptr, "remove event callback failed");
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSession::SetAVMetaData(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::SetAVMetadata");
    struct ConcreteContext : public ContextBase {
        AVMetaData metaData_;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments");
        context->status = NapiMetaData::GetValue(env, argv[ARGV_FIRST], context->metaData_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get metaData failed");
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_META_DATA_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
        int32_t ret = napiSession->session_->SetAVMetaData(context->metaData_);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "SetAVMetaData failed";
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVMetaData", executor, complete);
}

napi_value NapiAVSession::SetAVPlaybackState(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::SetAVPlaybackState");
    struct ConcreteContext : public ContextBase {
        AVPlaybackState playBackState_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments");
        context->status = NapiPlaybackState::GetValue(env, argv[ARGV_FIRST], context->playBackState_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get playBackState failed");
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_PLAYBACK_STATE_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
        int32_t ret = napiSession->session_->SetAVPlaybackState(context->playBackState_);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "SetAVPlaybackState failed";
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVPlaybackState", executor, complete);
}

napi_value NapiAVSession::SetLaunchAbility(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::SetLaunchAbility");
    struct ConcreteContext : public ContextBase {
        AbilityRuntime::WantAgent::WantAgent* wantAgent_;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments");
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->wantAgent_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get  wantAgent failed");
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_LAUNCH_ABILITY_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
        int32_t ret = napiSession->session_->SetLaunchAbility(*context->wantAgent_);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "SetLaunchAbility failed";
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetLaunchAbility", executor, complete);
}

napi_value NapiAVSession::SetAudioStreamId(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::SetAudioStreamId");
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_SET_AUDIO_STREAM_ID_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAudioStreamId", executor, complete);
}

napi_value NapiAVSession::GetController(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::GetController");
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_GET_CONTROLLER_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetController", executor, complete);
}

napi_value NapiAVSession::GetOutputDevice(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::GetOutputDevice");
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_AVSESSION_GET_OUTPUT_DEVICE_TASK_ID;
    
    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetOutputDevice", executor, complete);
}

napi_value NapiAVSession::Activate(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::Activate");
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_ACTIVATE_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
        int32_t ret = napiSession->session_->Activate();
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "activate session failed";
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Activate", executor, complete);
}

napi_value NapiAVSession::Deactivate(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::Deactivate");
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_DEACTIVATE_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
        int32_t ret = napiSession->session_->Deactivate();
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "deactivate session failed";
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Deactivate", executor, complete);
}

napi_value NapiAVSession::Destroy(napi_env env, napi_callback_info info)
{
    AVSessionTrace trace("NapiAVSession::Destroy");
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_AVSESSION_DESTROY_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native session is nullptr";
            return;
        }
        int32_t ret = napiSession->session_->Destroy();
        if (ret == AVSESSION_SUCCESS) {
            napiSession->session_ = nullptr;
            napiSession->callback_ = nullptr;
        } else {
            context->status = napi_generic_failure;
            context->error = "destroy session failed";
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Destroy", executor, complete);
}

napi_status NapiAVSession::OnPlay(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY, callback);
}

napi_status NapiAVSession::OnPause(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PAUSE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PAUSE, callback);
}

napi_status NapiAVSession::OnStop(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_STOP);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_STOP, callback);
}

napi_status NapiAVSession::OnPlayNext(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY_NEXT, callback);
}

napi_status NapiAVSession::OnPlayPrevious(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY_PREVIOUS, callback);
}

napi_status NapiAVSession::OnFastForward(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_FAST_FORWARD);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_FAST_FORWARD, callback);
}

napi_status NapiAVSession::OnRewind(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_REWIND);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_REWIND, callback);
}

napi_status NapiAVSession::OnSeek(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SEEK);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SEEK, callback);
}

napi_status NapiAVSession::OnSetSpeed(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_SPEED);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SET_SPEED, callback);
}

napi_status NapiAVSession::OnSetLoopMode(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SET_LOOP_MODE, callback);
}

napi_status NapiAVSession::OnToggleFavorite(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_TOGGLE_FAVORITE, callback);
}

napi_status NapiAVSession::OnMediaKeyEvent(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_MEDIA_KEY_EVENT, callback);
}

napi_status NapiAVSession::OnOutputDeviceChange(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_OUTPUT_DEVICE_CHANGED, callback);
}

napi_status NapiAVSession::OffPlay(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PLAY, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PLAY)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PLAY);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffPause(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PAUSE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PAUSE)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PAUSE);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffStop(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_STOP, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_STOP)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_STOP);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffPlayNext(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PLAY_NEXT, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PLAY_NEXT)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffPlayPrevious(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PLAY_PREVIOUS, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PLAY_PREVIOUS)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffFastForward(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_FAST_FORWARD, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_FAST_FORWARD)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_FAST_FORWARD);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffRewind(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_REWIND, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_REWIND)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_REWIND);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffSeek(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SEEK, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_SEEK)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_SEEK);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffSetSpeed(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SET_SPEED, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_SET_SPEED)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_SET_SPEED);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffSetLoopMode(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SET_LOOP_MODE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_SET_LOOP_MODE)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffToggleFavorite(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_TOGGLE_FAVORITE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_TOGGLE_FAVORITE)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffMediaKeyEvent(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_MEDIA_KEY_EVENT, callback);
}

napi_status NapiAVSession::OffOutputDeviceChange(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_OUTPUT_DEVICE_CHANGED, callback);
}
}