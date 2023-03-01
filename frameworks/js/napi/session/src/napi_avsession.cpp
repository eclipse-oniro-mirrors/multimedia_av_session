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
#include "napi_media_description.h"
#include "napi_queue_item.h"
#include "want_params.h"
#include "want_agent.h"
#include "avsession_trace.h"
#include "napi_avsession_controller.h"
#include "napi_avsession_manager.h"

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
    { "commonCommand", OnCommonCommand },
    { "skipToQueueItem", OnSkipToQueueItem },
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
    { "outputDeviceChange", OffOutputDeviceChange },
    { "commonCommand", OffCommonCommand },
    { "skipToQueueItem", OffSkipToQueueItem },
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
        DECLARE_NAPI_FUNCTION("getOutputDevice", GetOutputDevice),
        DECLARE_NAPI_FUNCTION("setSessionEvent", SetSessionEvent),
        DECLARE_NAPI_FUNCTION("setAVQueueItems", SetAVQueueItems),
        DECLARE_NAPI_FUNCTION("setAVQueueTitle", SetAVQueueTitle),
    };
    auto propertyCount = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor{};
    auto status = napi_define_class(env, "AVSession", NAPI_AUTO_LENGTH, ConstructorCallback, nullptr,
                                    propertyCount, descriptors, &constructor);
    if (status != napi_ok) {
        SLOGE("define class failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_create_reference(env, constructor, 1, &AVSessionConstructorRef);
    return exports;
}

napi_value NapiAVSession::ConstructorCallback(napi_env env, napi_callback_info info)
{
    napi_value self;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr), nullptr);
    auto finalize = [](napi_env env, void* data, void* hint) {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(data);
        napi_delete_reference(env, napiSession->wrapperRef_);
        delete napiSession;
    };
    auto* napiSession = new(std::nothrow) NapiAVSession();
    if (napiSession == nullptr) {
        SLOGE("no memory");
        return nullptr;
    }
    if (napi_wrap(env, self, static_cast<void*>(napiSession), finalize, nullptr,
                  &(napiSession->wrapperRef_)) != napi_ok) {
        SLOGE("wrap failed");
        return nullptr;
    }
    return self;
}

napi_status NapiAVSession::NewInstance(napi_env env, std::shared_ptr<AVSession>& nativeSession, napi_value& out)
{
    napi_value constructor{};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, AVSessionConstructorRef, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);
    NapiAVSession* napiAvSession{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&napiAvSession)), napi_generic_failure);
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
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    std::string eventName;
    napi_value callback {};
    auto input = [&eventName, &callback, env, &context](size_t argc, napi_value* argv) {
        /* require 2 arguments <event, callback> */
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                               "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        callback = argv[ARGV_SECOND];
    };
    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto it = onEventHandlers_.find(eventName);
    if (it == onEventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
    if (napiSession->session_ == nullptr) {
        SLOGE("OnEvent failed : session is nullptr");
        NapiUtils::ThrowError(env, "OnEvent failed : session is nullptr",
            NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    if (napiSession->callback_ == nullptr) {
        napiSession->callback_ = std::make_shared<NapiAVSessionCallback>();
        if (napiSession->callback_ == nullptr) {
            SLOGE("OnEvent failed : no memory");
            NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
            return NapiUtils::GetUndefinedValue(env);
        }
        int32_t ret = napiSession->session_->RegisterCallback(napiSession->callback_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                NapiUtils::ThrowError(env, "OnEvent failed : native session not exist",
                    NapiAVSessionManager::errcode_[ret]);
            } else if (ret == ERR_INVALID_PARAM) {
                NapiUtils::ThrowError(env, "OnEvent failed : native invalid parameters",
                    NapiAVSessionManager::errcode_[ret]);
            } else if (ret == ERR_NO_PERMISSION) {
                NapiUtils::ThrowError(env, "OnEvent failed : native no permission",
                    NapiAVSessionManager::errcode_[ret]);
            } else {
                NapiUtils::ThrowError(env, "OnEvent failed : native server exception",
                    NapiAVSessionManager::errcode_[ret]);
            }
            return NapiUtils::GetUndefinedValue(env);
        }
    }
    if (it->second(env, napiSession, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSession::OffEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OffEvent failed : no memory");
        NapiUtils::ThrowError(env, "OffEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    std::string eventName;
    napi_value callback = nullptr;
    auto input = [&eventName, env, &context, &callback](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE || argc == ARGC_TWO,
                               "invalid argument number", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_TWO) {
            callback = argv[ARGV_SECOND];
        }
    };
    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto it = offEventHandlers_.find(eventName);
    if (it == offEventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
    if (napiSession->session_ == nullptr) {
        SLOGE("OffEvent failed : session is nullptr");
        NapiUtils::ThrowError(env, "OffEvent failed : session is nullptr",
            NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    if (napiSession != nullptr && it->second(env, napiSession, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSession::SetAVMetaData(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVMetadata");
    struct ConcreteContext : public ContextBase {
        AVMetaData metaData_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAVMetaData failed : no memory");
        NapiUtils::ThrowError(env, "SetAVMetaData failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiMetaData::GetValue(env, argv[ARGV_FIRST], context->metaData_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get metaData failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_META_DATA_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVMetaData failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVMetaData(context->metaData_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVMetaData failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVMetaData failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVMetaData failed : native no permission";
            } else {
                context->errMessage = "SetAVMetaData failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVMetaData", executor, complete);
}

napi_value NapiAVSession::SetAVPlaybackState(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVPlaybackState");
    struct ConcreteContext : public ContextBase {
        AVPlaybackState playBackState_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAVPlaybackState failed : no memory");
        NapiUtils::ThrowError(env, "SetAVPlaybackState failed : no memory",
                              NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiPlaybackState::GetValue(env, argv[ARGV_FIRST], context->playBackState_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get playBackState failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_PLAYBACK_STATE_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVPlaybackState failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVPlaybackState(context->playBackState_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVPlaybackState failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVPlaybackState failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVPlaybackState failed : native no permission";
            } else {
                context->errMessage = "SetAVPlaybackState failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVPlaybackState", executor, complete);
}

napi_value NapiAVSession::SetAVQueueItems(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVQueueItems");
    struct ConcreteContext : public ContextBase {
        std::vector<AVQueueItem> items_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAVQueueItems failed : no memory");
        NapiUtils::ThrowError(env, "SetAVQueueItems failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->items_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get queueItems failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_QUEUE_ITEMS_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVQueueItems failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVQueueItems(context->items_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVQueueItems failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVQueueItems failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVQueueItems failed : native no permission";
            } else {
                context->errMessage = "SetAVQueueItems failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVQueueItems", executor, complete);
}

napi_value NapiAVSession::SetAVQueueTitle(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVQueueTitle");
    struct ConcreteContext : public ContextBase {
        std::string title;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAVQueueTitle failed : no memory");
        NapiUtils::ThrowError(env, "SetAVQueueTitle failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->title);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get queueItems failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_QUEUE_TITLE_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVQueueTitle failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVQueueTitle(context->title);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVQueueTitle failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVQueueTitle failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVQueueTitle failed : native no permission";
            } else {
                context->errMessage = "SetAVQueueTitle failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVQueueTitle", executor, complete);
}

napi_value NapiAVSession::SetLaunchAbility(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AbilityRuntime::WantAgent::WantAgent* wantAgent_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetLaunchAbility failed : no memory");
        NapiUtils::ThrowError(env, "SetLaunchAbility failed : no memory",
                              NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->wantAgent_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get  wantAgent failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetLaunchAbility failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetLaunchAbility(*context->wantAgent_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetLaunchAbility failed : native session not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetLaunchAbility failed : native no permission";
            } else {
                context->errMessage = "SetLaunchAbility failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetLaunchAbility", executor, complete);
}

napi_value NapiAVSession::SetAudioStreamId(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<int32_t> streamIds_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAudioStreamId failed : no memory");
        NapiUtils::ThrowError(env, "SetAudioStreamId failed : no memory",
                              NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->streamIds_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get streamIds_ failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAudioStreamId failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
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
    struct ConcreteContext : public ContextBase {
        std::shared_ptr<AVSessionController> controller_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("GetController failed : no memory");
        NapiUtils::ThrowError(env, "GetController failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetController failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        context->controller_ = napiSession->session_->GetController();
        if (context->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetController failed : native get controller failed";
            context->errCode = NapiAVSessionManager::errcode_[AVSESSION_ERROR];
        }
    };
    auto complete = [env, context](napi_value& output) {
        CHECK_STATUS_RETURN_VOID(context, "get controller failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        CHECK_ARGS_RETURN_VOID(context, context->controller_ != nullptr, "controller is nullptr",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        context->status = NapiAVSessionController::NewInstance(env, context->controller_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to js object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetController", executor, complete);
}

napi_value NapiAVSession::GetOutputDevice(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        OutputDeviceInfo outputDeviceInfo_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("GetOutputDevice failed : no memory");
        NapiUtils::ThrowError(env, "GetOutputDevice failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetOutputDevice failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        AVSessionDescriptor descriptor;
        AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(napiSession->session_->GetSessionId(),
                                                                         descriptor);
        context->outputDeviceInfo_ = descriptor.outputDeviceInfo_;
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->outputDeviceInfo_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetOutputDevice", executor, complete);
}

napi_value NapiAVSession::Activate(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Activate failed : no memory");
        NapiUtils::ThrowError(env, "Activate failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "Activate session failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->Activate();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "Activate session failed : native session not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "Activate failed : native no permission";
            } else {
                context->errMessage = "Activate session failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Activate", executor, complete);
}

napi_value NapiAVSession::Deactivate(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Deactivate failed : no memory");
        NapiUtils::ThrowError(env, "Deactivate failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "Deactivate session failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->Deactivate();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "Deactivate session failed : native session not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "Deactivate failed : native no permission";
            } else {
                context->errMessage = "Deactivate session failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Deactivate", executor, complete);
}

napi_value NapiAVSession::Destroy(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Destroy failed : no memory");
        NapiUtils::ThrowError(env, "Destroy failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "Destroy session failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->Destroy();
        if (ret == AVSESSION_SUCCESS) {
            napiSession->session_ = nullptr;
            napiSession->callback_ = nullptr;
        } else if (ret == ERR_SESSION_NOT_EXIST) {
            context->status = napi_generic_failure;
            context->errMessage = "Destroy session failed : native session not exist";
            context->errCode = NapiAVSessionManager::errcode_[ret];
        } else if (ret == ERR_NO_PERMISSION) {
            context->status = napi_generic_failure;
            context->errMessage = "Destroy failed : native no permission";
            context->errCode = NapiAVSessionManager::errcode_[ret];
        } else {
            context->status = napi_generic_failure;
            context->errMessage = "Destroy session failed : native server exception";
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Destroy", executor, complete);
}

napi_value NapiAVSession::SetSessionEvent(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetSessionEvent");
    struct ConcreteContext : public ContextBase {
        std::string event_;
        AAFwk::WantParams args_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetSessionEvent failed : no memory");
        NapiUtils::ThrowError(env, "SetSessionEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->event_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get event failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->args_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get args failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_META_DATA_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetSessionEvent failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetSessionEvent(context->event_, context->args_);
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, context->errMessage);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetSessionEvent", executor, complete);
}

void NapiAVSession::ErrCodeToMessage(int32_t errCode, std::string& message)
{
    switch (errCode) {
        case ERR_SESSION_NOT_EXIST:
            message = "SetSessionEvent failed : native session not exist";
            break;
        case ERR_INVALID_PARAM:
            message = "SetAVMetaData failed : native invalid parameters";
            break;
        case ERR_NO_PERMISSION:
            message = "SetSessionEvent failed : native no permission";
            break;
        default:
            message = "SetSessionEvent failed : native server exception";
            break;
    }
}

napi_status NapiAVSession::OnPlay(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY, callback);
}

napi_status NapiAVSession::OnPause(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PAUSE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PAUSE, callback);
}

napi_status NapiAVSession::OnStop(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_STOP);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_STOP, callback);
}

napi_status NapiAVSession::OnPlayNext(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY_NEXT, callback);
}

napi_status NapiAVSession::OnPlayPrevious(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY_PREVIOUS, callback);
}

napi_status NapiAVSession::OnFastForward(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_FAST_FORWARD);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_FAST_FORWARD, callback);
}

napi_status NapiAVSession::OnRewind(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_REWIND);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_REWIND, callback);
}

napi_status NapiAVSession::OnSeek(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SEEK);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SEEK, callback);
}

napi_status NapiAVSession::OnSetSpeed(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_SPEED);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SET_SPEED, callback);
}

napi_status NapiAVSession::OnSetLoopMode(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SET_LOOP_MODE, callback);
}

napi_status NapiAVSession::OnToggleFavorite(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_TOGGLE_FAVORITE, callback);
}

napi_status NapiAVSession::OnMediaKeyEvent(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_MEDIA_KEY_EVENT, callback);
}

napi_status NapiAVSession::OnOutputDeviceChange(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_OUTPUT_DEVICE_CHANGE, callback);
}

napi_status NapiAVSession::OnCommonCommand(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SEND_COMMON_COMMAND, callback);
}

napi_status NapiAVSession::OnSkipToQueueItem(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SKIP_TO_QUEUE_ITEM, callback);
}

napi_status NapiAVSession::OffPlay(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PLAY, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
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
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_TOGGLE_FAVORITE)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffMediaKeyEvent(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_MEDIA_KEY_EVENT, callback);
}

napi_status NapiAVSession::OffOutputDeviceChange(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_OUTPUT_DEVICE_CHANGE, callback);
}

napi_status NapiAVSession::OffCommonCommand(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SEND_COMMON_COMMAND, callback);
}

napi_status NapiAVSession::OffSkipToQueueItem(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SKIP_TO_QUEUE_ITEM, callback);
}
}
