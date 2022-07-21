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

#include "napi_avsession_manager.h"
#include "avcontrol_command.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "key_event.h"
#include "ability.h"
#include "napi_base_context.h"
#include "napi_utils.h"
#include "napi_async_work.h"
#include "napi_avsession.h"
#include "napi_avsession_controller.h"
#include "napi_control_command.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
std::map<std::string, std::pair<NapiAVSessionManager::OnEventHandlerType, NapiAVSessionManager::OffEventHandlerType>>
    NapiAVSessionManager::eventHandlers_ = {
    { "sessionCreate", { OnSessionCreate, OffSessionCreate } },
    { "sessionDestroy", { OnSessionDestroy, OffSessionDestroy } },
    { "topSessionChange", { OnTopSessionChange, OffTopSessionChange } },
    { "sessionServiceDie", { OnServiceDie, OffServiceDie } },
};

std::shared_ptr<NapiSessionListener> NapiAVSessionManager::listener_;
std::shared_ptr<NapiAsyncCallback> NapiAVSessionManager::asyncCallback_;
std::list<napi_ref> NapiAVSessionManager::serviceDiedCallbacks_;

napi_value NapiAVSessionManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVSession", CreateAVSession),
        DECLARE_NAPI_STATIC_FUNCTION("getAllSessionDescriptors", GetAllSessionDescriptors),
        DECLARE_NAPI_STATIC_FUNCTION("createController", CreateController),
        DECLARE_NAPI_STATIC_FUNCTION("castAudio", CastAudio),
        DECLARE_NAPI_STATIC_FUNCTION("on", OnEvent),
        DECLARE_NAPI_STATIC_FUNCTION("off", OffEvent),
        DECLARE_NAPI_STATIC_FUNCTION("sendSystemAVKeyEvent", SendSystemAVKeyEvent),
        DECLARE_NAPI_STATIC_FUNCTION("sendSystemControlCommand", SendSystemControlCommand),
    };

    napi_status status = napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor),
                                                descriptors);
    if (status != napi_ok) {
        SLOGE("define manager properties failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    return exports;
}

napi_value NapiAVSessionManager::CreateAVSession(napi_env env, napi_callback_info info)
{
    AVSessionTrace::TraceBegin("NapiAVSessionManager::CreateAVSession", NAPI_CREATE_AVSESSION_TASK_ID);
    struct ConcreteContext : public ContextBase {
        std::string tag_;
        int32_t type_{};
        AppExecFwk::ElementName elementName_;
        std::shared_ptr<AVSession> session_;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        // require 3 arguments <context> <tag> <type>
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THERE, "invalid arguments");
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->elementName_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok , "invalid context");
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->tag_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok && !context->tag_.empty(), "invalid tag");
        std::string typeString;
        context->status = NapiUtils::GetValue(env, argv[ARGV_THIRD], typeString);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok && !typeString.empty(), "invalid type");
        context->type_ = NapiUtils::ConvertSessionType(typeString);
        CHECK_ARGS_RETURN_VOID(context, context->type_ >= 0, "wrong session type");
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        context->session_ = AVSessionManager::GetInstance().CreateSession(context->tag_, context->type_,
                                                                          context->elementName_);
        if (context->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native create session failed";
        }
    };

    auto complete = [context](napi_value &output) {
        context->status = NapiAVSession::NewInstance(context->env, context->session_, output);
        CHECK_STATUS_RETURN_VOID(context, "create new javascript object failed");
        AVSessionTrace::TraceEnd("NapiAVSessionManager::CreateAVSession", NAPI_CREATE_AVSESSION_TASK_ID);
    };

    return NapiAsyncWork::Enqueue(env, context, "CreateAVSession", executor, complete);
}

napi_value NapiAVSessionManager::GetAllSessionDescriptors(napi_env env, napi_callback_info info)
{
    AVSessionTrace::TraceBegin("NapiAVSessionManager::GetAllSessionDescriptors",
        NAPI_GET_ALL_SESSION_DESCRIPTORS_TASK_ID);
    struct ConcreteContext : public ContextBase {
        std::vector<AVSessionDescriptor> descriptors_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        context->descriptors_ = AVSessionManager::GetInstance().GetAllSessionDescriptors();
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiUtils::SetValue(env, context->descriptors_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
        AVSessionTrace::TraceEnd("NapiAVSessionManager::GetAllSessionDescriptors",
            NAPI_GET_ALL_SESSION_DESCRIPTORS_TASK_ID);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAllSessionDescriptors", executor, complete);
}

napi_value NapiAVSessionManager::CreateController(napi_env env, napi_callback_info info)
{
    AVSessionTrace::TraceBegin("NapiAVSessionManager::CreateController", NAPI_CREATE_CONTROLLER_TASK_ID);
    struct ConcreteContext : public ContextBase {
        std::string sessionId_ {};
        std::shared_ptr<AVSessionController> controller_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments");
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionId_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (!context->sessionId_.empty()),
                               "invalid sessionId");
    };
    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        context->controller_ = AVSessionManager::GetInstance().CreateController(context->sessionId_);
        if (context->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "native create controller failed";
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiAVSessionController::NewInstance(env, context->controller_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
        AVSessionTrace::TraceEnd("NapiAVSessionManager::CreateController", NAPI_CREATE_CONTROLLER_TASK_ID);
    };

    return NapiAsyncWork::Enqueue(env, context, "CreateController", executor, complete);
}

napi_value NapiAVSessionManager::CastAudio(napi_env env, napi_callback_info info)
{
    AVSessionTrace avSessionTrace("NapiAVSessionManager::CastAudio");
    SLOGI("not implement");
    napi_throw_error(env, nullptr, "not implement");
    return nullptr;
}

napi_value NapiAVSessionManager::OnEvent(napi_env env, napi_callback_info info)
{
    AVSessionTrace avSessionTrace("NapiAVSessionManager::OnEvent");
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
    if (context->status != napi_ok) {
        napi_throw_error(env, nullptr, context->error.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }

    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        napi_throw_error(env, nullptr, "event name invalid");
        return NapiUtils::GetUndefinedValue(env);
    }
    if (listener_ == nullptr) {
        listener_ = std::make_shared<NapiSessionListener>();
        if (listener_ == nullptr) {
            SLOGE("no memory");
            napi_throw_error(env, nullptr, "no memory");
            return NapiUtils::GetUndefinedValue(env);
        }
        if (AVSessionManager::GetInstance().RegisterSessionListener(listener_) != AVSESSION_SUCCESS) {
            SLOGE("native register session listener failed");
            napi_throw_error(env, nullptr, "native register session listener failed");
            return NapiUtils::GetUndefinedValue(env);
        }
    }

    if (it->second.first(env, callback) != napi_ok) {
        napi_throw_error(env, nullptr, "add event callback failed");
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionManager::OffEvent(napi_env env, napi_callback_info info)
{
    AVSessionTrace avSessionTrace("NapiAVSessionManager::OffEvent");
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
    if (context->status != napi_ok) {
        napi_throw_error(env, nullptr, context->error.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }

    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        napi_throw_error(env, nullptr, "event name invalid");
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.second(env, callback) != napi_ok) {
        napi_throw_error(env, nullptr, "remove event callback failed");
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionManager::SendSystemAVKeyEvent(napi_env env, napi_callback_info info)
{
    AVSessionTrace::TraceBegin("NapiAVSessionManager::SendSystemAVKeyEvent", NAPI_SEND_SYSTEM_AV_KEY_EVENT_TASK_ID);
    struct ConcreteContext : public ContextBase {
        std::shared_ptr<MMI::KeyEvent> keyEvent_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments");
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->keyEvent_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (context->keyEvent_ != nullptr),
                               "invalid keyEvent");
    };
    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        if (AVSessionManager::GetInstance().SendSystemAVKeyEvent(*context->keyEvent_) != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "native send keyEvent failed";
        }
        AVSessionTrace::TraceEnd("NapiAVSessionManager::SendSystemAVKeyEvent", NAPI_SEND_SYSTEM_AV_KEY_EVENT_TASK_ID);
    };

    return NapiAsyncWork::Enqueue(env, context, "SendSystemAVKeyEvent", executor);
}

napi_value NapiAVSessionManager::SendSystemControlCommand(napi_env env, napi_callback_info info)
{
    AVSessionTrace::TraceBegin("NapiAVSessionManager::SendSystemControlCommand",
        NAPI_SEND_SYSTEM_CONTROL_COMMAND_TASK_ID);
    struct ConcrentContext : public ContextBase {
        AVControlCommand command;
    };
    auto context = std::make_shared<ConcrentContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments");
        context->status = NapiControlCommand::GetValue(env, argv[ARGV_FIRST], context->command);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command");
    };
    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        if (AVSessionManager::GetInstance().SendSystemControlCommand(context->command) != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "native send control command failed";
        }
        AVSessionTrace::TraceEnd("NapiAVSessionManager::SendSystemControlCommand",
            NAPI_SEND_SYSTEM_CONTROL_COMMAND_TASK_ID);
    };

    return NapiAsyncWork::Enqueue(env, context, "SendSystemControlCommand", executor);
}

napi_status NapiAVSessionManager::OnSessionCreate(napi_env env, napi_value callback)
{
    return listener_->AddCallback(env, NapiSessionListener::EVENT_SESSION_CREATED, callback);
}

napi_status NapiAVSessionManager::OnSessionDestroy(napi_env env, napi_value callback)
{
    return listener_->AddCallback(env, NapiSessionListener::EVENT_SESSION_DESTROYED, callback);
}

napi_status NapiAVSessionManager::OnTopSessionChange(napi_env env, napi_value callback)
{
    return listener_->AddCallback(env, NapiSessionListener::EVENT_TOP_SESSION_CHANGED, callback);
}

napi_status NapiAVSessionManager::OnServiceDie(napi_env env, napi_value callback)
{
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, serviceDiedCallbacks_, callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref == nullptr, napi_ok, "callback has been registered");
    napi_status status = napi_create_reference(env, callback, ARGC_ONE, &ref);
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
    serviceDiedCallbacks_.push_back(ref);
    if (AVSessionManager::GetInstance().RegisterServiceDeathCallback(HandleServiceDied) != AVSESSION_SUCCESS) {
        return napi_generic_failure;
    }
    return napi_ok;
}

void NapiAVSessionManager::HandleServiceDied()
{
    if (!serviceDiedCallbacks_.empty() && asyncCallback_ != nullptr) {
        for (auto callbackRef = serviceDiedCallbacks_.begin(); callbackRef != serviceDiedCallbacks_.end();
             ++callbackRef) {
            asyncCallback_->Call(*callbackRef);
        }
    }
}

napi_status NapiAVSessionManager::OffSessionCreate(napi_env env, napi_value callback)
{
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_SESSION_CREATED, callback);
}

napi_status NapiAVSessionManager::OffSessionDestroy(napi_env env, napi_value callback)
{
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_SESSION_DESTROYED, callback);
}

napi_status NapiAVSessionManager::OffTopSessionChange(napi_env env, napi_value callback )
{
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_TOP_SESSION_CHANGED, callback);
}

napi_status NapiAVSessionManager::OffServiceDie(napi_env env, napi_value callback)
{
    AVSessionManager::GetInstance().UnregisterServiceDeathCallback();
    if (callback == nullptr) {
        for (auto callbackRef = serviceDiedCallbacks_.begin(); callbackRef != serviceDiedCallbacks_.end();
             ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(napi_ok == ret, ret, "delete callback reference failed");
        }
        serviceDiedCallbacks_.clear();
        return napi_ok;
    }
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, serviceDiedCallbacks_, callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref != nullptr, napi_ok, "callback has been remove");
    serviceDiedCallbacks_.remove(ref);
    return napi_delete_reference(env, ref);
}
}