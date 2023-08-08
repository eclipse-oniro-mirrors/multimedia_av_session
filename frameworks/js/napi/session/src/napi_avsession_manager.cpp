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
#include "avsession_sysevent.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "napi_avcast_controller.h"
#endif

namespace OHOS::AVSession {
using namespace Security::AccessToken;
std::map<std::string, std::pair<NapiAVSessionManager::OnEventHandlerType, NapiAVSessionManager::OffEventHandlerType>>
    NapiAVSessionManager::eventHandlers_ = {
    { "sessionCreate", { OnSessionCreate, OffSessionCreate } },
    { "sessionDestroy", { OnSessionDestroy, OffSessionDestroy } },
    { "topSessionChange", { OnTopSessionChange, OffTopSessionChange } },
    { "sessionServiceDie", { OnServiceDie, OffServiceDie } },
    { "deviceAvailable", { OnDeviceAvailable, OffDeviceAvailable } },
};

std::shared_ptr<NapiSessionListener> NapiAVSessionManager::listener_;
std::shared_ptr<NapiAsyncCallback> NapiAVSessionManager::asyncCallback_;
std::list<napi_ref> NapiAVSessionManager::serviceDiedCallbacks_;

std::map<int32_t, int32_t> NapiAVSessionManager::errcode_ = {
    {AVSESSION_ERROR, 6600101},
    {ERR_NO_MEMORY, 6600101},
    {ERR_SERVICE_NOT_EXIST, 6600101},
    {ERR_SESSION_LISTENER_EXIST, 6600101},
    {ERR_MARSHALLING, 6600101},
    {ERR_UNMARSHALLING, 6600101},
    {ERR_IPC_SEND_REQUEST, 6600101},
    {ERR_CONTROLLER_IS_EXIST, 6600101},
    {ERR_START_ABILITY_IS_RUNNING, 6600101},
    {ERR_ABILITY_NOT_AVAILABLE, 6600101},
    {ERR_START_ABILITY_TIMEOUT, 6600101},
    {ERR_SESSION_NOT_EXIST, 6600102},
    {ERR_CONTROLLER_NOT_EXIST, 6600103},
    {ERR_RPC_SEND_REQUEST, 6600104},
    {ERR_COMMAND_NOT_SUPPORT, 6600105},
    {ERR_SESSION_DEACTIVE, 6600106},
    {ERR_COMMAND_SEND_EXCEED_MAX, 6600107},
    {ERR_DEVICE_CONNECTION_FAILED, 6600108},
    {ERR_REMOTE_CONNECTION_NOT_EXIST, 6600109},
    {ERR_NO_PERMISSION, 202},
    {ERR_INVALID_PARAM, 401},
};
napi_value NapiAVSessionManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVSession", CreateAVSession),
        DECLARE_NAPI_STATIC_FUNCTION("getAllSessionDescriptors", GetAllSessionDescriptors),
        DECLARE_NAPI_STATIC_FUNCTION("getHistoricalSessionDescriptors", GetHistoricalSessionDescriptors),
        DECLARE_NAPI_STATIC_FUNCTION("createController", CreateController),
        DECLARE_NAPI_STATIC_FUNCTION("getAVCastController", GetAVCastController),
        DECLARE_NAPI_STATIC_FUNCTION("castAudio", CastAudio),
        DECLARE_NAPI_STATIC_FUNCTION("on", OnEvent),
        DECLARE_NAPI_STATIC_FUNCTION("off", OffEvent),
        DECLARE_NAPI_STATIC_FUNCTION("sendSystemAVKeyEvent", SendSystemAVKeyEvent),
        DECLARE_NAPI_STATIC_FUNCTION("sendSystemControlCommand", SendSystemControlCommand),
        DECLARE_NAPI_STATIC_FUNCTION("startCastDeviceDiscovery", StartCastDiscovery),
        DECLARE_NAPI_STATIC_FUNCTION("stopCastDeviceDiscovery", StopCastDiscovery),
        DECLARE_NAPI_STATIC_FUNCTION("setDiscoverable", SetDiscoverable),
        DECLARE_NAPI_STATIC_FUNCTION("startCasting", StartCast),
        DECLARE_NAPI_STATIC_FUNCTION("stopCasting", StopCast),
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
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::CreateAVSession");
    struct ConcreteContext : public ContextBase {
        std::string tag_;
        int32_t type_{};
        AppExecFwk::ElementName elementName_;
        std::shared_ptr<AVSession> session_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->taskId = NAPI_CREATE_AVSESSION_TASK_ID;

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        // require 3 arguments <context> <tag> <type>
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THREE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->elementName_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "invalid context",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->tag_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok && !context->tag_.empty(), "invalid tag",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        std::string typeString;
        context->status = NapiUtils::GetValue(env, argv[ARGV_THIRD], typeString);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok && !typeString.empty(), "invalid type",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->type_ = NapiUtils::ConvertSessionType(typeString);
        CHECK_ARGS_RETURN_VOID(context, context->type_ >= 0, "wrong session type",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        context->session_ = AVSessionManager::GetInstance().CreateSession(context->tag_, context->type_,
                                                                          context->elementName_);
        if (context->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "CreateAVSession failed : native create session failed";
            context->errCode = NapiAVSessionManager::errcode_[AVSESSION_ERROR];
        }
    };

    auto complete = [context](napi_value& output) {
        context->status = NapiAVSession::NewInstance(context->env, context->session_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "CreateAVSession", executor, complete);
}

napi_value NapiAVSessionManager::GetAllSessionDescriptors(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<AVSessionDescriptor> descriptors_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().GetAllSessionDescriptors(context->descriptors_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAllSessionDescriptors failed : native no permission";
            } else {
                context->errMessage = "GetAllSessionDescriptors failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->descriptors_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAllSessionDescriptors", executor, complete);
}

napi_value NapiAVSessionManager::GetHistoricalSessionDescriptors(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int32_t maxSize_ {};
        std::vector<AVSessionDescriptor> descriptors_;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto input = [env, context](size_t argc, napi_value* argv) {
        if (argc == ARGC_ONE && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_undefined)
            && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_null)) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->maxSize_);
            CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "invalid arguments",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            CHECK_ARGS_RETURN_VOID(context,
                (context->maxSize_ >= (int32_t)HISTORICAL_MIN_NUM && context->maxSize_ <= (int32_t)HISTORICAL_MAX_NUM),
                "invalid arguments", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        } else {
            context->maxSize_ = HISTORICAL_UNSET_NUM;
        }
    };

    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().GetHistoricalSessionDescriptors(context->maxSize_,
            context->descriptors_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetHistoricalSessionDescriptors failed : native no permission";
            } else {
                context->errMessage = "GetHistoricalSessionDescriptors failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->descriptors_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetHistoricalSessionDescriptors", executor, complete);
}

napi_value NapiAVSessionManager::CreateController(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::CreateController");
    struct ConcreteContext : public ContextBase {
        std::string sessionId_ {};
        std::shared_ptr<AVSessionController> controller_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionId_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (!context->sessionId_.empty()),
                               "invalid sessionId", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CREATE_CONTROLLER_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().CreateController(context->sessionId_, context->controller_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "CreateController failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "CreateController failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "CreateController failed : native session not exist";
            } else {
                context->errMessage = "CreateController failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiAVSessionController::NewInstance(env, context->controller_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "CreateController", executor, complete);
}

napi_value NapiAVSessionManager::GetAVCastController(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::GetAVCastController");
    struct ConcreteContext : public ContextBase {
        std::string sessionId_ {};
        std::shared_ptr<AVCastController> castController_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionId_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (!context->sessionId_.empty()),
            "invalid sessionId", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CREATE_CAST_CONTROLLER_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().GetAVCastController(context->sessionId_,
            context->castController_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAVCastController failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "GetAVCastController failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAVCastController failed : native session not exist";
            } else {
                context->errMessage = "GetAVCastController failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiAVCastController::NewInstance(env, context->castController_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAVCastController", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::CastAudio(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::CastAudio");
    struct ConcreteContext : public ContextBase {
        SessionToken sessionToken_ {};
        bool isAll_ = false;
        std::vector<AudioStandard::AudioDeviceDescriptor> audioDeviceDescriptors_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);

        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_string || type == napi_object),
                               "invalid type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (type == napi_string) {
            std::string flag;
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], flag);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (flag == "all"),
                                   "invalid argument", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            context->isAll_ = true;
        }
        if (type == napi_object) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionToken_);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (!context->sessionToken_.sessionId.empty()),
                                   "invalid session token", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        }
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->audioDeviceDescriptors_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (context->audioDeviceDescriptors_.size() > 0),
                               "invalid AudioDeviceDescriptor", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CAST_AUDIO_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        if (context->isAll_) {
            ret = AVSessionManager::GetInstance().CastAudioForAll(context->audioDeviceDescriptors_);
        } else {
            ret = AVSessionManager::GetInstance().CastAudio(context->sessionToken_, context->audioDeviceDescriptors_);
        }
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "CastAudio failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "CastAudio failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "CastAudio failed : native session not exist";
            } else {
                context->errMessage = "CastAudio failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "CastAudio", executor, complete);
}
napi_status NapiAVSessionManager::RegisterNativeSessionListener(napi_env env)
{
    if (listener_ != nullptr) {
        return napi_ok;
    }

    listener_ = std::make_shared<NapiSessionListener>();
    if (listener_ == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return napi_generic_failure;
    }
    int32_t ret = AVSessionManager::GetInstance().RegisterSessionListener(listener_);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("native register session listener failed");
        if (ret == ERR_INVALID_PARAM) {
            NapiUtils::ThrowError(env, "OnEvent failed : native invalid parameters",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        } else if (ret == ERR_NO_PERMISSION) {
            NapiUtils::ThrowError(env, "OnEvent failed : native no permission",
                NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
        } else {
            NapiUtils::ThrowError(env, "OnEvent failed : native server exception",
                NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        }
        return napi_generic_failure;
    }

    return napi_ok;
}

napi_value NapiAVSessionManager::OnEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    std::string eventName;
    napi_value callback = nullptr;
    auto input = [&eventName, &callback, env, &context](size_t argc, napi_value* argv) {
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        bool isSystemApp = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
        CHECK_ARGS_RETURN_VOID(context, isSystemApp, "Check system permission error",
            NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);

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

    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    if (RegisterNativeSessionListener(env) == napi_generic_failure) {
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.first(env, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionManager::OffEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    std::string eventName;
    napi_value callback = nullptr;
    auto input = [&eventName, env, &context, &callback](size_t argc, napi_value* argv) {
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        bool isSystemApp = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
        CHECK_ARGS_RETURN_VOID(context, isSystemApp, "Check system permission error",
            NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);

        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE || argc == ARGC_TWO, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_TWO) {
            callback = argv[ARGV_SECOND];
        }
    };

    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.second(env, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionManager::SendSystemAVKeyEvent(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::SendSystemAVKeyEvent");
    struct ConcreteContext : public ContextBase {
        std::shared_ptr<MMI::KeyEvent> keyEvent_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->keyEvent_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (context->keyEvent_ != nullptr),
                               "invalid keyEvent", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_SEND_SYSTEM_AV_KEY_EVENT_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().SendSystemAVKeyEvent(*context->keyEvent_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "SendSystemAVKeyEvent failed : native invalid keyEvent";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SendSystemAVKeyEvent failed : native no permission";
            } else {
                context->errMessage = "SendSystemAVKeyEvent failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendSystemAVKeyEvent", executor);
}

napi_value NapiAVSessionManager::SendSystemControlCommand(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::SendSystemControlCommand");
    struct ConcrentContext : public ContextBase {
        AVControlCommand command;
    };
    auto context = std::make_shared<ConcrentContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiControlCommand::GetValue(env, argv[ARGV_FIRST], context->command);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_SEND_SYSTEM_CONTROL_COMMAND_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().SendSystemControlCommand(context->command);
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
            double speed;
            int64_t time;
            int32_t mode;
            std::string assetId;
            context->command.GetSpeed(speed);
            context->command.GetSeekTime(time);
            context->command.GetLoopMode(mode);
            context->command.GetAssetId(assetId);
            HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "SEND_CMD_FAILED",
                "CMD", context->command.GetCommand(), "TIME", time, "SPEED", speed, "MODE", mode, "ASSETID", assetId,
                "ERROR_CODE", ret, "ERROR_INFO", "native send control command failed");
#endif
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "SendSystemControlCommand failed : native invalid command";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SendSystemControlCommand failed : native send control command no permission";
                HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "ERROR_CODE", ret,
                                    "ERROR_INFO", "SendSystemControlCommand failed : native no permission");
            } else if (ret == ERR_COMMAND_SEND_EXCEED_MAX) {
                context->errMessage = "SendSystemControlCommand failed : native send command overload";
            } else {
                context->errMessage = "SendSystemControlCommand failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendSystemControlCommand", executor);
}

napi_value NapiAVSessionManager::StartCastDiscovery(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StartCastDiscovery");
    struct ConcreteContext : public ContextBase {
        int32_t castDeviceCapability_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        if (argc == ARGC_ONE && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_undefined)
            && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_null)) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->castDeviceCapability_);
            CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "invalid castDeviceCapability",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        } else {
            context->castDeviceCapability_ = ProtocolType::TYPE_CAST_PLUS_STREAM;
        }
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_START_CAST_DISCOVERY_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().StartCastDiscovery(context->castDeviceCapability_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "StartCastDiscovery failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "StartCastDiscovery failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "StartCastDiscovery failed : native session not exist";
            } else {
                context->errMessage = "StartCastDiscovery failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    return NapiAsyncWork::Enqueue(env, context, "StartCastDiscovery", executor);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::StopCastDiscovery(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StopCastDiscovery");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Activate failed : no memory");
        NapiUtils::ThrowError(env, "Activate failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);
    context->taskId = NAPI_STOP_CAST_DISCOVERY_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        ret = AVSessionManager::GetInstance().StopCastDiscovery();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "StopCastDiscovery failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "StopCastDiscovery failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "StopCastDiscovery failed : native session not exist";
            } else {
                context->errMessage = "StopCastDiscovery failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "StopCastDiscovery", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::SetDiscoverable(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::SetDiscoverable");
    struct ConcreteContext : public ContextBase {
        bool enable_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->enable_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get streamIds_ failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_SET_DISCOVERABLE_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().SetDiscoverable(context->enable_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetDiscoverable failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetDiscoverable failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetDiscoverable failed : native session not exist";
            } else {
                context->errMessage = "SetDiscoverable failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    return NapiAsyncWork::Enqueue(env, context, "SetDiscoverable", executor);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::StartCast(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StartCast");
    struct ConcreteContext : public ContextBase {
        SessionToken sessionToken_ {};
        OutputDeviceInfo outputdeviceInfo_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);

        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_object),
            "invalid type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionToken_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok)
            && (!context->sessionToken_.sessionId.empty()),
            "invalid session token", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->outputdeviceInfo_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok)
            && (context->outputdeviceInfo_.deviceInfos_.size() > 0),
            "invalid outputdeviceInfo", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_START_CAST_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        ret = AVSessionManager::GetInstance().StartCast(context->sessionToken_, context->outputdeviceInfo_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "StartCast failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "StartCast failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "StartCast failed : native session not exist";
            } else {
                context->errMessage = "StartCast failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "StartCast", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::StopCast(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StopCast");
    struct ConcreteContext : public ContextBase {
        SessionToken sessionToken_ {};
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);

        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_object),
            "invalid type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionToken_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (!context->sessionToken_.sessionId.empty()),
            "invalid session token", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_STOP_CAST_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        ret = AVSessionManager::GetInstance().StopCast(context->sessionToken_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "StopCast failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "StopCast failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "StopCast failed : native session not exist";
            } else {
                context->errMessage = "StopCast failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "StopCast", executor, complete);
#else
    return nullptr;
#endif
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

napi_status NapiAVSessionManager::OnAudioSessionChecked(napi_env env, napi_value callback)
{
    return listener_->AddCallback(env, NapiSessionListener::EVENT_AUDIO_SESSION_CHECKED, callback);
}

napi_status NapiAVSessionManager::OnDeviceAvailable(napi_env env, napi_value callback)
{
    return listener_->AddCallback(env, NapiSessionListener::EVENT_DEVICE_AVAILABLE, callback);
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
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_SESSION_CREATED, callback);
}

napi_status NapiAVSessionManager::OffSessionDestroy(napi_env env, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_SESSION_DESTROYED, callback);
}

napi_status NapiAVSessionManager::OffTopSessionChange(napi_env env, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_TOP_SESSION_CHANGED, callback);
}

napi_status NapiAVSessionManager::OffAudioSessionChecked(napi_env env, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_AUDIO_SESSION_CHECKED, callback);
}

napi_status NapiAVSessionManager::OffDeviceAvailable(napi_env env, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_DEVICE_AVAILABLE, callback);
}

napi_status NapiAVSessionManager::OffServiceDie(napi_env env, napi_value callback)
{
    AVSessionManager::GetInstance().UnregisterServiceDeathCallback();
    if (callback == nullptr) {
        for (auto callbackRef = serviceDiedCallbacks_.begin(); callbackRef != serviceDiedCallbacks_.end();
             ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(napi_ok == ret, ret, "delete callback reference failed");
            *callbackRef = nullptr;
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
