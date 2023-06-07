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

#include "key_event.h"
#include "napi_async_work.h"
#include "napi_avcast_controller_callback.h"
#include "napi_avcast_controller.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_utils.h"
#include "napi_media_description.h"
#include "napi_queue_item.h"
#include "want_agent.h"
#include "avsession_errors.h"
#include "avsession_trace.h"
#include "napi_avsession_manager.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

#include "napi_cast_control_command.h"

namespace OHOS::AVSession {
static __thread napi_ref AVCastControllerConstructorRef = nullptr;
std::map<std::string, std::pair<NapiAVCastController::OnEventHandlerType,
    NapiAVCastController::OffEventHandlerType>> NapiAVCastController::EventHandlers_ = {
    { "stateChange", { OnStateChange, OffStateChange } },
    { "volumeChange", { OnVolumeChange, OffVolumeChange } },
    { "seekDone", { OnSeekDone, OffSeekDone } },
    { "speedDone", { OnSpeedDone, OffSpeedDone } },
    { "timeUpdate", { OnTimeUpdate, OffTimeUpdate } },
    { "error", { OnError, OffError } },
};

NapiAVCastController::NapiAVCastController()
{
    SLOGI("NapiAVCastController construct");
}

NapiAVCastController::~NapiAVCastController()
{
    SLOGI("NapiAVCastController destroy");
}

napi_value NapiAVCastController::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("sendControlCommand", SendControlCommand),
    };

    auto property_count = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor{};
    auto status = napi_define_class(env, "AVCastController", NAPI_AUTO_LENGTH, ConstructorCallback, nullptr,
        property_count, descriptors, &constructor);
    if (status != napi_ok) {
        SLOGE("define class failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_create_reference(env, constructor, 1, &AVCastControllerConstructorRef);
    return exports;
}

napi_value NapiAVCastController::ConstructorCallback(napi_env env, napi_callback_info info)
{
    napi_value self;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr), nullptr);

    auto finalize = [](napi_env env, void* data, void* hint) {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(data);
        napi_delete_reference(env, napiCastController->wrapperRef_);
        delete napiCastController;
    };

    auto* napiCastController = new(std::nothrow) NapiAVCastController();
    if (napiCastController == nullptr) {
        SLOGE("no memory");
        return nullptr;
    }
    if (napi_wrap(env, self, static_cast<void*>(napiCastController), finalize, nullptr,
        &(napiCastController->wrapperRef_)) != napi_ok) {
        SLOGE("wrap failed");
        return nullptr;
    }
    return self;
}

napi_status NapiAVCastController::NewInstance(napi_env env, std::shared_ptr<AVCastController>& nativeController,
    napi_value& out)
{
    napi_value constructor{};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, AVCastControllerConstructorRef, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);
    NapiAVCastController* napiCastController{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&napiCastController)), napi_generic_failure);
    napiCastController->castController_ = std::move(nativeController);
    napiCastController->surfaceId_ = napiCastController->castController_->GetSurfaceId();
    napiCastController->currentTime_ = napiCastController->castController_->GetCurrentIndex();

    napi_value property {};
    auto status = NapiUtils::SetValue(env, napiCastController->surfaceId_, property);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    NAPI_CALL_BASE(env, napi_set_named_property(env, instance, "surfaceId", property), napi_generic_failure);

    status = NapiUtils::SetValue(env, napiCastController->currentTime_, property);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    NAPI_CALL_BASE(env, napi_set_named_property(env, instance, "currentIndex", property), napi_generic_failure);

    out = instance;
    return napi_ok;
}

napi_value NapiAVCastController::Start(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::Start");
    struct ConcreteContext : public ContextBase {
        PlayInfoHolder playInfoHolder_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("Start failed : no memory");
        NapiUtils::ThrowError(env, "Start failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "Invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->playInfoHolder_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "Get play info holder failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_CAST_CONTROLLER_START_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("Start failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "Start failed : castController_ is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->Start(context->playInfoHolder_);
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, context->errMessage);
            SLOGE("CastController Start failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Start", executor, complete);
}

napi_value NapiAVCastController::SendControlCommand(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::SendControlCommand");
    struct ConcrentContext : public ContextBase {
        AVCastControlCommand castCommand_;
    };
    auto context = std::make_shared<ConcrentContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiCastControlCommand::GetValue(env, argv[ARGV_FIRST], context->castCommand_); // TODO:: add napi cast control command
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CAST_CONTROLLER_SEND_CONTROL_COMMAND;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("SendControlCommand failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "SendControlCommand failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->SendControlCommand(context->castCommand_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SendControlCommand failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "SendControlCommand failed : native controller not exist";
            } else if (ret == ERR_SESSION_DEACTIVE) {
                context->errMessage = "SendControlCommand failed : native session is not active";
            } else if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "SendControlCommand failed : native command not support";
            } else if (ret == ERR_COMMAND_SEND_EXCEED_MAX) {
                context->errMessage = "SendControlCommand failed : native command send nums overload";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SendControlCommand failed : native no permission";
            } else {
                context->errMessage = "SendControlCommand failed : native server exception";
            }
            SLOGE("controller SendControlCommand failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendControlCommand", executor);
}

napi_status NapiAVCastController::RegisterCallback(napi_env env, const std::shared_ptr<ContextBase>& context,
    const std::string& event, napi_value filter, napi_value callback)
{
    auto it = EventHandlers_.find(event);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return napi_generic_failure;
    }
    auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
    if (napiCastController->castController_ == nullptr) {
        SLOGE("OnEvent failed : controller is nullptr");
        NapiUtils::ThrowError(env, "OnEvent failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return napi_generic_failure;
    }
    if (napiCastController->callback_ == nullptr) {
        napiCastController->callback_= std::make_shared<NapiAVCastControllerCallback>();
        if (napiCastController->callback_ == nullptr) {
            SLOGE("OnEvent failed : no memory");
            NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
            return napi_generic_failure;
        }
        auto ret = napiCastController->castController_->RegisterCallback(napiCastController->callback_);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("controller RegisterCallback failed:%{public}d", ret);
            if (ret == ERR_CONTROLLER_NOT_EXIST) {
                NapiUtils::ThrowError(env, "OnEvent failed : native controller not exist",
                    NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
            } else if (ret == ERR_NO_MEMORY) {
                NapiUtils::ThrowError(env, "OnEvent failed : native no memory",
                    NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
            } else if (ret == ERR_NO_PERMISSION) {
                NapiUtils::ThrowError(env, "OnEvent failed : native no permission",
                    NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
            } else {
                NapiUtils::ThrowError(env, "OnEvent failed : native server exception",
                    NapiAVSessionManager::errcode_[ret]);
            }
            napiCastController->callback_ = nullptr;
            return napi_generic_failure;
        }
    }
    if (it->second.first(env, napiCastController, filter, callback) != napi_ok) {
        SLOGE("add event callback failed");
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return napi_generic_failure;
    }
    return napi_ok;
}

static bool IsThreeParamForOnEvent(const std::string& event)
{
    return event == "metadataChange" || event == "playbackStateChange";
}

napi_value NapiAVCastController::OnEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    std::string eventName;
    napi_value filter {};
    napi_value callback {};
    auto input = [&eventName, &callback, &filter, env, &context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc >= ARGC_ONE, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        napi_valuetype type = napi_undefined;
        if (!IsThreeParamForOnEvent(eventName)) {
            CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid argument number",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                                   "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            callback = argv[ARGV_SECOND];
        } else {
            CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THERE, "invalid argument number",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
            CHECK_ARGS_RETURN_VOID(
                context, (context->status == napi_ok) && (type == napi_object || type == napi_string),
                "Second param type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            filter = argv[ARGV_SECOND];
            context->status = napi_typeof(env, argv[ARGV_THIRD], &type);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                                   "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            callback = argv[ARGV_THIRD];
        }
    };
    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }
    RegisterCallback(env, context, eventName, filter, callback);

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVCastController::OffEvent(napi_env env, napi_callback_info info)
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
        bool isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
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

    auto it = EventHandlers_.find(eventName);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid:%{public}s", eventName.c_str());
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
    if (napiCastController->callback_ == nullptr) {
        SLOGI("function %{public}s not register yet", eventName.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.second(env, napiCastController, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_status NapiAVCastController::OnStateChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_STATE_CHANGE, callback);
}

napi_status NapiAVCastController::OnVolumeChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env, NapiAVCastControllerCallback::EVENT_CAST_VOLUME_CHANGE, callback);
}

napi_status NapiAVCastController::OnSeekDone(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env, NapiAVCastControllerCallback::EVENT_CAST_SEEK_DONE, callback);
}

napi_status NapiAVCastController::OnSpeedDone(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env, NapiAVCastControllerCallback::EVENT_CAST_SPEED_DONE, callback);
}

napi_status NapiAVCastController::OnTimeUpdate(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env, NapiAVCastControllerCallback::EVENT_CAST_TIME_UPDATE, callback);
}

napi_status NapiAVCastController::OnError(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env, NapiAVCastControllerCallback::EVENT_CAST_ERROR, callback);
}

napi_status NapiAVCastController::OffStateChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    return napiCastController->callback_->RemoveCallback(env, NapiAVCastControllerCallback::EVENT_CAST_STATE_CHANGE, callback);
}

napi_status NapiAVCastController::OffVolumeChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    return napiCastController->callback_->RemoveCallback(env, NapiAVCastControllerCallback::EVENT_CAST_VOLUME_CHANGE, callback);
}

napi_status NapiAVCastController::OffSeekDone(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    return napiCastController->callback_->RemoveCallback(env, NapiAVCastControllerCallback::EVENT_CAST_SEEK_DONE, callback);
}

napi_status NapiAVCastController::OffSpeedDone(napi_env env, NapiAVCastController* napiCastController, napi_value callback)
{
    return napiCastController->callback_->RemoveCallback(env, NapiAVCastControllerCallback::EVENT_CAST_SPEED_DONE, callback);
}

napi_status NapiAVCastController::OffTimeUpdate(napi_env env, NapiAVCastController* napiCastController, napi_value callback)
{
    return napiCastController->callback_->RemoveCallback(env, NapiAVCastControllerCallback::EVENT_CAST_TIME_UPDATE, callback);
}

napi_status NapiAVCastController::OffError(napi_env env, NapiAVCastController* napiCastController, napi_value callback)
{
    return napiCastController->callback_->RemoveCallback(env, NapiAVCastControllerCallback::EVENT_CAST_ERROR, callback);
}

void NapiAVCastController::ErrCodeToMessage(int32_t errCode, std::string& message)
{
    switch (errCode) {
        case ERR_SESSION_NOT_EXIST:
            message = "SetSessionEvent failed : native session not exist";
            break;
        case ERR_CONTROLLER_NOT_EXIST:
            message = "SendCommonCommand failed : native controller not exist";
            break;
        case ERR_SESSION_DEACTIVE:
            message = "SendCommonCommand failed : native session is not active";
            break;
        case ERR_NO_PERMISSION:
            message = "SetSessionEvent failed : native no permission";
            break;
        default:
            message = "SetSessionEvent failed : native server exception";
            break;
    }
}

}
