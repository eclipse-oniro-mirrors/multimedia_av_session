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
#include "napi_avcontroller_callback.h"
#include "napi_avsession_controller.h"
#include "napi_control_command.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_utils.h"
#include "want_agent.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
static __thread napi_ref AVControllerConstructorRef = nullptr;
std::map<std::string, std::pair<NapiAVSessionController::OnEventHandlerType,
    NapiAVSessionController::OffEventHandlerType>> NapiAVSessionController::EventHandlers_ = {
    { "sessionDestroyed", { OnSessionDestroy, OffSessionDestroy } },
    { "metadataChanged", { OnMetaDataChange, OffMetaDataChange } },
    { "playbackStateChanged", { OnPlaybackStateChange, OffPlaybackStateChange } },
    { "activeStateChanged", { OnActiveStateChange, OffActiveStateChange } },
    { "validCommandChanged", { OnValidCommandChange, OffValidCommandChange } },
    { "outputDeviceChanged", { OnOutputDeviceChanged, OffOutputDeviceChanged } },
};

NapiAVSessionController::NapiAVSessionController()
{
    SLOGI("construct");
}

NapiAVSessionController::~NapiAVSessionController()
{
    SLOGI("destroy");
}

napi_value NapiAVSessionController::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
        DECLARE_NAPI_FUNCTION("getAVPlaybackState", GetAVPlaybackState),
        DECLARE_NAPI_FUNCTION("getAVMetadata", GetAVMetaData),
        DECLARE_NAPI_FUNCTION("getOutputDevice", GetOutputDevice),
        DECLARE_NAPI_FUNCTION("sendAVKeyEvent", SendAVKeyEvent),
        DECLARE_NAPI_FUNCTION("getLaunchAbility", GetLaunchAbility),
        DECLARE_NAPI_FUNCTION("getRealPlaybackPositionSync", GetRealPlaybackPositionSync),
        DECLARE_NAPI_FUNCTION("isActive", IsSessionActive),
        DECLARE_NAPI_FUNCTION("destroy", Destroy),
        DECLARE_NAPI_FUNCTION("getValidCommands", GetValidCommands),
        DECLARE_NAPI_FUNCTION("sendControlCommand", SendControlCommand),
    };

    auto property_count = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor{};
    auto status = napi_define_class(env, "AVSessionController", NAPI_AUTO_LENGTH, ConstructorCallback, nullptr,
        property_count, descriptors, &constructor);
    if (status != napi_ok) {
        SLOGE("define class failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_create_reference(env, constructor, 1, &AVControllerConstructorRef);
    return exports;
}

napi_value NapiAVSessionController::ConstructorCallback(napi_env env, napi_callback_info info)
{
    napi_value self;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr), nullptr);

    auto finalize = [](napi_env env, void *data, void *hint) {
        auto *napiController = reinterpret_cast<NapiAVSessionController *>(data);
        napi_delete_reference(env, napiController->wrapperRef_);
        delete napiController;
    };

    auto *napiController = new(std::nothrow) NapiAVSessionController();
    if (napiController == nullptr) {
        SLOGE("no memory");
        return nullptr;
    }
    if (napi_wrap(env, self, static_cast<void *>(napiController), finalize, nullptr,
                  &(napiController->wrapperRef_)) != napi_ok) {
        SLOGE("wrap failed");
        return nullptr;
    }
    return self;
}

napi_status NapiAVSessionController::NewInstance(napi_env env, std::shared_ptr<AVSessionController> &nativeController,
    napi_value &out)
{
    napi_value constructor{};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, AVControllerConstructorRef, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);
    NapiAVSessionController *napiController{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void **>(&napiController)), napi_generic_failure);
    napiController->controller_ = std::move(nativeController);
    napiController->sessionId_ = napiController->controller_->GetSessionId();

    napi_value property {};
    auto status = NapiUtils::SetValue(env, napiController->sessionId_, property);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    NAPI_CALL_BASE(env, napi_set_named_property(env, instance, "sessionId", property), napi_generic_failure);

    out = instance;
    return napi_ok;
}

napi_value NapiAVSessionController::GetAVPlaybackState(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AVPlaybackState state;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
            SLOGE("native controller is nullptr");
            return;
        }
        int32_t ret = napiController->controller_->GetAVPlaybackState(context->state);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "controller GetAVPlaybackState failed";
            SLOGE("controller GetAVPlaybackState failed:%{public}d", ret);
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiPlaybackState::SetValue(env, context->state, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAVPlaybackState", executor, complete);
}

napi_value NapiAVSessionController::GetAVMetaData(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AVMetaData data;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
            SLOGE("native controller is nullptr");
            return;
        }
        int32_t ret = napiController->controller_->GetAVMetaData(context->data);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "controller GetAVMetaData failed";
            SLOGE("controller GetAVMetaData failed:%{public}d", ret);
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiMetaData::SetValue(env, context->data, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAVMetaData", executor, complete);
}

napi_value NapiAVSessionController::SendAVKeyEvent(napi_env env, napi_callback_info info)
{
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
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
            SLOGE("native controller is nullptr");
            return;
        }
        int32_t ret = napiController->controller_->SendAVKeyEvent(*context->keyEvent_);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "controller SendAVKeyEvent failed";
            SLOGE("controller SendAVKeyEvent failed:%{public}d", ret);
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendAVKeyEvent", executor);
}

napi_value NapiAVSessionController::GetLaunchAbility(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AbilityRuntime::WantAgent::WantAgent *ability {};
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
            SLOGE("native controller is nullptr");
            return;
        }
        int32_t ret = napiController->controller_->GetLaunchAbility(*context->ability);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "controller GetLaunchAbility failed";
            SLOGE("controller GetLaunchAbility failed:%{public}d", ret);
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiUtils::SetValue(env, context->ability, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
    };

    return NapiAsyncWork::Enqueue(env, context, "GetLaunchAbility", executor, complete);
}

napi_value NapiAVSessionController::GetValidCommands(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<std::string> stringCmds;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
            SLOGE("native controller is nullptr");
            return;
        }
        std::vector<int32_t> cmds;
        int32_t ret = napiController->controller_->GetValidCommands(cmds);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "controller GetValidCommands failed";
            SLOGE("controller GetValidCommands failed:%{public}d", ret);
        }
        context->stringCmds = NapiControlCommand::ConvertCommands(cmds);
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiUtils::SetValue(env, context->stringCmds, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
    };

    return NapiAsyncWork::Enqueue(env, context, "GetValidCommands", executor, complete);
}

napi_value NapiAVSessionController::IsSessionActive(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        bool isActive {};
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
            SLOGE("native controller is nullptr");
            return;
        }
        int32_t ret = napiController->controller_->IsSessionActive(context->isActive);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "controller IsSessionActive failed";
            SLOGE("controller IsSessionActive failed:%{public}d", ret);
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiUtils::SetValue(env, context->isActive, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
    };

    return NapiAsyncWork::Enqueue(env, context, "IsSessionActive", executor, complete);
}

napi_value NapiAVSessionController::SendControlCommand(napi_env env, napi_callback_info info)
{
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
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
            SLOGE("native controller is nullptr");
            return;
        }
        int32_t ret = napiController->controller_->SendControlCommand(context->command);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "controller SendControlCommand failed";
            SLOGE("controller SendControlCommand failed:%{public}d", ret);
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendControlCommand", executor);
}

napi_value NapiAVSessionController::Destroy(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
            SLOGE("native controller is nullptr");
            return;
        }
        int32_t ret = napiController->controller_->Destroy();
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->error = "controller Destroy failed";
            SLOGE("controller Destroy failed:%{public}d", ret);
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "IsSessionActive", executor);
}

napi_value NapiAVSessionController::GetRealPlaybackPositionSync(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGI("no controller");
        napi_throw_error(env, nullptr, "no controller");
        return NapiUtils::GetUndefinedValue(env);
    }

    auto position = napiController->controller_->GetRealPlaybackPosition();
    napi_value output {};
    auto status = NapiUtils::SetValue(env, static_cast<int64_t>(position), output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        napi_throw_error(env, nullptr, "convert native object to javascript object failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
}

napi_value NapiAVSessionController::GetOutputDevice(napi_env env, napi_callback_info info)
{
    SLOGI("not implement");
    napi_throw_error(env, nullptr, "not implement");
    return NapiUtils::GetUndefinedValue(env);
}

napi_status NapiAVSessionController::SetPlaybackStateFilter(napi_env env, NapiAVSessionController *napiController,
                                                            napi_value filter)
{
    AVPlaybackState::PlaybackStateMaskType playbackMask;
    auto status = NapiPlaybackState::ConvertFilter(env, filter, playbackMask);
    CHECK_RETURN(status == napi_ok, "convert filter failed", status);
    auto ret = napiController->controller_->SetPlaybackFilter(playbackMask);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller SetPlaybackFilter failed:%{public}d", ret);
        status = napi_generic_failure;
    }
    return status;
}

napi_status NapiAVSessionController::SetMetaFilter(napi_env env, NapiAVSessionController *napiController,
                                                   napi_value filter)
{
    AVMetaData::MetaMaskType metaMask;
    auto status = NapiMetaData::ConvertFilter(env, filter, metaMask);
    CHECK_RETURN(status == napi_ok, "convert filter failed", status);
    auto ret = napiController->controller_->SetMetaFilter(metaMask);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller SetMetaFilter failed:%{public}d", ret);
        status = napi_generic_failure;
    }
    return status;
}

napi_status NapiAVSessionController::RegisterCallback(napi_env env, const std::shared_ptr<ContextBase>& context,
    const std::string& event, napi_value filter, napi_value callback)
{
    auto it = EventHandlers_.find(event);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid");
        return napi_generic_failure;
    }
    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGE("native controller is nullptr");
        return napi_generic_failure;
    }
    if (napiController->callback_ == nullptr) {
        napiController->callback_= std::make_shared<NapiAVControllerCallback>();
        if (napiController->callback_ == nullptr) {
            SLOGE("no memory");
            return napi_generic_failure;
        }
        auto ret = napiController->controller_->RegisterCallback(napiController->callback_);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("controller RegisterCallback failed:%{public}d", ret);
            return napi_generic_failure;
        }
    }
    if (it->second.first(env, napiController, filter, callback) != napi_ok) {
        SLOGE("add event callback failed");
        return napi_generic_failure;
    }
    return napi_ok;
}

static bool IsThreeParamForOnEvent(const std::string& event)
{
    return event == "metadataChanged" || event == "playbackStateChanged";
}

napi_value NapiAVSessionController::OnEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    std::string eventName;
    napi_value filter {};
    napi_value callback {};
    auto input = [&eventName, &callback, &filter, env, &context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc >= ARGC_ONE, "invalid argument number");
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed");
        napi_valuetype type = napi_undefined;
        if (!IsThreeParamForOnEvent(eventName)) {
            CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid argument number");
            context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                                   "callback type invalid");
            callback = argv[ARGV_SECOND];
        } else {
            CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THERE, "invalid argument number");
            context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
            CHECK_ARGS_RETURN_VOID(
                context, (context->status == napi_ok) && (type == napi_object || type == napi_string),
                "filter type invalid");
            filter = argv[ARGV_SECOND];
            context->status = napi_typeof(env, argv[ARGV_THIRD], &type);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                                   "callback type invalid");
            callback = argv[ARGV_THIRD];
        }
    };
    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        napi_throw_error(env, nullptr, context->error.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }

    if (RegisterCallback(env, context, eventName, filter, callback) != napi_ok) {
        napi_throw_error(env, nullptr, "OnEvent RegisterCallback fail");
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionController::OffEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    std::string eventName;
    auto input = [&eventName, env, &context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid argument number");
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed");
    };

    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        napi_throw_error(env, nullptr, context->error.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }

    auto it = EventHandlers_.find(eventName);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid:%{public}s", eventName.c_str());
        napi_throw_error(env, nullptr, "event name invalid");
        return NapiUtils::GetUndefinedValue(env);
    }

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->callback_ == nullptr) {
        SLOGI("function %{public}s not register yet", eventName.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.second(env, napiController) != napi_ok) {
        napi_throw_error(env, nullptr, "remove event callback failed");
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_status NapiAVSessionController::OnSessionDestroy(napi_env env, NapiAVSessionController *napiController,
                                                      napi_value param, napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_SESSION_DESTROY, callback);
}

napi_status NapiAVSessionController::OnPlaybackStateChange(napi_env env, NapiAVSessionController* napiController,
                                                           napi_value param, napi_value callback)
{
    if (SetPlaybackStateFilter(env, napiController, param) != napi_ok) {
        return napi_generic_failure;
    }
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_PLAYBACK_STATE_CHANGE,
                                                  callback);
}

napi_status NapiAVSessionController::OnMetaDataChange(napi_env env, NapiAVSessionController* napiController,
                                                      napi_value param, napi_value callback)
{
    if (SetMetaFilter(env, napiController, param) != napi_ok) {
        return napi_generic_failure;
    }
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_META_DATA_CHANGE, callback);
}

napi_status NapiAVSessionController::OnActiveStateChange(napi_env env, NapiAVSessionController* napiController,
                                                         napi_value param, napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_ACTIVE_STATE_CHANGE, callback);
}

napi_status NapiAVSessionController::OnValidCommandChange(napi_env env, NapiAVSessionController* napiController,
                                                          napi_value param, napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_VALID_COMMAND_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OnOutputDeviceChanged(napi_env env, NapiAVSessionController* napiController,
                                                           napi_value param, napi_value callback)
{
    return napi_generic_failure;
}

napi_status NapiAVSessionController::OffSessionDestroy(napi_env env, NapiAVSessionController *napiController)
{
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_SESSION_DESTROY);
}

napi_status NapiAVSessionController::OffPlaybackStateChange(napi_env env, NapiAVSessionController* napiController)
{
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_PLAYBACK_STATE_CHANGE);
}

napi_status NapiAVSessionController::OffMetaDataChange(napi_env env, NapiAVSessionController* napiController)
{
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_META_DATA_CHANGE);
}

napi_status NapiAVSessionController::OffActiveStateChange(napi_env env, NapiAVSessionController* napiController)
{
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_ACTIVE_STATE_CHANGE);
}

napi_status NapiAVSessionController::OffValidCommandChange(napi_env env, NapiAVSessionController* napiController)
{
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_VALID_COMMAND_CHANGE);
}

napi_status NapiAVSessionController::OffOutputDeviceChanged(napi_env env, NapiAVSessionController* napiController)
{
    return napi_generic_failure;
}
}