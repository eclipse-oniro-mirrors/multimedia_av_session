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

#include "avsession_errors.h"
#include "key_event.h"
#include "napi_async_work.h"
#include "napi_avcontroller_callback.h"
#include "napi_avsession_controller.h"
#include "napi_control_command.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_utils.h"
#include "want_agent.h"

using namespace std;

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
        DECLARE_NAPI_STATIC_FUNCTION("on", OnEvent),
        DECLARE_NAPI_STATIC_FUNCTION("off", OffEvent),
        DECLARE_NAPI_STATIC_FUNCTION("getAVPlaybackState", GetAVPlaybackState),
        DECLARE_NAPI_STATIC_FUNCTION("getAVMetadata", GetAVMetaData),
        DECLARE_NAPI_STATIC_FUNCTION("getOutputDevice", GetOutputDevice),
        DECLARE_NAPI_STATIC_FUNCTION("sendAVKeyEvent", SendAVKeyEvent),
        DECLARE_NAPI_STATIC_FUNCTION("getLaunchAbility", GetLaunchAbility),
        DECLARE_NAPI_STATIC_FUNCTION("getRealPlaybackPositionSync", GetRealPlaybackPosition),
        DECLARE_NAPI_STATIC_FUNCTION("isActive", IsSessionActive),
        DECLARE_NAPI_STATIC_FUNCTION("destroy", Release),
        DECLARE_NAPI_STATIC_FUNCTION("getValidCommands", GetValidCommands),
        DECLARE_NAPI_STATIC_FUNCTION("sendControlCommand", SendControlCommand),
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
        } else {
            int32_t ret = napiController->controller_->GetAVPlaybackState(context->state);
            if (ret != AVSESSION_SUCCESS) {
                context->status = napi_generic_failure;
                context->error = "controller GetAVPlaybackState failed";
                SLOGE("controller GetAVPlaybackState failed:%{public}d", ret);
            }
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
        } else {
            int32_t ret = napiController->controller_->GetAVMetaData(context->data);
            if (ret != AVSESSION_SUCCESS) {
                context->status = napi_generic_failure;
                context->error = "controller GetAVMetaData failed";
                SLOGE("controller GetAVMetaData failed:%{public}d", ret);
            }
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
        // require 1 arguments <sessionId>
        CHECK_ARGS_RETURN_VOID(context, argc == 1, "invalid arguments");
        context->status = NapiUtils::GetValue(env, argv[0], context->keyEvent_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (context->keyEvent_ != nullptr),
            "invalid keyEvent");
    };
    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
        } else {
            int32_t ret = napiController->controller_->SendAVKeyEvent(*context->keyEvent_);
            if (ret != AVSESSION_SUCCESS) {
                context->status = napi_generic_failure;
                context->error = "controller SendAVKeyEvent failed";
                SLOGE("controller SendAVKeyEvent failed:%{public}d", ret);
            }
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
        } else {
            int32_t ret = napiController->controller_->GetLaunchAbility(*context->ability);
            if (ret != AVSESSION_SUCCESS) {
                context->status = napi_generic_failure;
                context->error = "controller GetLaunchAbility failed";
                SLOGE("controller GetLaunchAbility failed:%{public}d", ret);
            }
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
        std::vector<int32_t> cmds;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
        } else {
            int32_t ret = napiController->controller_->GetValidCommands(context->cmds);
            if (ret != AVSESSION_SUCCESS) {
                context->status = napi_generic_failure;
                context->error = "controller GetValidCommands failed";
                SLOGE("controller GetValidCommands failed:%{public}d", ret);
            }
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiUtils::SetValue(env, context->cmds, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
    };

    return NapiAsyncWork::Enqueue(env, context, "GetValidCommands", executor, complete);
}

napi_value NapiAVSessionController::IsSessionActive(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        bool isActive;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
        } else {
            int32_t ret = napiController->controller_->IsSessionActive(context->isActive);
            if (ret != AVSESSION_SUCCESS) {
                context->status = napi_generic_failure;
                context->error = "controller IsSessionActive failed";
                SLOGE("controller IsSessionActive failed:%{public}d", ret);
            }
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
        // require 1 arguments <command>
        CHECK_ARGS_RETURN_VOID(context, argc == 1, "invalid arguments");
        context->status = NapiControlCommand::GetValue(env, argv[0], context->command);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command");
    };
    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
        } else {
            int32_t ret = napiController->controller_->SendControlCommand(context->command);
            if (ret != AVSESSION_SUCCESS) {
                context->status = napi_generic_failure;
                context->error = "controller SendControlCommand failed";
                SLOGE("controller SendControlCommand failed:%{public}d", ret);
            }
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendControlCommand", executor);
}

napi_value NapiAVSessionController::Release(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
        } else {
            int32_t ret = napiController->controller_->Release();
            if (ret != AVSESSION_SUCCESS) {
                context->status = napi_generic_failure;
                context->error = "controller Release failed";
                SLOGE("controller Release failed:%{public}d", ret);
            }
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "IsSessionActive", executor);
}

napi_value NapiAVSessionController::GetRealPlaybackPosition(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        uint64_t position;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->error = "no controller";
        } else {
            context->position = napiController->controller_->GetRealPlaybackPosition();
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = NapiUtils::SetValue(env, static_cast<int64_t>(context->position), output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed");
    };

    return NapiAsyncWork::Enqueue(env, context, "GetRealPlaybackPosition", executor, complete);
}

napi_value NapiAVSessionController::GetOutputDevice(napi_env env, napi_callback_info info)
{
    SLOGI("not implement");
    napi_throw_error(env, nullptr, "not implement");
    return NapiUtils::GetUndefinedValue(env);
}

napi_status NapiAVSessionController::GetfiltersByNapi(napi_env env, std::vector<std::string> &filters,
    napi_value filter)
{
    napi_value value {};
    uint32_t count = 0;
    std::string res;
    auto status = napi_get_array_length(env, filter, &count);
    CHECK_RETURN(status == napi_ok, "get array length failed", status);
    for (uint32_t i = 0; i < count; i++) {
        status = napi_get_element(env, filter, i, &value);
        CHECK_RETURN(status == napi_ok, "get element failed", status);
        status = NapiUtils::GetValue(env, value, res);
        CHECK_RETURN(status == napi_ok, "get string value failed", status);
        filters.push_back(res);
    }
    return napi_ok;
}

napi_status NapiAVSessionController::SetPlaybackStateFilter(napi_env env, NapiAVSessionController *napiController,
    napi_value filter)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, filter, &valueType);
    AVPlaybackState::PlaybackStateMaskType playbackMaskType;
    std::vector<std::string> filters;
    int32_t ret = 0;
    napi_status status = napi_ok;
    if (valueType == napi_string) {
        std::string filterStr;
        status = NapiUtils::GetValue(env, filter, filterStr);
        CHECK_RETURN(status == napi_ok && !filterStr.empty(), "get property failed", status);
        CHECK_RETURN(filterStr == "all", "string filter Only support all", napi_generic_failure);
        playbackMaskType.set();
        ret = napiController->controller_->SetPlaybackFilter(playbackMaskType);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("controller SetPlaybackFilter failed:%{public}d", ret);
            status = napi_generic_failure;
        }
        return status;
    }

    status = GetfiltersByNapi(env, filters, filter);
    CHECK_RETURN(status == napi_ok, "GetfiltersByNapi failed", status);
    playbackMaskType = NapiPlaybackState::ConvertFilter(filters);
    ret = napiController->controller_->SetPlaybackFilter(playbackMaskType);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller SetPlaybackFilter failed:%{public}d", ret);
        status = napi_generic_failure;
    }
    return status;
}

napi_status NapiAVSessionController::SetMetaFilter(napi_env env, NapiAVSessionController *napiController, napi_value filter)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, filter, &valueType);
    AVMetaData::MetaMaskType metaMaskType;
    std::vector<std::string> filters;
    int32_t ret = 0;
    napi_status status = napi_ok;
    if (valueType == napi_string) {
        std::string filterStr;
        status = NapiUtils::GetValue(env, filter, filterStr);
        CHECK_RETURN(status == napi_ok && !filterStr.empty(), "get property failed", status);
        CHECK_RETURN(filterStr == "all", "string filter Only support all", napi_generic_failure);
        metaMaskType.set();
        ret = napiController->controller_->SetMetaFilter(metaMaskType);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("controller SetMetaFilter failed:%{public}d", ret);
            status = napi_generic_failure;
        }
        return status;
    }

    status = GetfiltersByNapi(env, filters, filter);
    CHECK_RETURN(status == napi_ok, "GetfiltersByNapi failed", status);
    metaMaskType = NapiMetaData::ConvertFilter(filters);
    ret = napiController->controller_->SetMetaFilter(metaMaskType);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller SetMetaFilter failed:%{public}d", ret);
        status = napi_generic_failure;
    }
    return status;
}

napi_status NapiAVSessionController::RegisterCallback(napi_env env, NapiAVSessionController *napiController,
    std::string eventName, napi_value filter, napi_value callback)
{
    auto it = EventHandlers_.find(eventName);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid");
        return napi_generic_failure;
    }

    if (napiController->controller_ == nullptr) {
        SLOGE("no controller");
        return napi_generic_failure;
    }

    if (eventName == "playbackStateChanged" &&
        SetPlaybackStateFilter(env, napiController, filter) != napi_ok) {
        SLOGE("controller SetPlaybackStateFilter failed");
        return napi_generic_failure;
    } else if (eventName == "metadataChanged" &&
        SetMetaFilter(env, napiController, filter) != napi_ok) {
        SLOGE("controller SetMetaFilter failed");
        return napi_generic_failure;
    }

    if (napiController->callback_ == nullptr) {
        napiController->callback_= std::make_shared<NapiAVControllerCallback>();
        if (napiController->callback_ == nullptr) {
            SLOGE("no memory");
            return napi_generic_failure;
        }
        int32_t ret = napiController->controller_->RegisterCallback(napiController->callback_);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("controller RegisterCallback failed:%{public}d", ret);
            return napi_generic_failure;
        }
    }

    if (it->second.first(env, napiController, callback) != napi_ok) {
        SLOGE("add event callback failed");
        return napi_generic_failure;
    }
    return napi_ok;
}

napi_value NapiAVSessionController::OnEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    std::string eventName;
    napi_value callback {};
    napi_value filter {};
    auto input = [&eventName, &callback, &filter, env, &context](size_t argc, napi_value* argv) {
        /* require 2 or 3 arguments <event, callback> */
        CHECK_ARGS_RETURN_VOID(context, argc >= ARGC_TWO, "invalid argument number");
        CHECK_ARGS_RETURN_VOID(context, argc <= ARGC_THERE, "invalid argument number");
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[0], &type);
        CHECK_RETURN_VOID((context->status == napi_ok) && (type == napi_string), "event name type invalid");
        context->status = NapiUtils::GetValue(env, argv[0], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed");
        if (argc == 2) {
            context->status = napi_typeof(env, argv[1], &type);
            CHECK_RETURN_VOID((context->status == napi_ok) && (type == napi_function), "callback type invalid");
            callback = argv[1];
            return;
        }
        context->status = napi_typeof(env, argv[2], &type);
        CHECK_RETURN_VOID((context->status == napi_ok) && (type == napi_function), "callback type invalid");
        callback = argv[2];
        filter = argv[1];
    };

    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        napi_throw_error(env, nullptr, context->error.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);

    napi_status ret = RegisterCallback(env, napiController, eventName, filter, callback);
    if (ret != napi_ok) {
        napi_throw_error(env, nullptr, "OnEvent RegisterCallback fail");
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionController::OffEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    std::string eventName;
    auto input = [&eventName, env, &context](size_t argc, napi_value* argv) {
        /* require 1 arguments <event> */
        CHECK_ARGS_RETURN_VOID(context, argc == 1, "invalid argument number");
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[0], &type);
        CHECK_RETURN_VOID((context->status == napi_ok) && (type == napi_string), "event name type invalid");
        context->status = NapiUtils::GetValue(env, argv[0], eventName);
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
    napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_SESSION_DESTROY, callback);
}

napi_status NapiAVSessionController::OnPlaybackStateChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_PLAYBACK_STATE_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OnMetaDataChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_META_DATA_CHANGE, callback);
}

napi_status NapiAVSessionController::OnActiveStateChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_ACTIVE_STATE_CHANGE, callback);
}

napi_status NapiAVSessionController::OnValidCommandChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_VALID_COMMAND_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OnOutputDeviceChanged(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
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