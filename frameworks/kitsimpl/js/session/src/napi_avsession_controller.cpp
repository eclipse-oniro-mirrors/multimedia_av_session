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

#include "napi_avsession_controller.h"
#include "key_event.h"
#include "want_agent.h"
#include "avplayback_state.h"
#include "napi_utils.h"
#include "napi_async_work.h"
#include "napi_avcontroller_callback.h"

using namespace std;

namespace OHOS::AVSession {
static __thread napi_ref AVControllerConstructorRef = nullptr;
std::map<std::string, NapiAVSessionController::OnEventHandlerType> NapiAVSessionController::onEventHandlers_ = {
    { "sessionDestroyed", OnSessionDestroy },
};

std::map<std::string, NapiAVSessionController::OffEventHandlerType> NapiAVSessionController::offEventHandlers_ = {
    { "sessionDestroyed", OffSessionDestroy },
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
    };

    auto property_count = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor{};
    auto status = napi_define_class(env, "AVSession", NAPI_AUTO_LENGTH, ConstructorCallback, nullptr,
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

napi_value NapiAVSessionController::OnEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    std::string eventName;
    napi_value callback {};
    auto input = [&eventName, &callback, env, &context](size_t argc, napi_value* argv) {
        /* require 2 arguments <event, callback> */
        CHECK_ARGS_RETURN_VOID(context, argc == 2, "invalid argument number");
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[0], &type);
        CHECK_RETURN_VOID((context->status == napi_ok) && (type == napi_string), "event name type invalid");
        context->status = NapiUtils::GetValue(env, argv[0], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed");

        context->status = napi_typeof(env, argv[1], &type);
        CHECK_RETURN_VOID((context->status == napi_ok) && (type == napi_function), "callback type invalid");
        callback = argv[1];
    };

    context->GetCbInfo(env, info, input, true);
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
    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->callback_ == nullptr) {
        napiController->callback_= std::make_shared<NapiAVControllerCallback>();
        SLOGE("no memory");
        napi_throw_error(env, nullptr, "no memory");
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second(env, napiController, callback) != napi_ok) {
        napi_throw_error(env, nullptr, "add event callback failed");
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

    auto it = offEventHandlers_.find(eventName);
    if (it == offEventHandlers_.end()) {
        SLOGE("event name invalid");
        napi_throw_error(env, nullptr, "event name invalid");
        return NapiUtils::GetUndefinedValue(env);
    }

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (it->second(env, napiController) != napi_ok) {
        napi_throw_error(env, nullptr, "remove event callback failed");
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_status NapiAVSessionController::OnSessionDestroy(napi_env env, NapiAVSessionController *napiController,
                                                      napi_value callback)
{
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_SESSION_DESTROY, callback);
}

napi_status NapiAVSessionController::OffSessionDestroy(napi_env env, NapiAVSessionController *napiController)
{
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_SESSION_DESTROY);
}
}