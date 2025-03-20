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

#include "napi_avcall_meta_data.h"
#include "napi_avcall_state.h"
#include "key_event.h"
#include "napi_async_work.h"
#include "napi_avcontroller_callback.h"
#include "napi_avsession_controller.h"
#include "napi_control_command.h"
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

namespace OHOS::AVSession {
static __thread napi_ref AVControllerConstructorRef = nullptr;
std::map<std::string, std::pair<NapiAVSessionController::OnEventHandlerType,
    NapiAVSessionController::OffEventHandlerType>> NapiAVSessionController::EventHandlers_ = {
    { "callMetadataChange", { OnAVCallMetaDataChange, OffAVCallMetaDataChange } },
    { "callStateChange", { OnAVCallStateChange, OffAVCallStateChange } },
    { "sessionDestroy", { OnSessionDestroy, OffSessionDestroy } },
    { "metadataChange", { OnMetaDataChange, OffMetaDataChange } },
    { "playbackStateChange", { OnPlaybackStateChange, OffPlaybackStateChange } },
    { "activeStateChange", { OnActiveStateChange, OffActiveStateChange } },
    { "validCommandChange", { OnValidCommandChange, OffValidCommandChange } },
    { "outputDeviceChange", { OnOutputDeviceChange, OffOutputDeviceChange } },
    { "sessionEvent", { OnSessionEventChange, OffSessionEventChange } },
    { "queueItemsChange", { OnQueueItemsChange, OffQueueItemsChange } },
    { "queueTitleChange", { OnQueueTitleChange, OffQueueTitleChange } },
    { "extrasChange", { OnExtrasChange, OffExtrasChange } },
};
std::map<std::string, NapiAVSessionController> NapiAVSessionController::ControllerList_ = {};
std::mutex NapiAVSessionController::uvMutex_;
std::mutex NapiAVSessionController::controllerListMutex_;

NapiAVSessionController::NapiAVSessionController()
{
    SLOGI("construct");
}

NapiAVSessionController::~NapiAVSessionController()
{
    SLOGI("destroy");
    if (controller_ != nullptr) {
        controller_->Destroy();
    }
}

napi_value NapiAVSessionController::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
        DECLARE_NAPI_FUNCTION("getAVCallState", GetAVCallState),
        DECLARE_NAPI_FUNCTION("getCallMetadata", GetAVCallMetaData),
        DECLARE_NAPI_FUNCTION("getAVPlaybackState", GetAVPlaybackState),
        DECLARE_NAPI_FUNCTION("getAVPlaybackStateSync", GetAVPlaybackStateSync),
        DECLARE_NAPI_FUNCTION("getAVMetadata", GetAVMetaData),
        DECLARE_NAPI_FUNCTION("getAVMetadataSync", GetAVMetaDataSync),
        DECLARE_NAPI_FUNCTION("getOutputDevice", GetOutputDevice),
        DECLARE_NAPI_FUNCTION("getOutputDeviceSync", GetOutputDeviceSync),
        DECLARE_NAPI_FUNCTION("sendAVKeyEvent", SendAVKeyEvent),
        DECLARE_NAPI_FUNCTION("getLaunchAbility", GetLaunchAbility),
        DECLARE_NAPI_FUNCTION("getRealPlaybackPositionSync", GetRealPlaybackPositionSync),
        DECLARE_NAPI_FUNCTION("isActive", IsSessionActive),
        DECLARE_NAPI_FUNCTION("isActiveSync", IsSessionActiveSync),
        DECLARE_NAPI_FUNCTION("destroy", Destroy),
        DECLARE_NAPI_FUNCTION("getValidCommands", GetValidCommands),
        DECLARE_NAPI_FUNCTION("getValidCommandsSync", GetValidCommandsSync),
        DECLARE_NAPI_FUNCTION("sendControlCommand", SendControlCommand),
        DECLARE_NAPI_FUNCTION("sendCommonCommand", SendCommonCommand),
        DECLARE_NAPI_FUNCTION("getAVQueueItems", GetAVQueueItems),
        DECLARE_NAPI_FUNCTION("getAVQueueItemsSync", GetAVQueueItemsSync),
        DECLARE_NAPI_FUNCTION("getAVQueueTitle", GetAVQueueTitle),
        DECLARE_NAPI_FUNCTION("getAVQueueTitleSync", GetAVQueueTitleSync),
        DECLARE_NAPI_FUNCTION("skipToQueueItem", SkipToQueueItem),
        DECLARE_NAPI_FUNCTION("getExtras", GetExtras),
        DECLARE_NAPI_FUNCTION("getExtrasWithEvent", GetExtrasWithEvent),
    };

    auto property_count = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor {};
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

    auto finalize = [](napi_env env, void* data, void* hint) {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(data);
        napi_delete_reference(env, napiController->wrapperRef_);
        delete napiController;
        napiController = nullptr;
    };

    auto* napiController = new(std::nothrow) NapiAVSessionController();
    if (napiController == nullptr) {
        SLOGE("no memory");
        return nullptr;
    }
    if (napi_wrap(env, self, static_cast<void*>(napiController), finalize, nullptr, nullptr) != napi_ok) {
        SLOGE("wrap failed");
        delete napiController;
        napiController = nullptr;
        return nullptr;
    }
    return self;
}

napi_status NapiAVSessionController::NewInstance(
    napi_env env, const std::shared_ptr<AVSessionController>& nativeController, napi_value& out)
{
    napi_value constructor {};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, AVControllerConstructorRef, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);
    CHECK_RETURN(nativeController != nullptr, "get native controller failed with null", napi_generic_failure);
    NapiAVSessionController* napiController{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&napiController)), napi_generic_failure);
    napiController->controller_ = std::move(nativeController);
    napiController->sessionId_ = napiController->controller_->GetSessionId();

    CHECK_RETURN(DoRegisterCallback(env, napiController) == napi_ok, "add callback failed", napi_generic_failure);
    SLOGD("add napiController instance prelock for sessionId: %{public}s", napiController->sessionId_.c_str());
    std::lock_guard<std::mutex> lock(controllerListMutex_);
    SLOGI("add napiController instance aftlock for sessionId: %{public}s", napiController->sessionId_.c_str());
    ControllerList_[napiController->sessionId_] = *napiController;
    napi_value property {};
    auto status = NapiUtils::SetValue(env, napiController->sessionId_, property);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    NAPI_CALL_BASE(env, napi_set_named_property(env, instance, "sessionId", property), napi_generic_failure);

    out = instance;
    return napi_ok;
}

napi_status NapiAVSessionController::RepeatedInstance(napi_env env, const std::string& controllerId, napi_value& out)
{
    napi_value constructor {};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, AVControllerConstructorRef, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);
    NapiAVSessionController* napiController{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&napiController)), napi_generic_failure);
    SLOGD("check repeat controller prelock with sessionId %{public}s", controllerId.c_str());
    std::lock_guard<std::mutex> lock(controllerListMutex_);
    SLOGI("check repeat controller aftlock with sessionId %{public}s", controllerId.c_str());
    if (ControllerList_.count(controllerId) <= 0) {
        SLOGE("check repeat without cur session");
        return napi_generic_failure;
    }

    NapiAVSessionController* repeatedNapiController = &(ControllerList_[controllerId]);
    napiController->controller_ = repeatedNapiController->controller_;
    napiController->sessionId_ = repeatedNapiController->sessionId_;
    napiController->callback_ = repeatedNapiController->callback_;
    SLOGI("check repeat controller for copy res %{public}d", (napiController->controller_ == nullptr));

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
            SLOGE("GetAVPlaybackState failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetAVPlaybackState failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetAVPlaybackState(context->state);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAVPlaybackState failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetAVPlaybackState failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAVPlaybackState failed : native no permission";
            } else {
                context->errMessage = "GetAVPlaybackState failed : native server exception";
            }
            SLOGE("controller GetAVPlaybackState failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiPlaybackState::SetValue(env, context->state, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetAVPlayback", executor, complete);
}

napi_value NapiAVSessionController::GetAVPlaybackStateSync(napi_env env, napi_callback_info info)
{
    SLOGD("Start GetAVPlaybackStateSync");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    context->GetCbInfo(env, info, NapiCbInfoParser(), true);
    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGI("GetAVPlaybackStateSync failed : controller is nullptr");
        NapiUtils::ThrowError(env, "GetAVPlaybackStateSync failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }

    AVPlaybackState state;
    int32_t ret = napiController->controller_->GetAVPlaybackState(state);
    SLOGD("Get playback state: %{public}d", state.GetState());
    if (ret != AVSESSION_SUCCESS) {
        std::string errMessage;
        if (ret == ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVPlaybackStateSync failed : native session not exist";
        } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVPlaybackStateSync failed : native controller not exist";
        } else if (ret == ERR_NO_PERMISSION) {
            errMessage = "GetAVPlaybackStateSync failed : native no permission";
        } else {
            ret = AVSESSION_ERROR;
            errMessage = "GetAVPlaybackStateSync failed : native server exception";
        }
        SLOGE("controller GetAVPlaybackStateSync failed:%{public}d", ret);
        NapiUtils::ThrowError(env, errMessage.c_str(), NapiAVSessionManager::errcode_[ret]);
        return NapiUtils::GetUndefinedValue(env);
    }

    napi_value output {};
    auto status = NapiUtils::SetValue(env, state, output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        NapiUtils::ThrowError(env, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
}

napi_value NapiAVSessionController::GetAVCallMetaData(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AVCallMetaData avCallMetaData;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("GetAVCallMetaData failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetAVCallMetaData failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetAVCallMetaData(context->avCallMetaData);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAVCallMetaData failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetAVCallMetaData failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAVCallMetaData failed : native no permission";
            } else {
                context->errMessage = "GetAVCallMetaData failed : native server exception";
            }
            SLOGE("controller GetAVCallMetaData failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiAVCallMetaData::SetValue(env, context->avCallMetaData, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAVCallMetaData", executor, complete);
}

napi_value NapiAVSessionController::GetAVCallState(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AVCallState avCallState;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("GetAVCallState failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetAVCallState failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetAVCallState(context->avCallState);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAVCallState failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetAVCallState failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAVCallState failed : native no permission";
            } else {
                context->errMessage = "GetAVCallState failed : native server exception";
            }
            SLOGE("controller GetAVCallState failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiAVCallState::SetValue(env, context->avCallState, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetAVCallState", executor, complete);
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
            SLOGE("GetAVMetaData failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetAVMetaData failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetAVMetaData(context->data);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAVMetaData failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetAVMetaData failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAVMetaData failed : native no permission";
            } else {
                context->errMessage = "GetAVMetaData failed : native server exception";
            }
            SLOGE("controller GetAVMetaData failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiMetaData::SetValue(env, context->data, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        SLOGI("metadata get done, clear cache");
        context->data.Reset();
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAVMetaData", executor, complete);
}

napi_value NapiAVSessionController::GetAVMetaDataSync(napi_env env, napi_callback_info info)
{
    SLOGD("Start GetAVMetaDataSync");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGE("GetAVMetaDataSync failed : controller is nullptr");
        NapiUtils::ThrowError(env, "GetAVMetaDataSync failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    AVMetaData data;
    int32_t ret = napiController->controller_->GetAVMetaData(data);
    if (ret != AVSESSION_SUCCESS) {
        std::string errMessage;
        if (ret == ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVMetaDataSync failed : native session not exist";
        } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVMetaDataSync failed : native controller not exist";
        } else if (ret == ERR_NO_PERMISSION) {
            errMessage = "GetAVMetaDataSync failed : native no permission";
        } else {
            ret = AVSESSION_ERROR;
            errMessage = "GetAVMetaDataSync failed : native server exception";
        }
        SLOGE("controller GetAVMetaDataSync failed:%{public}d", ret);
        NapiUtils::ThrowError(env, errMessage.c_str(), NapiAVSessionManager::errcode_[ret]);
        return NapiUtils::GetUndefinedValue(env);
    }

    napi_value output {};
    auto status = NapiUtils::SetValue(env, data, output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        NapiUtils::ThrowError(env, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
}

napi_value NapiAVSessionController::GetAVQueueItems(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<AVQueueItem> items_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("GetAVQueueItems failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetAVQueueItems failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetAVQueueItems(context->items_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAVQueueItems failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetAVQueueItems failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAVQueueItems failed : native no permission";
            } else {
                context->errMessage = "GetAVQueueItems failed : native server exception";
            }
            SLOGE("controller GetAVQueueItems failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->items_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAVQueueItems", executor, complete);
}

napi_value NapiAVSessionController::GetAVQueueItemsSync(napi_env env, napi_callback_info info)
{
    SLOGD("Start GetAVQueueItemsSync");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGE("GetAVQueueItemsSync failed : controller is nullptr");
        NapiUtils::ThrowError(env, "GetAVQueueItemsSync failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    std::vector<AVQueueItem> items;
    int32_t ret = napiController->controller_->GetAVQueueItems(items);
    SLOGD("Get queueItem size: %{public}zu", items.size());
    if (ret != AVSESSION_SUCCESS) {
        std::string errMessage;
        if (ret == ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVQueueItemsSync failed : native session not exist";
        } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVQueueItemsSync failed : native controller not exist";
        } else if (ret == ERR_NO_PERMISSION) {
            errMessage = "GetAVQueueItemsSync failed : native no permission";
        } else {
            ret = AVSESSION_ERROR;
            errMessage = "GetAVQueueItemsSync failed : native server exception";
        }
        SLOGE("controller GetAVQueueItemsSync failed:%{public}d", ret);
        NapiUtils::ThrowError(env, errMessage.c_str(), NapiAVSessionManager::errcode_[ret]);
        return NapiUtils::GetUndefinedValue(env);
    }

    napi_value output {};
    auto status = NapiUtils::SetValue(env, items, output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        NapiUtils::ThrowError(env, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
}

napi_value NapiAVSessionController::GetAVQueueTitle(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::string title_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("GetAVQueueTitle failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetAVQueueTitle failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetAVQueueTitle(context->title_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAVQueueTitle failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetAVQueueTitle failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAVQueueTitle failed : native no permission";
            } else {
                context->errMessage = "GetAVQueueTitle failed : native server exception";
            }
            SLOGE("controller GetAVQueueTitle failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->title_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAVQueueTitle", executor, complete);
}

napi_value NapiAVSessionController::GetAVQueueTitleSync(napi_env env, napi_callback_info info)
{
    SLOGD("Start GetAVQueueTitleSync");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGE("GetAVQueueTitleSync failed : controller is nullptr");
        NapiUtils::ThrowError(env, "GetAVQueueTitleSync failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    std::string title;
    int32_t ret = napiController->controller_->GetAVQueueTitle(title);
    SLOGD("Get queue title: %{public}s", title.c_str());
    if (ret != AVSESSION_SUCCESS) {
        std::string errMessage;
        if (ret == ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVQueueTitleSync failed : native session not exist";
        } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVQueueTitleSync failed : native controller not exist";
        } else if (ret == ERR_NO_PERMISSION) {
            errMessage = "GetAVQueueTitleSync failed : native no permission";
        } else {
            ret = AVSESSION_ERROR;
            errMessage = "GetAVQueueTitleSync failed : native server exception";
        }
        SLOGE("controller GetAVQueueTitleSync failed:%{public}d", ret);
        NapiUtils::ThrowError(env, errMessage.c_str(), NapiAVSessionManager::errcode_[ret]);
        return NapiUtils::GetUndefinedValue(env);
    }

    napi_value output {};
    auto status = NapiUtils::SetValue(env, title, output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        NapiUtils::ThrowError(env, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
}

napi_value NapiAVSessionController::SkipToQueueItem(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionController::SkipToQueueItem");
    struct ConcreteContext : public ContextBase {
        int32_t itemId_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        NapiUtils::ThrowError(env, "avsession SkipToQueueItem failed:no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->itemId_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get itemId failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_META_DATA_TASK_ID;
    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("SkipToQueueItem failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "SkipToQueueItem failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->SkipToQueueItem(context->itemId_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SkipToQueueItem failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "SkipToQueueItem failed : native controller not exist";
            } else if (ret == ERR_SESSION_DEACTIVE) {
                context->errMessage = "SkipToQueueItem failed : native session is not active";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SkipToQueueItem failed : native no permission";
            } else {
                context->errMessage = "SkipToQueueItem failed : native server exception";
            }
            SLOGE("controller SkipToQueueItem failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    return NapiAsyncWork::Enqueue(env, context, "SkipToQueueItem", executor);
}

napi_value NapiAVSessionController::GetExtras(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionController::GetExtras");
    struct ConcreteContext : public ContextBase {
        AAFwk::WantParams extras_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        SLOGD("NapiAVSessionController GetExtras process check lock");
        std::lock_guard<std::mutex> lock(uvMutex_);
        SLOGI("Start NapiAVSessionController GetExtras process");
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("GetExtras failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetExtras failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetExtras(context->extras_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetExtras failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetExtras failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetExtras failed : native no permission";
            } else {
                context->errMessage = "GetExtras failed : native server exception";
            }
            SLOGE("Controller getExtras failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->extras_, output);
        CHECK_STATUS_RETURN_VOID(context, "Convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        SLOGI("check getextras done");
    };

    return NapiAsyncWork::Enqueue(env, context, "GetExtras", executor, complete);
}

napi_value NapiAVSessionController::GetExtrasWithEvent(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionController::GetExtrasWithEvent");
    struct ConcreteContext : public ContextBase {
        std::string extraEvent_;
        AAFwk::WantParams extras_;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "Invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->extraEvent_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "Get extras event failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        std::lock_guard<std::mutex> lock(uvMutex_);
        SLOGI("Start NapiAVSessionController GetExtrasWithEvent process");
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("GetExtrasWithEvent failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetExtrasWithEvent failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetExtrasWithEvent(context->extraEvent_, context->extras_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetExtrasWithEvent failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetExtrasWithEvent failed : native controller not exist";
            } else if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "GetExtrasWithEvent failed : native invalid key event";
            } else {
                context->errMessage = "GetExtrasWithEvent failed : native server exception";
            }
            SLOGE("Controller getExtras with event failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->extras_, output);
        CHECK_STATUS_RETURN_VOID(context, "Convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        SLOGI("check getextraswithevent done");
    };

    return NapiAsyncWork::Enqueue(env, context, "GetExtrasWithEvent", executor, complete);
}

napi_value NapiAVSessionController::SendAVKeyEvent(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionController::SendAVKeyEvent");
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
    context->taskId = NAPI_SEND_AV_KEY_EVENT_TASK_ID;

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("SendAVKeyEvent failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "SendAVKeyEvent failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->SendAVKeyEvent(*context->keyEvent_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SendAVKeyEvent failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "SendAVKeyEvent failed : native controller not exist";
            } else if (ret == ERR_SESSION_DEACTIVE) {
                context->errMessage = "SendAVKeyEvent failed : native session is not active";
            } else if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "SendAVKeyEvent failed : native invalid KeyEvent";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SendAVKeyEvent failed : native no permission";
            } else {
                context->errMessage = "SendAVKeyEvent failed : native server exception";
            }
            SLOGE("controller SendAVKeyEvent failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendAVKeyEvent", executor);
}

napi_value NapiAVSessionController::GetLaunchAbility(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AbilityRuntime::WantAgent::WantAgent* ability;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController == nullptr || napiController->controller_ == nullptr) {
            SLOGE("GetLaunchAbility failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetLaunchAbility failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->GetLaunchAbilityInner(context->ability);
        SLOGE("GetLaunchAbilityInner check:%{public}d", context->ability != nullptr);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetLaunchAbility failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetLaunchAbility failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetLaunchAbility failed : native no permission";
            } else {
                context->errMessage = "GetLaunchAbility failed : native server exception";
            }
            SLOGE("controller GetLaunchAbility failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->ability, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
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
            SLOGE("GetValidCommands failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetValidCommands failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        std::vector<int32_t> cmds;
        int32_t ret = napiController->controller_->GetValidCommands(cmds);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetValidCommands failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetValidCommands failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetValidCommands failed : native no permission";
            } else {
                context->errMessage = "GetValidCommands failed : native server exception";
            }
            SLOGE("controller GetValidCommands failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
        context->stringCmds = NapiControlCommand::ConvertCommands(cmds);
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->stringCmds, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetValidCommands", executor, complete);
}

napi_value NapiAVSessionController::GetValidCommandsSync(napi_env env, napi_callback_info info)
{
    SLOGD("Start GetValidCommandsSync");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGE("GetValidCommandsSync failed : controller is nullptr");
        NapiUtils::ThrowError(env, "GetValidCommandsSync failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    std::vector<int32_t> cmds;
    int32_t ret = napiController->controller_->GetValidCommands(cmds);
    SLOGD("Get valid commands size: %{public}zu", cmds.size());
    if (ret != AVSESSION_SUCCESS) {
        std::string errMessage;
        if (ret == ERR_SESSION_NOT_EXIST) {
            errMessage = "GetValidCommandsSync failed : native session not exist";
        } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetValidCommandsSync failed : native controller not exist";
        } else if (ret == ERR_NO_PERMISSION) {
            errMessage = "GetValidCommandsSync failed : native no permission";
        } else {
            ret = AVSESSION_ERROR;
            errMessage = "GetValidCommandsSync failed : native server exception";
        }
        SLOGE("controller GetValidCommandsSync failed:%{public}d", ret);
        NapiUtils::ThrowError(env, errMessage.c_str(), NapiAVSessionManager::errcode_[ret]);
        return NapiUtils::GetUndefinedValue(env);
    }

    std::vector<std::string> stringCmds = NapiControlCommand::ConvertCommands(cmds);
    napi_value output {};
    auto status = NapiUtils::SetValue(env, stringCmds, output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        NapiUtils::ThrowError(env, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
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
            SLOGE("IsSessionActive failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "IsSessionActive failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->IsSessionActive(context->isActive);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "IsSessionActive failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "IsSessionActive failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "IsSessionActive failed : native no permission";
            } else {
                context->errMessage = "IsSessionActive failed : native server exception";
            }
            SLOGE("controller IsSessionActive failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->isActive, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "IsSessionActive", executor, complete);
}

napi_value NapiAVSessionController::IsSessionActiveSync(napi_env env, napi_callback_info info)
{
    SLOGD("Start IsSessionActiveSync");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGE("IsSessionActiveSync failed : controller is nullptr");
        NapiUtils::ThrowError(env, "IsSessionActiveSync failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    bool isActive {};
    int32_t ret = napiController->controller_->IsSessionActive(isActive);
    SLOGD("Get session active state: %{public}d", static_cast<int32_t>(isActive));
    if (ret != AVSESSION_SUCCESS) {
        std::string errMessage;
        if (ret == ERR_SESSION_NOT_EXIST) {
            errMessage = "IsSessionActiveSync failed : native session not exist";
        } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "IsSessionActiveSync failed : native controller not exist";
        } else if (ret == ERR_NO_PERMISSION) {
            errMessage = "IsSessionActiveSync failed : native no permission";
        } else {
            ret = AVSESSION_ERROR;
            errMessage = "IsSessionActiveSync failed : native server exception";
        }
        SLOGE("controller IsSessionActiveSync failed:%{public}d", ret);
        NapiUtils::ThrowError(env, errMessage.c_str(), NapiAVSessionManager::errcode_[ret]);
        return NapiUtils::GetUndefinedValue(env);
    }

    napi_value output {};
    auto status = NapiUtils::SetValue(env, isActive, output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        NapiUtils::ThrowError(env, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
}

napi_value NapiAVSessionController::SendControlCommand(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionController::SendControlCommand");
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
    context->taskId = NAPI_SEND_CONTROL_COMMAND_TASK_ID;

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("SendControlCommand failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "SendControlCommand failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->SendControlCommand(context->command);
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

napi_value NapiAVSessionController::SendCommonCommand(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionController::SendCommonCommand");
    struct ConcreteContext : public ContextBase {
        std::string commonCommand_;
        AAFwk::WantParams commandArgs_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SendCommonCommand failed : no memory");
        NapiUtils::ThrowError(env, "SendCommonCommand failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "Invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->commonCommand_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "Get common command failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->commandArgs_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "Get command args failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SEND_COMMON_COMMAND_TASK_ID;

    auto executor = [context]() {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("SendCommonCommand failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "SendCommonCommand failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->
            SendCommonCommand(context->commonCommand_, context->commandArgs_);
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, context->errMessage);
            SLOGE("Controller SendCommonCommand failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SendCommonCommand", executor, complete);
}

void NapiAVSessionController::ErrCodeToMessage(int32_t errCode, std::string& message)
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

napi_value NapiAVSessionController::Destroy(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    context->GetCbInfo(env, info);
    auto executor = [context]() {
        SLOGD("Start NapiAVSessionController destroy process check lock");
        std::lock_guard<std::mutex> lock(uvMutex_);
        SLOGI("Start NapiAVSessionController destroy process");
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("Destroy controller failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "Destroy controller failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiController->controller_->Destroy();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "Destroy controller failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "Destroy controller failed : native no permission";
            } else {
                context->errMessage = "Destroy controller failed : native server exception";
            }
            SLOGE("controller Destroy failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            return;
        }
        SLOGI("NapiAVSessionController destroy process done for: %{public}s", napiController->sessionId_.c_str());
    };
    auto complete = [env, context](napi_value& output) {
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        napiController->callback_ = nullptr;
        napiController->controller_ = nullptr;
        std::lock_guard<std::mutex> lock(controllerListMutex_);
        SLOGI("repeat list check for controller destory: %{public}s", napiController->sessionId_.c_str());
        if (!ControllerList_.empty() && ControllerList_.find(napiController->sessionId_) != ControllerList_.end()) {
            SLOGI("repeat list erase for controller destory: %{public}s", napiController->sessionId_.c_str());
            ControllerList_.erase(napiController->sessionId_);
        }
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Destroy", executor, complete);
}

napi_value NapiAVSessionController::GetRealPlaybackPositionSync(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGI("GetRealPlaybackPositionSync failed : controller is nullptr");
        NapiUtils::ThrowError(env, "GetRealPlaybackPositionSync failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto position = napiController->controller_->GetRealPlaybackPosition();
    napi_value output {};
    auto status = NapiUtils::SetValue(env, position, output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        NapiUtils::ThrowError(env, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
}

napi_value NapiAVSessionController::GetOutputDevice(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        OutputDeviceInfo outputDeviceInfo_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        if (context == nullptr) {
            SLOGE("GetOutputDevice failed for context is nullptr");
            return;
        }
        auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
        if (napiController->controller_ == nullptr) {
            SLOGE("GetOutputDevice failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetOutputDevice failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        AVSessionDescriptor descriptor;
        std::string sessionId = napiController->controller_->GetSessionId();
        AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(sessionId, descriptor);
        SLOGI("set outputdevice info for session:%{public}s***", sessionId.substr(0, ARGC_THREE).c_str());
        context->outputDeviceInfo_ = descriptor.outputDeviceInfo_;
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->outputDeviceInfo_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetOutputDevice", executor, complete);
}

napi_value NapiAVSessionController::GetOutputDeviceSync(napi_env env, napi_callback_info info)
{
    SLOGD("Start GetOutputDeviceSync");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGE("GetOutputDeviceSync failed : controller is nullptr");
        NapiUtils::ThrowError(env, "GetOutputDeviceSync failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }

    AVSessionDescriptor descriptor;
    AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(napiController->controller_->GetSessionId(),
        descriptor);
    napi_value output {};
    auto status = NapiUtils::SetValue(env, descriptor.outputDeviceInfo_, output);
    if (status != napi_ok) {
        SLOGE("convert native object to javascript object failed");
        NapiUtils::ThrowError(env, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return NapiUtils::GetUndefinedValue(env);
    }
    return output;
}

napi_status NapiAVSessionController::SetAVCallMetaFilter(napi_env env, NapiAVSessionController* napiController,
    napi_value filter)
{
    AVCallMetaData::AVCallMetaMaskType avCallMetaMask;
    auto status = NapiAVCallMetaData::ConvertFilter(env, filter, avCallMetaMask);
    CHECK_RETURN(status == napi_ok, "convert filter failed", status);
    auto ret = napiController->controller_->SetAVCallMetaFilter(avCallMetaMask);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller SetAVCallMetaFilter failed:%{public}d", ret);
        status = napi_generic_failure;
    }
    return status;
}

napi_status NapiAVSessionController::SetAVCallStateFilter(napi_env env, NapiAVSessionController *napiController,
    napi_value filter)
{
    AVCallState::AVCallStateMaskType avCallStateMask;
    auto status = NapiAVCallState::ConvertFilter(env, filter, avCallStateMask);
    CHECK_RETURN(status == napi_ok, "convert filter failed", status);
    auto ret = napiController->controller_->SetAVCallStateFilter(avCallStateMask);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller SetAVCallStateFilter failed:%{public}d", ret);
        status = napi_generic_failure;
    }
    return status;
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

napi_status NapiAVSessionController::SetMetaFilter(napi_env env, NapiAVSessionController* napiController,
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

napi_status NapiAVSessionController::DoRegisterCallback(napi_env env, NapiAVSessionController* napiController)
{
    SLOGI("do register callback with for sessionId: %{public}s", napiController->sessionId_.c_str());
    if (napiController->callback_ == nullptr) {
        napiController->callback_ = std::make_shared<NapiAVControllerCallback>();
        if (napiController->callback_ == nullptr) {
            SLOGE("OnEvent failed : no memory");
            NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
            return napi_generic_failure;
        }
        std::string registerControllerId = napiController->sessionId_;
        napiController->callback_->AddCallbackForSessionDestroy([registerControllerId]() {
            SLOGI("repeat list check for session destory: %{public}s", registerControllerId.c_str());
            std::lock_guard<std::mutex> lock(controllerListMutex_);
            if (!ControllerList_.empty() && ControllerList_.find(registerControllerId) != ControllerList_.end()) {
                SLOGI("repeat list erase controller for session destory: %{public}s", registerControllerId.c_str());
                ControllerList_.erase(registerControllerId);
            } else {
                SLOGI("repeat list erase fail for session not in list: %{public}s", registerControllerId.c_str());
            }
        });
        auto ret = napiController->controller_->RegisterCallback(napiController->callback_);
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
            napiController->callback_ = nullptr;
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

napi_status NapiAVSessionController::RegisterCallback(napi_env env,
    const std::shared_ptr<ContextBase>& context,
    const std::string& event, napi_value filter, napi_value callback)
{
    auto it = EventHandlers_.find(event);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return napi_generic_failure;
    }
    SLOGD("NapiAVSessionController RegisterCallback process check lock");
    std::lock_guard<std::mutex> lock(uvMutex_);
    SLOGD("NapiAVSessionController RegisterCallback process");
    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->controller_ == nullptr) {
        SLOGE("OnEvent failed : controller is nullptr");
        NapiUtils::ThrowError(env, "OnEvent CTL null", NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return napi_generic_failure;
    }
    if (DoRegisterCallback(env, napiController) != napi_ok) {
        SLOGE("do register callback fail!");
        return napi_generic_failure;
    }
    if (it->second.first(env, napiController, filter, callback) != napi_ok) {
        SLOGE("add event callback failed");
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return napi_generic_failure;
    }
    return napi_ok;
}

static bool IsThreeParamForOnEvent(const std::string& event)
{
    return event == "metadataChange" || event == "playbackStateChange" ||
        event == "callMetadataChange" || event == "callStateChange";
}

napi_value NapiAVSessionController::OnEvent(napi_env env, napi_callback_info info)
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
            CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THREE, "invalid argument number",
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

napi_value NapiAVSessionController::OffEvent(napi_env env, napi_callback_info info)
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
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE || argc == ARGC_TWO, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_TWO) {
            callback = argv[ARGV_SECOND];
        }
    };
    SLOGD("check offEvent eventName %{public}s", eventName.c_str());

    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        SLOGE("check offEvent with status err");
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto it = EventHandlers_.find(eventName);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid:%{public}s", eventName.c_str());
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto* napiController = reinterpret_cast<NapiAVSessionController*>(context->native);
    if (napiController->callback_ == nullptr) {
        SLOGI("function %{public}s not register yet", eventName.c_str());
        NapiUtils::ThrowError(env, "callback not register yet",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.second(env, napiController, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }
    SLOGD("check offEvent done");
    return NapiUtils::GetUndefinedValue(env);
}

napi_status NapiAVSessionController::OnAVCallMetaDataChange(napi_env env, NapiAVSessionController* napiController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    napi_status status = SetAVCallMetaFilter(env, napiController, param);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "SetAVCallMetaFilter failed");

    return napiController->callback_->AddCallback(env,
        NapiAVControllerCallback::EVENT_AVCALL_META_DATA_CHANGE, callback);
}

napi_status NapiAVSessionController::OnAVCallStateChange(napi_env env, NapiAVSessionController* napiController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    napi_status status = SetAVCallStateFilter(env, napiController, param);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "SetAVCallStateFilter failed");

    return napiController->callback_->AddCallback(env,
        NapiAVControllerCallback::EVENT_AVCALL_STATE_CHANGE, callback);
}

napi_status NapiAVSessionController::OnSessionDestroy(napi_env env, NapiAVSessionController* napiController,
                                                      napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_SESSION_DESTROY, callback);
}

napi_status NapiAVSessionController::OnPlaybackStateChange(napi_env env, NapiAVSessionController* napiController,
                                                           napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    napi_status status = SetPlaybackStateFilter(env, napiController, param);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "SetPlaybackStateFilter failed");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_PLAYBACK_STATE_CHANGE,
                                                  callback);
}

napi_status NapiAVSessionController::OnMetaDataChange(napi_env env, NapiAVSessionController* napiController,
                                                      napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    napi_status status = SetMetaFilter(env, napiController, param);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "SetMetaFilter failed");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_META_DATA_CHANGE, callback);
}

napi_status NapiAVSessionController::OnActiveStateChange(napi_env env, NapiAVSessionController* napiController,
                                                         napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_ACTIVE_STATE_CHANGE, callback);
}

napi_status NapiAVSessionController::OnValidCommandChange(napi_env env, NapiAVSessionController* napiController,
                                                          napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_VALID_COMMAND_CHANGE,
                                                  callback);
}

napi_status NapiAVSessionController::OnOutputDeviceChange(napi_env env, NapiAVSessionController* napiController,
                                                          napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_OUTPUT_DEVICE_CHANGE,
                                                  callback);
}

napi_status NapiAVSessionController::OnSessionEventChange(napi_env env, NapiAVSessionController* napiController,
                                                          napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_SESSION_EVENT_CHANGE,
                                                  callback);
}

napi_status NapiAVSessionController::OnQueueItemsChange(napi_env env, NapiAVSessionController* napiController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_QUEUE_ITEMS_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OnQueueTitleChange(napi_env env, NapiAVSessionController* napiController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_QUEUE_TITLE_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OnExtrasChange(napi_env env, NapiAVSessionController* napiController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->AddCallback(env, NapiAVControllerCallback::EVENT_EXTRAS_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OffAVCallMetaDataChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_AVCALL_META_DATA_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OffAVCallStateChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_AVCALL_STATE_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OffSessionDestroy(napi_env env, NapiAVSessionController* napiController,
                                                       napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_SESSION_DESTROY, callback);
}

napi_status NapiAVSessionController::OffPlaybackStateChange(napi_env env, NapiAVSessionController* napiController,
                                                            napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_PLAYBACK_STATE_CHANGE,
                                                     callback);
}

napi_status NapiAVSessionController::OffMetaDataChange(napi_env env, NapiAVSessionController* napiController,
                                                       napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_META_DATA_CHANGE, callback);
}

napi_status NapiAVSessionController::OffActiveStateChange(napi_env env, NapiAVSessionController* napiController,
                                                          napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_ACTIVE_STATE_CHANGE,
                                                     callback);
}

napi_status NapiAVSessionController::OffValidCommandChange(napi_env env, NapiAVSessionController* napiController,
                                                           napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_VALID_COMMAND_CHANGE,
                                                     callback);
}

napi_status NapiAVSessionController::OffOutputDeviceChange(napi_env env, NapiAVSessionController* napiController,
                                                           napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_OUTPUT_DEVICE_CHANGE,
                                                     callback);
}

napi_status NapiAVSessionController::OffSessionEventChange(napi_env env, NapiAVSessionController* napiController,
                                                           napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_SESSION_EVENT_CHANGE,
                                                     callback);
}

napi_status NapiAVSessionController::OffQueueItemsChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_QUEUE_ITEMS_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OffQueueTitleChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_QUEUE_TITLE_CHANGE,
        callback);
}

napi_status NapiAVSessionController::OffExtrasChange(napi_env env, NapiAVSessionController* napiController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiController != nullptr, napi_generic_failure, "input param is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiController->callback_->RemoveCallback(env, NapiAVControllerCallback::EVENT_EXTRAS_CHANGE,
        callback);
}
}
