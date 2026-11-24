/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "avsession_trace.h"
#include "napi_avsession_manager.h"
#include "napi_avcast_picker_helper.h"
#include "bool_wrapper.h"
#include "int_wrapper.h"

namespace OHOS::AVSession {

static const std::string ABILITY_WANT_PARAMS_UIEXTENSIONTARGETTYPE = "ability.want.params.uiExtensionType";
static const std::string ABILITY_WANT_ELEMENT_NAME = "com.ohos.mediacontroller";

static __thread napi_ref AVCastPickerHelperConstructorRef = nullptr;
std::map<std::string, std::pair<NapiAVCastPickerHelper::OnEventHandlerType,
    NapiAVCastPickerHelper::OffEventHandlerType>> NapiAVCastPickerHelper::eventHandlers_ = {
    { "pickerStateChange", { OnPickerStateChange, OffPickerStateChange } },
};

std::mutex NapiAVCastPickerHelper::instanceLock_;
std::set<NapiAVCastPickerHelper*> NapiAVCastPickerHelper::instances_;

NapiAVCastPickerHelper::NapiAVCastPickerHelper(Ace::UIContent* uiContent)
{
    SLOGI("construct");
    uiContent_ = uiContent;
    isValid_ = std::make_shared<std::atomic<bool>>(true);
    audioRoutingMngr_ = AudioStandard::AudioRoutingManager::GetInstance();
    std::lock_guard<std::mutex> lockGuard(instanceLock_);
    instances_.insert(this);
}

NapiAVCastPickerHelper::~NapiAVCastPickerHelper()
{
    SLOGI("destroy.");
    *isValid_ = false;
    std::lock_guard<std::mutex> lockGuard(instanceLock_);
    instances_.erase(this);
}

napi_value NapiAVCastPickerHelper::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_STATIC_FUNCTION("closeAll", CloseAllAVPicker),
        DECLARE_NAPI_FUNCTION("select", SelectAVPicker),
        DECLARE_NAPI_FUNCTION("selectForId", SelectAVPickerForId),
        DECLARE_NAPI_FUNCTION("close", CloseAVPicker),
        DECLARE_NAPI_FUNCTION("resetCommunicationDevice", ResetCommunicationDevice),
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
        DECLARE_NAPI_FUNCTION("onPickerStateChangeForId", OnPickerStateChangeForId),
        DECLARE_NAPI_FUNCTION("offPickerStateChangeForId", OffPickerStateChangeForId),
    };
    auto propertyCount = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor {};
    auto status = napi_define_class(env, "AVCastPickerHelper", NAPI_AUTO_LENGTH, ConstructorCallback, nullptr,
                                    propertyCount, descriptors, &constructor);
    if (status != napi_ok) {
        SLOGE("define class failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_create_reference(env, constructor, 1, &AVCastPickerHelperConstructorRef);
    napi_set_named_property(env, exports, "AVCastPickerHelper", constructor);

    return exports;
}

napi_value NapiAVCastPickerHelper::ConstructorCallback(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase { Ace::UIContent* uiContent; };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        NapiUtils::ThrowError(env, "ConstructorCallback failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        auto stageCtx = AbilityRuntime::GetStageModeContext(env, argv[ARGV_FIRST]);
        if (stageCtx == nullptr) {
            context->status = napi_generic_failure;
            NapiUtils::ThrowError(env, "get stageCtx failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            return;
        }
        auto abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(stageCtx);
        if (abilityContext != nullptr) {
            context->uiContent = abilityContext->GetUIContent();
        } else {
            auto extensionContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(stageCtx);
            CHECK_RETURN_VOID(extensionContext != nullptr, "convert to AbilityContext and ExtensionContext fail");
            context->uiContent = extensionContext->GetUIContent();
        }
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    CHECK_AND_RETURN_RET_LOG(context->status == napi_ok, nullptr, "no need to wrap");

    auto* napiAVCastPickerHelper = new(std::nothrow) NapiAVCastPickerHelper(context->uiContent);
    CHECK_AND_RETURN_RET_LOG(napiAVCastPickerHelper != nullptr, nullptr, "no memory");
    auto finalize = [](napi_env env, void* data, void* hint) {
        auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(data);
        CHECK_AND_RETURN_LOG(napiAVCastPickerHelper != nullptr, "napiAVCastPickerHelper is nullptr");
        napi_delete_reference(env, napiAVCastPickerHelper->wrapperRef_);
        delete napiAVCastPickerHelper;
        napiAVCastPickerHelper = nullptr;
    };
    if (napi_wrap(env, context->self, static_cast<void*>(napiAVCastPickerHelper),
        finalize, nullptr, nullptr) != napi_ok) {
        SLOGE("wrap failed");
        delete napiAVCastPickerHelper;
        napiAVCastPickerHelper = nullptr;
        return nullptr;
    }
    return context->self;
}

napi_value NapiAVCastPickerHelper::OnEvent(napi_env env, napi_callback_info info)
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
    auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(context->native);
    if (it->second.first(env, napiAVCastPickerHelper, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVCastPickerHelper::OffEvent(napi_env env, napi_callback_info info)
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
    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(context->native);
    if (napiAVCastPickerHelper == nullptr) {
        SLOGE("OffEvent failed : napiAVCastPickerHelper is nullptr");
        NapiUtils::ThrowError(env, "OffEvent failed : napiAVCastPickerHelper is nullptr",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }
    if (napiAVCastPickerHelper != nullptr && it->second.second(env, napiAVCastPickerHelper, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVCastPickerHelper::SelectAVPicker(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ConcreteContext>();
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ZERO || argc == ARGC_ONE,
                               "invalid argument number", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_ONE) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->napiAVCastPickerOptions);
        }
        CHECK_STATUS_RETURN_VOID(context, "get object failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_CAST_PICKER_HELPER_TASK_ID;
    
    auto executor = [context]() {
        auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(context->native);
        int32_t pickerId = napiAVCastPickerHelper->CreatePickerInternal(context->napiAVCastPickerOptions);
        if (pickerId < 0) {
            SLOGE("SelectAVPicker failed pickerId=%{public}d", pickerId);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ERR_INVALID_PARAM];
            context->errMessage = "selectAVPicker failed: failed to create picker";
        }
    };
    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, context, "SelectAVPicker", executor, complete);
}

napi_value NapiAVCastPickerHelper::SelectAVPickerForId(napi_env env, napi_callback_info info)
{
    struct SelectForIdContext : public ContextBase {
        NapiAVCastPickerOptions napiAVCastPickerOptions;
        int32_t pickerId = -1;
    };
    auto context = std::make_shared<SelectForIdContext>();
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ZERO || argc == ARGC_ONE,
                               "invalid argument number", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_ONE) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->napiAVCastPickerOptions);
        }
        CHECK_STATUS_RETURN_VOID(context, "get object failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_CAST_PICKER_HELPER_TASK_ID;

    auto executor = [context]() {
        auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(context->native);
        context->pickerId = napiAVCastPickerHelper->CreatePickerInternal(context->napiAVCastPickerOptions);
        if (context->pickerId < 0) {
            SLOGE("SelectAVPickerForId failed pickerId=%{public}d", context->pickerId);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ERR_INVALID_PARAM];
            context->errMessage = "selectAVPickerForId failed: failed to create picker";
        }
    };
    auto complete = [env, context](napi_value& output) {
        NapiUtils::SetValue(env, context->pickerId, output);
    };
    return NapiAsyncWork::Enqueue(env, context, "SelectAVPickerForId", executor, complete);
}

napi_value NapiAVCastPickerHelper::CloseAVPicker(napi_env env, napi_callback_info info)
{
    struct CloseContext : public ContextBase {
        bool hasPickerId = false;
        int32_t pickerId = -1;
    };
    auto context = std::make_shared<CloseContext>();
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ZERO || argc == ARGC_ONE,
                               "invalid argument number", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_ONE) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->pickerId);
            CHECK_STATUS_RETURN_VOID(context, "get pickerId failed",
                NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
            context->hasPickerId = true;
        }
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_CAST_PICKER_HELPER_TASK_ID;

    auto executor = [context]() {
        auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(context->native);
        if (context->hasPickerId) {
            int32_t ret = napiAVCastPickerHelper->SendCloseData(context->pickerId);
            if (ret != AVSESSION_SUCCESS) {
                SLOGE("CloseAVPicker failed ret=%{public}d", ret);
                context->status = napi_generic_failure;
                context->errCode = NapiAVSessionManager::errcode_[ret];
            }
        } else {
            napiAVCastPickerHelper->SendCloseDataToAll();
        }
    };
    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, context, "CloseAVPicker", executor, complete);
}

napi_value NapiAVCastPickerHelper::CloseAllAVPicker(napi_env env, napi_callback_info info)
{
    struct CloseAllContext : public ContextBase {};
    auto context = std::make_shared<CloseAllContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_PICKER_HELPER_TASK_ID;

    auto executor = [context]() {
        auto allProxies = CollectAllProxies();
        SendCloseDataToProxies(allProxies);
        SLOGI("CloseAllAVPicker count=%{public}zu", allProxies.size());
    };
    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, context, "CloseAllAVPicker", executor, complete);
}

int32_t NapiAVCastPickerHelper::CreatePickerInternal(const NapiAVCastPickerOptions& options)
{
    AAFwk::Want request;
    BuildPickerRequest(options, request);

    PickerCallBack pickerCallBack;
    auto callback = std::make_shared<ModalUICallback>(uiContent_, pickerCallBack);
    auto extensionCallback = CreateExtensionCallback(callback, this);

    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    CHECK_AND_RETURN_RET_LOG(uiContent_ != nullptr, -1, "picker ui content is nullptr");
    int32_t sessionId = uiContent_->CreateModalUIExtension(request, extensionCallback, config);
    callback->SetSessionId(sessionId);
    return sessionId;
}

void NapiAVCastPickerHelper::StoreProxy(int32_t sessionId,
    const std::shared_ptr<Ace::ModalUIExtensionProxy>& proxy)
{
    std::lock_guard<std::mutex> lockGuard(proxyLock_);
    proxyMap_[sessionId] = proxy;
    SLOGI("StoreProxy sessionId=%{public}d, map size=%{public}zu", sessionId, proxyMap_.size());
}

void NapiAVCastPickerHelper::RemoveProxy(int32_t sessionId)
{
    std::lock_guard<std::mutex> lockGuard(proxyLock_);
    auto it = proxyMap_.find(sessionId);
    if (it != proxyMap_.end()) {
        proxyMap_.erase(it);
        SLOGI("RemoveProxy sessionId=%{public}d, map size=%{public}zu", sessionId, proxyMap_.size());
    }
}

int32_t NapiAVCastPickerHelper::SendCloseData(int32_t pickerId)
{
    std::shared_ptr<Ace::ModalUIExtensionProxy> proxy;
    {
        std::lock_guard<std::mutex> lockGuard(proxyLock_);
        auto it = proxyMap_.find(pickerId);
        if (it == proxyMap_.end() || it->second == nullptr) {
            SLOGE("SendCloseData proxy not found for pickerId=%{public}d", pickerId);
            return ERR_PICKER_NOT_EXIST;
        }
        proxy = it->second;
    }
    AAFwk::WantParams params;
    params.SetParam("closeByPickerApi", AAFwk::Boolean::Box(true));
    proxy->SendData(params);
    SLOGI("SendCloseData pickerId=%{public}d", pickerId);
    return AVSESSION_SUCCESS;
}

void NapiAVCastPickerHelper::SendCloseDataToAll()
{
    std::vector<std::shared_ptr<Ace::ModalUIExtensionProxy>> proxies;
    {
        std::lock_guard<std::mutex> lockGuard(proxyLock_);
        for (auto& [id, proxy] : proxyMap_) {
            if (proxy != nullptr) {
                proxies.push_back(proxy);
            }
        }
    }
    SendCloseDataToProxies(proxies);
    SLOGI("SendCloseDataToAll count=%{public}zu", proxies.size());
}

std::vector<std::shared_ptr<Ace::ModalUIExtensionProxy>> NapiAVCastPickerHelper::CollectAllProxies()
{
    std::vector<std::shared_ptr<Ace::ModalUIExtensionProxy>> allProxies;
    std::lock_guard<std::mutex> lockGuard(instanceLock_);
    for (auto* inst : instances_) {
        std::lock_guard<std::mutex> proxyLock(inst->proxyLock_);
        for (auto& [id, proxy] : inst->proxyMap_) {
            if (proxy != nullptr) {
                allProxies.push_back(proxy);
            }
        }
    }
    return allProxies;
}

void NapiAVCastPickerHelper::SendCloseDataToProxies(
    const std::vector<std::shared_ptr<Ace::ModalUIExtensionProxy>>& proxies)
{
    for (auto& proxy : proxies) {
        AAFwk::WantParams params;
        params.SetParam("closeByPickerApi", AAFwk::Boolean::Box(true));
        proxy->SendData(params);
    }
}

napi_value NapiAVCastPickerHelper::OnPickerStateChangeForId(napi_env env, napi_callback_info info)
{
    struct OnForIdContext : public ContextBase {};
    auto context = std::make_shared<OnForIdContext>();
    napi_value callback {};
    auto input = [&context, &callback, env](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
            "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        callback = argv[ARGV_FIRST];
    };
    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(context->native);
    if (napiAVCastPickerHelper == nullptr) {
        NapiUtils::ThrowError(env, "OnPickerStateChangeForId failed : napiAVCastPickerHelper is nullptr",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_status ret = napiAVCastPickerHelper->AddCallback(env, EVENT_PICKER_STATE_CHANGE_FOR_ID, callback);
    if (ret != napi_ok) {
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVCastPickerHelper::OffPickerStateChangeForId(napi_env env, napi_callback_info info)
{
    struct OffForIdContext : public ContextBase {};
    auto context = std::make_shared<OffForIdContext>();
    napi_value callback = nullptr;
    auto input = [&context, &callback, env](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ZERO || argc == ARGC_ONE,
            "invalid argument number", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_ONE) {
            napi_valuetype type = napi_undefined;
            context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            callback = argv[ARGV_FIRST];
        }
    };
    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(context->native);
    if (napiAVCastPickerHelper == nullptr) {
        NapiUtils::ThrowError(env, "OffPickerStateChangeForId failed : napiAVCastPickerHelper is nullptr",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_status ret = napiAVCastPickerHelper->RemoveCallback(env, EVENT_PICKER_STATE_CHANGE_FOR_ID, callback);
    if (ret != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

void NapiAVCastPickerHelper::BuildPickerRequest(const NapiAVCastPickerOptions& options, AAFwk::Want& request)
{
    std::string targetType = "sysPicker/mediaControl";
    request.SetParam(ABILITY_WANT_PARAMS_UIEXTENSIONTARGETTYPE, targetType);
    request.SetParam("isAVCastPickerHelper", true);
    request.SetParam("AVCastPickerOptionsType", options.sessionType);
    request.SetParam("AVCastPickerOptionsStyle", options.pickerStyle);
    request.SetParam("AVCastPickerOptionsPositionX", options.menuPosition.x);
    request.SetParam("AVCastPickerOptionsPositionY", options.menuPosition.y);
    request.SetParam("AVCastPickerOptionsPositionW", options.menuPosition.width);
    request.SetParam("AVCastPickerOptionsPositionH", options.menuPosition.height);
    request.SetElementName(ABILITY_WANT_ELEMENT_NAME, "UIExtAbility");
}

Ace::ModalUIExtensionCallbacks NapiAVCastPickerHelper::CreateExtensionCallback(
    const std::shared_ptr<ModalUICallback>& callback, NapiAVCastPickerHelper* napiAVCastPickerHelper)
{
    static const std::string callBackName = "NapiAVCastPickerHelper::SelectAVPicker";
    auto isValid = napiAVCastPickerHelper->isValid_;
    return {
        .onRelease = ([callback, napiAVCastPickerHelper, isValid](auto arg) {
            callback->OnRelease(arg);
            CHECK_AND_RETURN_LOG(isValid && *isValid, "NapiAVCastPickerHelper is destroyed");
            napiAVCastPickerHelper->RemoveProxy(callback->GetSessionId());
        }),
        .onResult = ([callback](auto arg1, auto arg2) { callback->OnResult(arg1, arg2); }),
        .onReceive = ([callback, napiAVCastPickerHelper, isValid](auto arg) {
            callback->OnReceive(arg);
            CHECK_AND_RETURN_LOG(isValid && *isValid, "NapiAVCastPickerHelper is destroyed");
            napiAVCastPickerHelper->HandleEvent(EVENT_PICPKER_STATE_CHANGE, callBackName, STATE_DISAPPEARING);
            napiAVCastPickerHelper->HandleEventForId(EVENT_PICKER_STATE_CHANGE_FOR_ID,
                callback->GetSessionId(), callBackName, STATE_DISAPPEARING);
        }),
        .onError = ([callback](auto arg1, auto arg2, auto arg3) { callback->OnError(arg1, arg2, arg3); }),
        .onRemoteReady = ([callback, napiAVCastPickerHelper, isValid](auto arg) {
            callback->OnRemoteReady(arg);
            CHECK_AND_RETURN_LOG(isValid && *isValid, "NapiAVCastPickerHelper is destroyed");
            napiAVCastPickerHelper->StoreProxy(callback->GetSessionId(), arg);
            napiAVCastPickerHelper->HandleEvent(EVENT_PICPKER_STATE_CHANGE, callBackName, STATE_APPEARING);
            napiAVCastPickerHelper->HandleEventForId(EVENT_PICKER_STATE_CHANGE_FOR_ID,
                callback->GetSessionId(), callBackName, STATE_APPEARING);
        }),
        .onDestroy = ([callback, napiAVCastPickerHelper, isValid]() {
            callback->OnDestroy();
            CHECK_AND_RETURN_LOG(isValid && *isValid, "NapiAVCastPickerHelper is destroyed");
            napiAVCastPickerHelper->RemoveProxy(callback->GetSessionId());
        }),
    };
}

napi_value NapiAVCastPickerHelper::ResetCommunicationDevice(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        sptr<AudioStandard::AudioRendererFilter> audioRendererFilter;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ZERO,
                               "invalid argument number", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        CHECK_RETURN_VOID(NapiUtils::GetUndefinedValue(env), "CHECK_RETURN_VOID");
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        auto* napiAVCastPickerHelper = reinterpret_cast<NapiAVCastPickerHelper*>(context->native);
        context->audioRendererFilter = new (std::nothrow) AudioStandard::AudioRendererFilter();
        CHECK_AND_RETURN_LOG(context->audioRendererFilter != nullptr, "init AudioRendererFilter failed");
        (context->audioRendererFilter->rendererInfo).streamUsage =
            AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
        
        napiAVCastPickerHelper->audioRoutingMngr_->RestoreOutputDevice(context->audioRendererFilter);
    };

    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "ResetCommunicationDevice", executor, complete);
}

napi_status NapiAVCastPickerHelper::OnPickerStateChange(napi_env env, NapiAVCastPickerHelper* napiAVCastPickerHelper,
    napi_value callback)
{
    SLOGI("NapiAVCastPickerHelper OnPickerStateChange");
    CHECK_AND_RETURN_RET_LOG(napiAVCastPickerHelper != nullptr, napi_generic_failure, "input param is nullptr");
    return napiAVCastPickerHelper->AddCallback(env, EVENT_PICPKER_STATE_CHANGE, callback);
}

napi_status NapiAVCastPickerHelper::OffPickerStateChange(napi_env env, NapiAVCastPickerHelper* napiAVCastPickerHelper,
    napi_value callback)
{
    SLOGI("NapiAVCastPickerHelper OffPickerStateChange");
    CHECK_AND_RETURN_RET_LOG(napiAVCastPickerHelper != nullptr, napi_generic_failure, "input param is nullptr");
    return napiAVCastPickerHelper->RemoveCallback(env, EVENT_PICPKER_STATE_CHANGE, callback);
}

template<typename T>
void NapiAVCastPickerHelper::HandleEvent(int32_t event, std::string callBackName, const T& param)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("pickerNotRegister:%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event=%{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                if (!hasFunc) {
                    SLOGE("checkCallbackValid res false for event=%{public}d", event);
                }
                return hasFunc;
            }, callBackName,
            [param](napi_env env, int& argc, napi_value* argv) {
                argc = NapiUtils::ARGC_ONE;
                NapiUtils::SetValue(env, param, *argv);
            });
    }
}

void NapiAVCastPickerHelper::HandleEventForId(int32_t event, int32_t pickerId,
    std::string callBackName, uint32_t state)
{
    CHECK_AND_RETURN_LOG(event == EVENT_PICKER_STATE_CHANGE_FOR_ID,
        "invalid event for HandleEventForId %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("pickerNotRegister:%{public}d", event);
        return;
    }
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event=%{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                return hasFunc;
            }, callBackName,
            [pickerId, state](napi_env env, int& argc, napi_value* argv) {
                argc = NapiUtils::ARGC_ONE;
                napi_status status = napi_create_object(env, argv);
                CHECK_RETURN_VOID((status == napi_ok) && (argv != nullptr), "create object failed");
                napi_value property = nullptr;
                NapiUtils::SetValue(env, pickerId, property);
                napi_set_named_property(env, *argv, "id", property);
                NapiUtils::SetValue(env, static_cast<int32_t>(state), property);
                napi_set_named_property(env, *argv, "state", property);
            });
    }
}

napi_status NapiAVCastPickerHelper::AddCallback(napi_env env, int32_t event, napi_value callback)
{
    SLOGI("Add callback %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX, napi_generic_failure, "has no event");
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref == nullptr, napi_ok, "callback has been registered");
    napi_status status = napi_create_reference(env, callback, NapiUtils::ARGC_ONE, &ref);
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
    callbacks_[event].push_back(ref);
    return napi_ok;
}

napi_status NapiAVCastPickerHelper::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    SLOGI("Remove callback %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX, napi_generic_failure, "has no event");
    if (callback == nullptr) {
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(napi_ok == ret, ret, "delete callback reference failed");
        }
        callbacks_[event].clear();
        return napi_ok;
    }
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref != nullptr, napi_ok, "callback has been remove");
    callbacks_[event].remove(ref);
    return napi_delete_reference(env, ref);
}

bool NapiAVCastPickerHelper::IsCallbacksEmpty(int32_t event)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX, true, "has no event");
    return callbacks_[event].empty();
}

ModalUICallback::ModalUICallback(Ace::UIContent* uiContent, PickerCallBack& pickerCallBack)
{
    this->uiContent_ = uiContent;
    this->pickerCallBack_ = pickerCallBack;
}

void ModalUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

int32_t ModalUICallback::GetSessionId() const
{
    return sessionId_;
}

void ModalUICallback::OnRelease(int32_t releaseCode)
{
    SLOGI("ModalUICallback OnRelease enter. release code is %{public}d", releaseCode);
    this->uiContent_->CloseModalUIExtension(this->sessionId_);
    pickerCallBack_.ready = true;
}

void ModalUICallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    SLOGI("ModalUICallback OnResult enter. resultCode code is %{public}d", resultCode);
    pickerCallBack_.resultCode = resultCode;
}

void ModalUICallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    SLOGI("ModalUICallback OnReceive enter.");
}

void ModalUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    SLOGI("ModalUICallback OnError enter. errorCode=%{public}d, name=%{public}s, message=%{public}s",
        code, name.c_str(), message.c_str());
    if (!pickerCallBack_.ready) {
        this->uiContent_->CloseModalUIExtension(this->sessionId_);
        pickerCallBack_.ready = true;
    }
}

void ModalUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    SLOGI("ModalUICallback OnRemoteReady enter.");
}

void ModalUICallback::OnDestroy()
{
    SLOGI("ModalUICallback OnDestroy enter.");
}

} // namespace OHOS::AVSession
