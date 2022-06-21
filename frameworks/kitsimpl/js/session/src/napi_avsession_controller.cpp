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

#include "avplayback_state.h"
#include "key_event.h"
#include "napi_avsession_controller.h"
#include "want_agent.h"

using namespace std;

namespace OHOS::AVSession {
static __thread napi_ref g_avsessionControllerConstructor = nullptr;
static const std::string AVSESSION_CONTROLLER_NAPI_CLASS_NAME = "AVSessionController";

struct AVSessionControllerAsyncContext : public NapiAsyncProxy<AVSessionControllerAsyncContext>::AysncContext {
    std::shared_ptr<AVPlaybackState> aVPlaybackState = nullptr;
    std::shared_ptr<MMI::KeyEvent> keyEvent = nullptr;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    bool isActive;
    std::vector<int32_t> cmds;
    std::shared_ptr<AVControlCommand> aVControlCommand = nullptr;
    std::shared_ptr<AVMetaData> aVMetaData = nullptr;
};

NapiAVSessionController::NapiAVSessionController()
    : env_(nullptr), wrapper_(nullptr), avsessionController_(nullptr), avcontrollerCallback_(nullptr) {}

NapiAVSessionController::~NapiAVSessionController()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

napi_value NapiAVSessionController::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor avsession_controller_prop_desc[] = {
        DECLARE_NAPI_FUNCTION("getAVPlaybackState", GetAVPlaybackState),
        DECLARE_NAPI_FUNCTION("getAVMetadata", GetAVMetadata),
        DECLARE_NAPI_FUNCTION("sendAVKeyEvent", SendAVKeyEvent),
        DECLARE_NAPI_FUNCTION("getOutputDevice", GetOutputDevice),
        DECLARE_NAPI_FUNCTION("getLaunchAbility", GetLaunchAbility),
        DECLARE_NAPI_FUNCTION("isActive", IsActive),
        DECLARE_NAPI_FUNCTION("destroy", Destroy),
        DECLARE_NAPI_FUNCTION("getValidCommands", GetValidCommands),
        DECLARE_NAPI_FUNCTION("sendControlCommand", SendControlCommand),
        DECLARE_NAPI_FUNCTION("getRealPlaybackPositionSync", GetRealPlaybackPositionSync),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
    };
    napi_status status = AVSessionNapiUtils::CreateJSObject(env,
        exports,
        AVSESSION_CONTROLLER_NAPI_CLASS_NAME,
        JsObjectConstruct,
        avsession_controller_prop_desc,
        sizeof(avsession_controller_prop_desc) / sizeof(avsession_controller_prop_desc[0]),
        &g_avsessionControllerConstructor);
    if (status == napi_ok) {
        return exports;
    }
    SLOGE("Failure in NapiAVSessionController::Init()");
    return AVSessionNapiUtils::NapiUndefined(env);
}

napi_value NapiAVSessionController::JsObjectConstruct(napi_env env, napi_callback_info info)
{
    napi_value jsThis;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    if (status != napi_ok) {
        SLOGE("napi_get_cb_info error");
        return AVSessionNapiUtils::NapiUndefined(env);
    }
    unique_ptr<NapiAVSessionController> obj = make_unique<NapiAVSessionController>();
    if (obj == nullptr) {
        SLOGE("obj is nullptr");
        return AVSessionNapiUtils::NapiUndefined(env);
    }
    obj->env_ = env;
    int32_t sessionId;
    if (argc > 0) {
        napi_get_value_int32(env, argv[0], &sessionId);
        obj->avsessionController_ = AVSessionManager::CreateController(sessionId);
        if (obj->avsessionController_ == nullptr) {
            SLOGE("native CreateController fail ");
            return AVSessionNapiUtils::NapiUndefined(env);
        }
        SLOGI("AVSessionManager::CreateController success ");
    } else {
        SLOGE("NapiAVSessionController::CreateController No parameters ");
        status = napi_invalid_arg;
    }
    status = napi_wrap(env, jsThis, static_cast<void*>(obj.get()),
        NapiAVSessionController::Destructor, nullptr, &(obj->wrapper_));
    if (status == napi_ok) {
        status = AVSessionNapiUtils::SetValueInt32(env, "sessionId", sessionId, jsThis);
    }
    if (status != napi_ok) {
        SLOGE("SetValueInt32 error");
        return AVSessionNapiUtils::NapiUndefined(env);
    }
    obj.release();
    return jsThis;
}

void NapiAVSessionController::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    if (nativeObject != nullptr) {
        auto obj = static_cast<NapiAVSessionController*>(nativeObject);
        delete obj;
        obj = nullptr;
        SLOGI("NapiAVSessionController::Destructor delete NapiAVSessionController obj done");
    }
}

napi_status NapiAVSessionController::NewInstance(napi_env env, napi_value* result, int32_t sessionId)
{
    napi_value constructor;
    napi_status status = napi_get_reference_value(env, g_avsessionControllerConstructor, &constructor);
    if (status == napi_ok) {
        napi_value arg;
        napi_create_int32(env, sessionId, &arg);
        status = napi_new_instance(env, constructor, 1, &arg, result);
    }
    return status;
}

napi_value NapiAVSessionController::GetAVPlaybackState(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> avsessionControllerProxy;
    avsessionControllerProxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    avsessionControllerProxy.ParseInputs(parsers);

    return avsessionControllerProxy.DoAsyncWork(
        "GetAVPlaybackState",
        [](AVSessionControllerAsyncContext* asyncContext) {
            SLOGI(" NapiAVSessionController::GetAVPlaybackState async ");
            asyncContext->aVPlaybackState = make_shared<AVPlaybackState>();
            NapiAVSessionController* napiController = static_cast<NapiAVSessionController*>(asyncContext->objectInfo);
            int32_t ret = napiController->avsessionController_->GetAVPlaybackState(*asyncContext->aVPlaybackState);
            if (ret) {
                SLOGE(" native GetAVPlaybackState() fail ");
                return ERR;
            }
            return OK;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            AVSessionNapiUtils::WrapAVPlaybackStateToNapi(asyncContext->env, *asyncContext->aVPlaybackState, output);
            return OK;
        });
}

napi_value NapiAVSessionController::GetAVMetadata(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> avsessionControllerProxy;
    avsessionControllerProxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    avsessionControllerProxy.ParseInputs(parsers);

    return avsessionControllerProxy.DoAsyncWork(
        "GetAVMetadata",
        [](AVSessionControllerAsyncContext* asyncContext) {
            SLOGI(" NapiAVSessionController::GetAVMetadata async ");
            asyncContext->aVMetaData = make_shared<AVMetaData>();
            NapiAVSessionController* napiController = static_cast<NapiAVSessionController*>(asyncContext->objectInfo);
            int32_t ret = napiController->avsessionController_->GetAVMetaData(*asyncContext->aVMetaData);
            if (ret) {
                SLOGE(" native GetAVMetadata() fail ");
                return ERR;
            }
            return OK;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            AVSessionNapiUtils::WrapAVMetadataToNapi(asyncContext->env, *asyncContext->aVMetaData, output);
            std::string getAVMetadataAssetId = AVSessionNapiUtils::GetValueString(asyncContext->env, "assetId", output);
            SLOGE(" WrapAVMetadataToNapi getAVMetadataAssetId assetId = %{public}s", getAVMetadataAssetId.c_str());
            return OK;
        });
}

void GetKeyEvent(const napi_env& env, const napi_value& object, AVSessionControllerAsyncContext* asyncContext)
{
    AVSessionNapiUtils::WrapNapiToKeyEvent(env, object, asyncContext->keyEvent);
}

napi_value NapiAVSessionController::SendAVKeyEvent(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> avsessionControllerProxy;
    avsessionControllerProxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    parsers.push_back(GetKeyEvent);
    avsessionControllerProxy.ParseInputs(parsers);

    return avsessionControllerProxy.DoAsyncWork(
        "SendAVKeyEvent",
        [](AVSessionControllerAsyncContext* asyncContext) {
            if (asyncContext->keyEvent == nullptr) {
                SLOGE("get param keyEvent fail");
                return ERR;
            }
            return OK;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            SLOGI("NapiAVSessionController::SendAVKeyEvent() async");
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            NapiAVSessionController* napiController = static_cast<NapiAVSessionController*>(asyncContext->objectInfo);
            if (napiController->avsessionController_ != nullptr) {
                int32_t ret = napiController->avsessionController_->SendAVKeyEvent(*asyncContext->keyEvent);
                if (ret) {
                    SLOGE("native SendAVKeyEvent() fail");
                    return ERR;
                }
                return OK;
            }
            SLOGE("NapiAVSessionController::SendAVKeyEvent avsessionController_ is nullptr");
            return ERR;
        });
}

napi_value NapiAVSessionController::GetLaunchAbility(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> avsessionControllerProxy;
    avsessionControllerProxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    avsessionControllerProxy.ParseInputs(parsers);

    return avsessionControllerProxy.DoAsyncWork(
        "GetLaunchAbility",
        [](AVSessionControllerAsyncContext* asyncContext) {
            NapiAVSessionController* napiController = static_cast<NapiAVSessionController*>(asyncContext->objectInfo);
            if (napiController->avsessionController_ != nullptr) {
                int32_t ret = napiController->avsessionController_->GetLaunchAbility(*asyncContext->wantAgent);
                if (ret) {
                    SLOGE(" native GetLaunchAbility() fail");
                    return ERR;
                }
                return OK;
            }
            SLOGE("NapiAVSessionController::GetLaunchAbility avsessionController_ is nullptr");
            return ERR;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            napi_value wantAgentClass = nullptr;
            napi_define_class(asyncContext->env, "WantAgentClass", NAPI_AUTO_LENGTH,
                [](napi_env env, napi_callback_info info) -> napi_value {
                    napi_value thisVar = nullptr;
                    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
                    return thisVar;
                },
                nullptr, 0, nullptr, &wantAgentClass);
            napi_new_instance(asyncContext->env, wantAgentClass, 0, nullptr, &output);
            napi_wrap(asyncContext->env, output, (void*)asyncContext->wantAgent.get(),
                [](napi_env env, void* data, void* hint) {}, nullptr, nullptr);
            return OK;
        });
}

napi_value NapiAVSessionController::IsActive(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> avsessionControllerProxy;
    avsessionControllerProxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    avsessionControllerProxy.ParseInputs(parsers);

    return avsessionControllerProxy.DoAsyncWork(
        "IsActive",
        [](AVSessionControllerAsyncContext* asyncContext) {
            return OK;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            SLOGI(" NapiAVSessionController::IsActive() async ");
            NapiAVSessionController* napiController = static_cast<NapiAVSessionController*>(asyncContext->objectInfo);
            int32_t ret = napiController->avsessionController_->IsSessionActive(asyncContext->isActive);
            if (ret) {
                SLOGE(" native IsActive() fail ");
                return ERR;
            }
            napi_get_boolean(asyncContext->env, asyncContext->isActive, &output);
            return OK;
        });
}

napi_value NapiAVSessionController::Destroy(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> avsessionControllerProxy;
    avsessionControllerProxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    avsessionControllerProxy.ParseInputs(parsers);

    return avsessionControllerProxy.DoAsyncWork(
        "Destroy",
        [](AVSessionControllerAsyncContext* asyncContext) {
            return OK;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            SLOGI(" NapiAVSessionController::Destroy() ");
            NapiAVSessionController* napiController = static_cast<NapiAVSessionController*>(asyncContext->objectInfo);
            int32_t ret = napiController->avsessionController_->Release();
            if (ret) {
                SLOGE(" native avsessionController::Release() fail ");
                return ERR;
            }
            SLOGI(" native avsessionController::Release() success ");
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}

napi_value NapiAVSessionController::GetValidCommands(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> avsessionControllerProxy;
    avsessionControllerProxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    avsessionControllerProxy.ParseInputs(parsers);

    return avsessionControllerProxy.DoAsyncWork(
        "GetValidCommands",
        [](AVSessionControllerAsyncContext* asyncContext) {
            NapiAVSessionController* napiController = static_cast<NapiAVSessionController*>(asyncContext->objectInfo);
            int32_t ret = napiController->avsessionController_->GetValidCommands(asyncContext->cmds);
            if (ret) {
                SLOGE(" native GetValidCommands() fail ");
                return ERR;
            }
            return OK;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            napi_status status;
            size_t size = asyncContext->cmds.size();
            SLOGI("GetValidCommands size = %{public}zu", size);
            if (size == 0) {
                napi_create_string_utf8(asyncContext->env, "", NAPI_AUTO_LENGTH, &output);
                return OK;
            }
            napi_create_array_with_length(asyncContext->env, size, &output);
            for (size_t i = 0; i < size; i ++) {
                napi_value valueParam = nullptr;
                (void)napi_create_object(asyncContext->env, &valueParam);
                int32_t cmd = asyncContext->cmds[i];
                if (aVControlCommandToStrMap.find(cmd) != aVControlCommandToStrMap.end()) {
                    napi_create_string_utf8(asyncContext->env, aVControlCommandToStrMap[cmd].c_str(),
                                            NAPI_AUTO_LENGTH, &valueParam);
                }
                status = napi_set_element(asyncContext->env, output, i, valueParam);
                if (status != napi_ok) {
                    SLOGE(" wrap  cmds to napi_value fail ");
                    return ERR;
                }
            }
            return OK;
        });
}

void GetArgvAVControlCommand(const napi_env& env, const napi_value& object,
                             AVSessionControllerAsyncContext *asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        SLOGE("SendControlCommand valueType incorrect");
        return ;
    }
    std::string strCommand = AVSessionNapiUtils::GetValueString(env, "command", object);
    if (strCommand.empty()) {
        SLOGE("SendControlCommand get param command  fail ");
        return ;
    }
    int32_t command = AVControlCommand::SESSION_CMD_MAX;
    if (aVControlCommandMap.find(strCommand) == aVControlCommandMap.end()) {
        SLOGE("SendControlCommand can not find %{public}s", strCommand.c_str());
        return ;
    }
    command = aVControlCommandMap[strCommand];
    asyncContext->aVControlCommand = make_shared<AVControlCommand>();
    SLOGI("get command: %{public}d", command);
    asyncContext->aVControlCommand->SetCommand(command);
    napi_value res = nullptr;
    if (napi_get_named_property(env, object, "parameter", &res) != napi_ok) {
        SLOGE("SendControlCommand napi_get_named_property error");
        return ;
    }
    napi_typeof(env, res, &valueType);
    if (valueType == napi_number && command == AVControlCommand::SESSION_CMD_SEEK) {
        int64_t time = 0;
        napi_get_value_int64(env, res, &time);
        asyncContext->aVControlCommand->SetSeekTime(time);
    }
    if (valueType == napi_number && command == AVControlCommand::SESSION_CMD_SET_SPEED) {
        double speed = 1.0;
        napi_get_value_double(env, res, &speed);
        asyncContext->aVControlCommand->SetSpeed(speed);
    }
    if (valueType == napi_number && command == AVControlCommand::SESSION_CMD_SET_LOOP_MODE) {
        int32_t loopMode = 0;
        napi_get_value_int32(env, res, &loopMode);
        asyncContext->aVControlCommand->SetLoopMode(loopMode);
    }
    if (valueType == napi_string && command == AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE) {
        std::string mediald = AVSessionNapiUtils::GetStringArgument(env, res);
        asyncContext->aVControlCommand->SetAssetId(mediald);
    }
}

napi_value NapiAVSessionController::SendControlCommand(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    parsers.push_back(GetArgvAVControlCommand);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "SendControlCommand",
        [](AVSessionControllerAsyncContext* asyncContext) {
            return OK;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            SLOGI(" NapiAVSession::SendControlCommand()");
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            NapiAVSessionController* napiController = static_cast<NapiAVSessionController*>(asyncContext->objectInfo);
            SLOGI("SendControlCommand : %{public}d ", asyncContext->aVControlCommand->GetCommand());
            int32_t ret = napiController->avsessionController_->SendControlCommand(*asyncContext->aVControlCommand);
            if (ret) {
                SLOGE(" native SendControlCommand fail ");
                return ERR;
            }
            return OK;
        });
}

napi_value NapiAVSessionController::RegisterCallback(napi_env env,
                                                     napi_value& jsThis,
                                                     napi_value& callbackRef,
                                                     napi_value& filter,
                                                     std::string& callbackName)
{
    NapiAVSessionController* napiController = nullptr;
    napi_status status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&napiController));
    if (status != napi_ok || napiController == nullptr) {
        SLOGE("unwrap napiController error");
        return AVSessionNapiUtils::NapiUndefined(env);
    }
    if (napiController->avcontrollerCallback_ == nullptr) {
        napiController->avcontrollerCallback_ = std::make_shared<NapiAVControllerCallback>();
    }
    if (napiController->avsessionController_ == nullptr) {
        SLOGE("controller did not create .");
        return AVSessionNapiUtils::NapiUndefined(env);
    }
    int32_t ret = napiController->avsessionController_->RegisterCallback(napiController->avcontrollerCallback_);
    if (ret) {
        SLOGE("native RegisterSessionListener Failed");
        return AVSessionNapiUtils::NapiUndefined(env);
    }
    std::shared_ptr<NapiAVControllerCallback> cb =
        std::static_pointer_cast<NapiAVControllerCallback>(napiController->avcontrollerCallback_);
    if (cb->hasCallback(callbackName)) {
        cb->SaveCallbackReference(callbackName, callbackRef, env);
        if (!callbackName.compare(PLAYBACKSTATECHANGED_CALLBACK) ||
            !callbackName.compare(METADATACHANGED_CALLBACK)) {
            cb->SaveFilter(napiController->avsessionController_, callbackName, filter, env);
        }
    }
    return AVSessionNapiUtils::NapiUndefined(env);
}

napi_value NapiAVSessionController::On(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = AVSessionNapiUtils::NapiUndefined(env);
    const size_t minArgCount = 3;
    size_t argCount = 3;
    napi_value args[minArgCount] = { nullptr, nullptr, nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    napi_valuetype eventType = napi_undefined;
    if (napi_typeof(env, args[0], &eventType) != napi_ok || eventType != napi_string) {
        SLOGE("first parameter is not string");
        return undefinedResult;
    }
    std::string callbackName = AVSessionNapiUtils::GetStringArgument(env, args[0]);
    SLOGI("NapiAVSessionController::On callbackName: %{public}s", callbackName.c_str());
    if (!callbackName.compare(PLAYBACKSTATECHANGED_CALLBACK) ||
        !callbackName.compare(METADATACHANGED_CALLBACK)) {
        if (status != napi_ok || argCount < minArgCount) {
            SLOGE("Less than third parameters");
            return undefinedResult;
        }
    } else {
        if (status != napi_ok || argCount < minArgCount - 1) {
            SLOGE("Less than two parameters");
            return undefinedResult;
        }
    }
    napi_value callbackRef = nullptr;
    if (!callbackName.compare(PLAYBACKSTATECHANGED_CALLBACK) ||
        !callbackName.compare(METADATACHANGED_CALLBACK)) {
        if (napi_typeof(env, args[minArgCount - 1], &eventType) != napi_ok || eventType != napi_function) {
            SLOGE("The third argument is not a function .");
            return undefinedResult;
        }
        callbackRef = args[minArgCount - 1];
    } else {
        if (napi_typeof(env, args[1], &eventType) != napi_ok || eventType != napi_function) {
            SLOGE("The second argument is not a function .");
            return undefinedResult;
        }
        callbackRef = args[1];
    }
    return RegisterCallback(env, jsThis, callbackRef, args[1], callbackName);
}

napi_value NapiAVSessionController::Off(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = AVSessionNapiUtils::NapiUndefined(env);
    const size_t minArgCount = 1;
    size_t argCount = 1;
    napi_value args[minArgCount] = {nullptr};
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok || argCount < minArgCount) {
        SLOGE("Less than two parameters");
        return undefinedResult;
    }
    napi_valuetype eventType = napi_undefined;
    if (napi_typeof(env, args[0], &eventType) != napi_ok || eventType != napi_string) {
        return undefinedResult;
    }
    std::string callbackName = AVSessionNapiUtils::GetStringArgument(env, args[0]);
    SLOGI("NapiAVSessionController::On callbackName: %{public}s", callbackName.c_str());
    NapiAVSessionController *napiController = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&napiController));
    if (status != napi_ok || napiController == nullptr) {
        SLOGE("napi_unwrap napiController error");
    }
    if (napiController->avcontrollerCallback_ == nullptr) {
        SLOGE("NapiAVSessionController: Off Failed");
        return undefinedResult;
    }
    std::shared_ptr<NapiAVControllerCallback> cb =
        std::static_pointer_cast<NapiAVControllerCallback>(napiController->avcontrollerCallback_);
    if (cb->hasCallback(callbackName)) {
        cb->ReleaseCallbackReference(callbackName);
    }
    return AVSessionNapiUtils::NapiUndefined(env);
}

napi_value NapiAVSessionController::GetOutputDevice(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<AVSessionControllerAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<AVSessionControllerAsyncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "GetOutputDevice",
        [](AVSessionControllerAsyncContext* asyncContext) {
            return OK;
        },
        [](AVSessionControllerAsyncContext* asyncContext, napi_value& output) {
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            SLOGE(" There is no native GetOutputDevice interface .");
            return OK;
        });
}

napi_value NapiAVSessionController::GetRealPlaybackPositionSync(napi_env env, napi_callback_info info)
{
    SLOGE(" There is no native GetRealPlaybackPositionSync interface .");
    napi_value jsResult = nullptr;
    napi_status status = napi_create_int64(env, 100, &jsResult);
    if (status == napi_ok) {
        return jsResult;
    }
    return AVSessionNapiUtils::NapiUndefined(env);
}
}