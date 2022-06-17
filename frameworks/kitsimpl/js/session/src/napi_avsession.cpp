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

#include "avsession_controller.h"
#include "napi_avsession.h"
#include "napi_avsession_controller.h"
#include "want_agent.h"

using namespace std;

namespace OHOS::AVSession {
static __thread napi_ref g_avsessionConstructor = nullptr;
static const std::string AVSESSION_NAPI_CLASS_NAME = "AVSession";

struct NapiAVSessionAsyncContext : NapiAsyncProxy<NapiAVSessionAsyncContext>::AysncContext {
    AbilityRuntime::WantAgent::WantAgent *wantAgent = nullptr;
    std::shared_ptr<AVSessionController> avSessionController = nullptr;
    std::vector<int32_t> streamIds;
    std::shared_ptr<AVMetaData> aVMetaData = nullptr;
    std::shared_ptr<AVPlaybackState> aVPlaybackState = nullptr;
};

NapiAVSession::NapiAVSession()
    : env_(nullptr), wrapper_(nullptr), avsession_(nullptr), avsessionCallback_(nullptr) {}

NapiAVSession::~NapiAVSession()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

napi_value NapiAVSession::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor avsession_prop_desc[] = {
        DECLARE_NAPI_FUNCTION("setAVMetadata", SetAVMetadata),
        DECLARE_NAPI_FUNCTION("setAVPlaybackState", SetAVPlaybackState),
        DECLARE_NAPI_FUNCTION("setLaunchAbility", SetLaunchAbility),
        DECLARE_NAPI_FUNCTION("setAudioStreamId", SetAudioStreamId),
        DECLARE_NAPI_FUNCTION("getController", GetController),
        DECLARE_NAPI_FUNCTION("activate", Activate),
        DECLARE_NAPI_FUNCTION("deactivate", Deactivate),
        DECLARE_NAPI_FUNCTION("destroy", Destroy),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
        DECLARE_NAPI_FUNCTION("getOutputDevice", GetOutputDevice)
    };
    napi_status status = AVSessionNapiUtils::CreateJSObject(env, exports, AVSESSION_NAPI_CLASS_NAME, JsObjectConstruct,
        avsession_prop_desc, sizeof(avsession_prop_desc) / sizeof(avsession_prop_desc[0]), &g_avsessionConstructor);
    if (status == napi_ok) {
        return exports;
    }
    SLOGE("Failure in NapiAVSession::Init()");
    return AVSessionNapiUtils::NapiUndefined(env);
}

// Constructor callback
napi_value NapiAVSession::JsObjectConstruct(napi_env env, napi_callback_info info)
{
    napi_value jsThis;
    size_t argc = 2;
    napi_value argv[2] = { nullptr, nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    if (status == napi_ok) {
        unique_ptr<NapiAVSession> obj = make_unique<NapiAVSession>();
        if (obj != nullptr) {
            obj->env_ = env;
            std::string tag = AVSessionNapiUtils::GetStringArgument(env, argv[0]);
            int32_t type;
            napi_get_value_int32(env, argv[1], &type);
            auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
            string bundleName = ability->GetWant()->GetElement().GetBundleName();
            string abilityName = ability->GetWant()->GetElement().GetAbilityName();
            SLOGI("abilityName %{public}s ,bundleName %{public}s ,tag: %{public}s ,type:%{public}d ",
                abilityName.c_str(), bundleName.c_str(), tag.c_str(), type);
            obj->avsession_ = AVSessionManager::CreateSession(tag, type, ability->GetWant()->GetElement());
            if (obj->avsession_ == nullptr) {
                SLOGE("native CreateSession fail.");
                return AVSessionNapiUtils::NapiUndefined(env);
            }
            status = napi_wrap(env, jsThis, static_cast<void*>(obj.get()),
                               NapiAVSession::Destructor, nullptr, &(obj->wrapper_));
            if (status == napi_ok) {
                status = AVSessionNapiUtils::SetValueInt32(env, "sessionId", obj->avsession_->GetSessionId(), jsThis);
            }
            if (status == napi_ok) {
                obj.release();
                return jsThis;
            }
        }
    }
    SLOGE("Failed in NapiAVSession::Construct()!");
    return AVSessionNapiUtils::NapiUndefined(env);
}

void NapiAVSession::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    if (nativeObject != nullptr) {
        auto obj = static_cast<NapiAVSession*>(nativeObject);
        delete obj;
        obj = nullptr;
        SLOGI("NapiAVSession::Destructor delete NapiAVSession obj done");
    }
}

void GetNapiAVMetadata(const napi_env& env, const napi_value& object, NapiAVSessionAsyncContext* asyncContext)
{
    asyncContext->aVMetaData = make_shared<AVMetaData>();
    AVSessionNapiUtils::WrapNapiToAVMetadata(env, object, *asyncContext->aVMetaData);
}

napi_value NapiAVSession::SetAVMetadata(napi_env env, napi_callback_info info)
{
    SLOGI(" NapiAVSession::SetAVMetadata entry");
    NapiAsyncProxy<NapiAVSessionAsyncContext> avsessionProxy;
    avsessionProxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    parsers.push_back(GetNapiAVMetadata);
    avsessionProxy.ParseInputs(parsers);

    return avsessionProxy.DoAsyncWork(
        "SetAVMetadata",
        [](NapiAVSessionAsyncContext* asyncContext) {
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            SLOGI(" NapiAVSession::SetAVMetadata Async");
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);

            NapiAVSession* napiAVSession = static_cast<NapiAVSession*>(asyncContext->objectInfo);
            int32_t ret = napiAVSession->avsession_->SetAVMetaData(*asyncContext->aVMetaData);
            if (ret) {
                SLOGE(" native SetAVMetaData fail ");
                return ERR;
            }
            return OK;
        });
}

void GetArgvAVPlaybackState(const napi_env& env, const napi_value& object, NapiAVSessionAsyncContext* asyncContext)
{
    asyncContext->aVPlaybackState = make_shared<AVPlaybackState>();
    AVSessionNapiUtils::WrapNapiToAVPlaybackState(env, object, *asyncContext->aVPlaybackState);
}

napi_value NapiAVSession::SetAVPlaybackState(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<NapiAVSessionAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    parsers.push_back(GetArgvAVPlaybackState);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "SetAVPlaybackState",
        [](NapiAVSessionAsyncContext* asyncContext) {
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            NapiAVSession* napiAVSession = static_cast<NapiAVSession*>(asyncContext->objectInfo);
            int32_t ret = napiAVSession->avsession_->SetAVPlaybackState(*asyncContext->aVPlaybackState);
            if (ret) {
                SLOGE(" native SetAVPlaybackState fail ");
                return ERR;
            }
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}

void GetWantAgent(const napi_env& env, const napi_value& object, NapiAVSessionAsyncContext* asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_object) {
        napi_status status = napi_unwrap(env, object, reinterpret_cast<void**>(&asyncContext->wantAgent));
        if (status != napi_ok || asyncContext->wantAgent == nullptr) {
            SLOGE("napi_unwrap asyncContext->wantAgent error");
        }
    }
}

napi_value NapiAVSession::SetLaunchAbility(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<NapiAVSessionAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    parsers.push_back(GetWantAgent);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "SetAVPlaybackState",
        [](NapiAVSessionAsyncContext* asyncContext) {
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            NapiAVSession* napiAVSession = static_cast<NapiAVSession*>(asyncContext->objectInfo);
            int32_t ret = napiAVSession->avsession_->SetLaunchAbility(*(asyncContext->wantAgent));
            if (ret) {
                SLOGE(" native SetLaunchAbility fail");
                return ERR;
            }
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}

napi_value NapiAVSession::GetController(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<NapiAVSessionAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "GetController",
        [](NapiAVSessionAsyncContext* asyncContext) {
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            auto context = static_cast<NapiAVSession*>(asyncContext->objectInfo);
            napi_status status = NapiAVSessionController::NewInstance(asyncContext->env,
                                                                      &output,
                                                                      context->avsession_->GetSessionId());
            if (status == napi_ok) {
                return OK;
            }
            return ERR;
        });
}

napi_value NapiAVSession::Activate(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<NapiAVSessionAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "Activate",
        [](NapiAVSessionAsyncContext* asyncContext) {
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            SLOGI(" NapiAVSession::Activate() ");
            NapiAVSession* napiAVSession = static_cast<NapiAVSession*>(asyncContext->objectInfo);
            int32_t ret = napiAVSession->avsession_->Active();
            if (ret) {
                SLOGE(" native Active fail ");
                return ERR;
            }
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}

napi_value NapiAVSession::Deactivate(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<NapiAVSessionAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "Deactivate",
        [](NapiAVSessionAsyncContext* asyncContext) {
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            SLOGI(" NapiAVSession::Deactivate() ");
            NapiAVSession* napiAVSession = static_cast<NapiAVSession*>(asyncContext->objectInfo);
            int32_t ret = napiAVSession->avsession_->Disactive();
            if (ret) {
                SLOGE(" native Disactive fail ");
                return ERR;
            }
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}

napi_value NapiAVSession::Destroy(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<NapiAVSessionAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "Destroy",
        [](NapiAVSessionAsyncContext* asyncContext) {
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            SLOGI(" NapiAVSession::Destroy() ");
            NapiAVSession* napiAVSession = static_cast<NapiAVSession*>(asyncContext->objectInfo);
            int32_t ret = napiAVSession->avsession_->Release();
            if (ret) {
                SLOGE(" native Release fail ");
                return ERR;
            }
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}

napi_value NapiAVSession::On(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = AVSessionNapiUtils::NapiUndefined(env);
    const size_t minArgCount = 2;
    size_t argCount = 2;
    napi_value args[minArgCount] = {nullptr, nullptr};
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
    if (napi_typeof(env, args[1], &eventType) != napi_ok || eventType != napi_function) {
        SLOGE("The second argument is not a function .");
        return undefinedResult;
    }
    std::string callbackName = AVSessionNapiUtils::GetStringArgument(env, args[0]);
    SLOGI("NapiAVSession::On callbackName: %{public}s", callbackName.c_str());
    NapiAVSession *napiAVSession = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&napiAVSession));
    if (status != napi_ok || napiAVSession == nullptr) {
        SLOGE("napi_unwrap napiAVSession error");
    }
    if (napiAVSession->avsessionCallback_ == nullptr) {
        napiAVSession->avsessionCallback_ = std::make_shared<NapiAVSessionCallback>();
        int32_t ret = napiAVSession->avsession_->RegisterCallback(napiAVSession->avsessionCallback_);
        if (ret) {
            SLOGE("NapiAVSessionController: avsessionController_ RegisterCallback Failed");
            return undefinedResult;
        }
    }
    auto iter = find(CALLBACK_VECTOR.begin(), CALLBACK_VECTOR.end(), callbackName);
    if (iter != CALLBACK_VECTOR.end()) {
        std::shared_ptr<NapiAVSessionCallback> cb =
            std::static_pointer_cast<NapiAVSessionCallback>(napiAVSession->avsessionCallback_);
        cb->SaveCallbackReference(callbackName, args[1], env);
    }
    return AVSessionNapiUtils::NapiUndefined(env);
}

napi_value NapiAVSession::Off(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = AVSessionNapiUtils::NapiUndefined(env);
    const size_t minArgCount = 1;
    size_t argCount = 1;
    napi_value args[minArgCount] = {nullptr};
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    if (status != napi_ok || argCount < minArgCount) {
        SLOGE("Less than one parameters");
        return undefinedResult;
    }
    napi_valuetype eventType = napi_undefined;
    if (napi_typeof(env, args[0], &eventType) != napi_ok || eventType != napi_string) {
        return undefinedResult;
    }
    std::string callbackName = AVSessionNapiUtils::GetStringArgument(env, args[0]);
    SLOGI("NapiAVSession::On callbackName: %{public}s", callbackName.c_str());
    NapiAVSession *napiAVSession = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&napiAVSession));
    if (status != napi_ok || napiAVSession == nullptr) {
        SLOGE("napi_unwrap napiAVSession error");
    }
    if (napiAVSession->avsessionCallback_ == nullptr) {
        SLOGE("NapiAVSession: off Failed");
        return undefinedResult;
    }
    auto iter = find(CALLBACK_VECTOR.begin(), CALLBACK_VECTOR.end(), callbackName);
    if (iter != CALLBACK_VECTOR.end()) {
        std::shared_ptr<NapiAVSessionCallback> cb =
            std::static_pointer_cast<NapiAVSessionCallback>(napiAVSession->avsessionCallback_);
        cb->ReleaseCallbackReference(callbackName);
    }
    return AVSessionNapiUtils::NapiUndefined(env);
}

napi_status NapiAVSession::NewInstance(napi_env env, napi_value * result, std::string tag, int32_t type)
{
    napi_value constructor;
    napi_status status = napi_get_reference_value(env, g_avsessionConstructor, &constructor);
    if (status == napi_ok) {
        const int32_t argNum = 2;
        napi_value args[argNum] = { nullptr, nullptr };
        status = napi_create_string_utf8(env, tag.c_str(), NAPI_AUTO_LENGTH, &args[0]);
        if (status != napi_ok) {
            return status;
        }
        status = napi_create_int32(env, type, &args[1]);
        if (status != napi_ok) {
            return status;
        }
        status = napi_new_instance(env, constructor, argNum, args, result);
    }
    return status;
}

void GetArgvStreamIds(const napi_env& env, const napi_value& object, NapiAVSessionAsyncContext* asyncContext)
{
    bool isArray = false;
    uint32_t len = 0;
    if ((napi_is_array(env, object, &isArray) != napi_ok) || (isArray == false)) {
        SLOGE("GetArgvStreamIds object not an array");
        return;
    }
    if (napi_get_array_length(env, object, &len) != napi_ok) {
        SLOGE("GetArgvStreamIds get array length error");
        return;
    }
    SLOGD("GetArgvStreamIds array length :%{public}d.", len);
    for (uint32_t i = 0; i < len; i++) {
        napi_value streamIdItem = nullptr;
        napi_valuetype valueType = napi_undefined;

        napi_get_element(env, object, i, &streamIdItem);
        napi_typeof(env, streamIdItem, &valueType);
        if (valueType == napi_number) {
            int32_t streamId = 0;
            napi_get_value_int32(env, streamIdItem, &streamId);
            asyncContext->streamIds.push_back(streamId);
        }
    }
    SLOGD("GetArgvStreamIds execute success");
}

napi_value NapiAVSession::SetAudioStreamId(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<NapiAVSessionAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    parsers.push_back(GetArgvStreamIds);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "SetAudioStreamId",
        [](NapiAVSessionAsyncContext* asyncContext) {
            SLOGE("No native methods: SetAudioStreamId .");
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}

napi_value NapiAVSession::GetOutputDevice(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<NapiAVSessionAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<NapiAVSessionAsyncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "GetOutputDevice",
        [](NapiAVSessionAsyncContext* asyncContext) {
            return OK;
        },
        [](NapiAVSessionAsyncContext* asyncContext, napi_value& output) {
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}
}