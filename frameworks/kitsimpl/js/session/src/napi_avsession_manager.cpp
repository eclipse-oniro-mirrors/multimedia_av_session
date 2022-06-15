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

#include <string.h>
#include "avcontrol_command.h"
#include "avplayback_state.h"
#include "key_event.h"
#include "napi_avsession_manager.h"

using namespace std;

namespace OHOS::AVSession {
struct AudioDeviceDescriptor {
    int32_t deviceRole;
    int32_t deviceType;
};

struct ManagerAsyncContext : NapiAsyncProxy<ManagerAsyncContext>::AysncContext {
    std::string tag;
    int32_t type = -1;
    int32_t volume;
    int32_t sessionId;
    std::shared_ptr<MMI::KeyEvent> keyEvent = nullptr;
    std::shared_ptr<AVControlCommand> aVControlCommand = nullptr;
    pid_t pid;
    uid_t uid;
    std::string session;
    std::vector<AudioDeviceDescriptor> audioDeviceDescriptors;
};

napi_ref NapiAVSessionManager::loopModeTypeRef_ = nullptr;
napi_ref NapiAVSessionManager::playbackStateTypeRef_ = nullptr;

NapiAVSessionManager::NapiAVSessionManager()
    : env_(nullptr), wrapper_(nullptr), avSessionController_(nullptr), sessionListenerCallback_(nullptr) {}

NapiAVSessionManager::~NapiAVSessionManager()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void GetTag(const napi_env& env, const napi_value& object, ManagerAsyncContext* asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_string) {
        asyncContext->tag = AVSessionNapiUtils::GetStringArgument(env, object);
    }
}

void GetType(const napi_env& env, const napi_value& object, ManagerAsyncContext* asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_string) {
        std::string value = AVSessionNapiUtils::GetStringArgument(env, object);
        if (!value.empty() && !value.compare("audio")) {
            asyncContext->type = AVSession::SESSION_TYPE_AUDIO;
        } else if (!value.empty() && !value.compare("video")) {
            asyncContext->type = AVSession::SESSION_TYPE_VIDEO;
        }
    }
}

void GetVolume(const napi_env& env, const napi_value& object, ManagerAsyncContext* asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_number) {
         napi_get_value_int32(env, object, &asyncContext->volume);
    }
}

napi_value NapiAVSessionManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVSession", CreateAVSession),
        DECLARE_NAPI_STATIC_FUNCTION("getAllSessionDescriptors", GetAllSessionDescriptors),
        DECLARE_NAPI_STATIC_FUNCTION("createController", CreateController),
        DECLARE_NAPI_STATIC_FUNCTION("castAudio", CastAudio),
        DECLARE_NAPI_STATIC_FUNCTION("sendSystemAVKeyEvent", SendSystemAVKeyEvent),
        DECLARE_NAPI_STATIC_FUNCTION("sendSystemControlCommand", SendSystemControlCommand),
        DECLARE_NAPI_STATIC_FUNCTION("on", On),
        DECLARE_NAPI_STATIC_FUNCTION("off", Off),
        DECLARE_NAPI_PROPERTY("LoopMode", CreateLoopModeObject(env)),
        DECLARE_NAPI_PROPERTY("PlaybackState", CreatePlaybackStateObject(env))
    };

    napi_status status = napi_define_properties(env, exports,
        sizeof(static_prop) / sizeof(static_prop[AVSessionNapiUtils::PARAM0]), static_prop);
    if (status == napi_ok) {
        return exports;
    }
    SLOGE("Failure in NapiAVSessionManager::Init()");
    return AVSessionNapiUtils::NapiUndefined(env);
}

napi_value NapiAVSessionManager::CreateAVSession(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<ManagerAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<ManagerAsyncContext>::InputParser> parsers;
    parsers.push_back(GetTag);
    parsers.push_back(GetType);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "CreateAVSession",
        [](ManagerAsyncContext* asyncContext) {
            if (asyncContext->tag.empty()) {
                SLOGE("createSession tag is null");
                return ERR;
            }
            if (asyncContext->type < 0) {
                SLOGE("createSession type is not 'audio' | 'video' ");
                return ERR;
            }
            return OK;
        },
        [](ManagerAsyncContext* asyncContext, napi_value& output) {
            napi_status status = NapiAVSession::NewInstance(asyncContext->env,
                &output,asyncContext->tag, asyncContext->type);
            if (status == napi_ok) {
                return OK;
            }
            SLOGE("CreateAVSession fail ");
            return ERR;
        });
}

napi_value NapiAVSessionManager::GetAllSessionDescriptors(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<ManagerAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<ManagerAsyncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "GetAllSessionDescriptors",
        [](ManagerAsyncContext* asyncContext) {
            return OK;
        },
        [](ManagerAsyncContext* asyncContext, napi_value& output) {
            std::vector<AVSessionDescriptor> descriptor =  AVSessionManager::GetAllSessionDescriptors();
            size_t size = descriptor.size();
            SLOGI("AVSessionDescriptor size = %{public}zu", size);
            napi_value valueParam = nullptr;
            napi_status status;
            napi_create_array_with_length(asyncContext->env, size, &output);
            for (size_t i = 0; i < size; i ++) {
                (void)napi_create_object(asyncContext->env, &valueParam);
                AVSessionNapiUtils::WrapAVSessionDescriptorToNapi(asyncContext->env, descriptor[i], valueParam);
                status = napi_set_element(asyncContext->env, output, i, valueParam);
                if (status != napi_ok) {
                    return ERR;
                }
            }
            return OK;
        });
}

void GetSessionId(const napi_env& env, const napi_value& object, ManagerAsyncContext* asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(asyncContext->env, object, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, object, &asyncContext->sessionId);
        SLOGI("NapiAVSessionManager::GetSessionId() sessionId : %{public}d ", asyncContext->sessionId);
    }
}

napi_value NapiAVSessionManager::CreateController(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<ManagerAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<ManagerAsyncContext>::InputParser> parsers;
    parsers.push_back(GetSessionId);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "CreateController",
        [](ManagerAsyncContext* asyncContext) {
            return OK;
        },
        [](ManagerAsyncContext* asyncContext, napi_value& output) {
            napi_status status = NapiAVSessionController::NewInstance(
                asyncContext->env, &output, asyncContext->sessionId);
            if (status == napi_ok) {
                return OK;
            }
            SLOGE(" CreateController fail ");
            return ERR;
        });
}

napi_value NapiAVSessionManager::CreateLoopModeObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;
    int32_t refCount = 1;
    string propName;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        for (int i = AVControlCommand::LOOP_MODE_SEQUENCE; i <= AVControlCommand::LOOP_MODE_SHUFFLE; i++) {
            switch (i) {
                case AVControlCommand::LOOP_MODE_SEQUENCE:
                    propName = "LOOP_MODE_SEQUENCE";
                    break;
                case AVControlCommand::LOOP_MODE_SINGLE:
                    propName = "LOOP_MODE_SINGLE";
                    break;
                case AVControlCommand::LOOP_MODE_LIST:
                    propName = "LOOP_MODE_LIST";
                    break;
                case AVControlCommand::LOOP_MODE_SHUFFLE:
                    propName = "LOOP_MODE_SHUFFLE";
                    break;
                default:
                    SLOGE("CreateDeviceRoleObject: No prob with this value try next value!");
                    continue;
            }
            status = AVSessionNapiUtils::SetValueInt32(env, propName, i, result);
            if (status != napi_ok) {
                SLOGE("Failed to add named prop!");
                break;
            }
            propName.clear();
        }
        if (status == napi_ok) {
            status = napi_create_reference(env, result, refCount, &loopModeTypeRef_);
            if (status == napi_ok) {
                return result;
            }
        }
    }
    SLOGE("CreateLoopModeObject is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value NapiAVSessionManager::CreatePlaybackStateObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;
    int32_t refCount = 1;
    string propName;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        for (int i = AVPlaybackState::PLAYBACK_STATE_INITIAL + 1; i < AVPlaybackState::PLAYBACK_STATE_MAX; i++) {
            switch (i) {
                case AVPlaybackState::PLAYBACK_STATE_INITIAL:
                    propName = "PLAYBACK_STATE_INITIAL";
                    break;
                case AVPlaybackState::PLAYBACK_STATE_PREPARING:
                    propName = "PLAYBACK_STATE_PREPARE";
                    break;
                case AVPlaybackState::PLAYBACK_STATE_PLAYING:
                    propName = "PLAYBACK_STATE_PLAY";
                    break;
                case AVPlaybackState::PLAYBACK_STATE_PAUSED:
                    propName = "PLAYBACK_STATE_PAUSE";
                    break;
                case AVPlaybackState::PLAYBACK_STATE_FAST_FORWARD:
                    propName = "PLAYBACK_STATE_FAST_FORWARD";
                    break;
                case AVPlaybackState::PLAYBACK_STATE_REWIND:
                    propName = "PLAYBACK_STATE_REWIND";
                    break;
                case AVPlaybackState::PLAYBACK_STATE_STOP:
                    propName = "PLAYBACK_STATE_STOP";
                    break;
                default:
                    SLOGE("CreatePlaybackStateObject: No prob with this value try next value!");
                    continue;
            }
            status = AVSessionNapiUtils::SetValueInt32(env, propName, i, result);
            if (status != napi_ok) {
                SLOGE("Failed to add named prop!");
                break;
            }
            propName.clear();
        }
        if (status == napi_ok) {
            status = napi_create_reference(env, result, refCount, &playbackStateTypeRef_);
            if (status == napi_ok) {
                return result;
            }
        }
    }
    SLOGE("CreatePlaybackStateObject is Failed!");
    napi_get_undefined(env, &result);
    return result;
}

void NapiAVSessionManager::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    if (nativeObject != nullptr) {
        auto obj = static_cast<NapiAVSessionManager*>(nativeObject);
        obj->sessionListenerCallback_ = nullptr;
        delete obj;
        obj = nullptr;
        SLOGI("NapiAVSessionManager::Destructor delete NapiAVSessionManager obj done");
    }
}

napi_value NapiAVSessionManager::On(napi_env env, napi_callback_info info)
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
        SLOGE("The first argument is not string");
        return undefinedResult;
    }

    if (napi_typeof(env, args[1], &eventType) != napi_ok || eventType != napi_function) {
        SLOGE("The second argument is not a function .");
        return undefinedResult;
    }
    std::string callbackName = AVSessionNapiUtils::GetStringArgument(env, args[0]);
    SLOGI("NapiAVSessionManager::On callbackName: %{public}s", callbackName.c_str());

    NapiAVSessionManager* managerNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&managerNapi));

    if (managerNapi == nullptr) {
        SLOGI("There is no NapiAVSessionManager. create NapiAVSessionManager!");
        managerNapi = new NapiAVSessionManager();
        status = napi_wrap(env, jsThis, static_cast<void*>(managerNapi),
                           NapiAVSessionManager::Destructor, nullptr, &(managerNapi->wrapper_));
    }

    if (managerNapi->sessionListenerCallback_ == nullptr) {
        managerNapi->sessionListenerCallback_ = std::make_shared<NapiSessionListenerCallback>();
        int32_t ret = AVSessionManager::RegisterSessionListener(managerNapi->sessionListenerCallback_);
        if (ret) {
            SLOGE("NapiAVSessionManager: RegisterSessionListener Failed");
            return undefinedResult;
        }
        SLOGI(" create NapiSessionListenerCallback ");
    }

    if (!callbackName.compare(SESSIONCREATED_CALLBACK) ||
        !callbackName.compare(SESSIONRELEASED_CALLBACK) ||
        !callbackName.compare(TOPSESSIONCHANGED_CALLBACK) ||
        !callbackName.compare(SESSIONSERVICEDIED_CALLBACK)) {
        SLOGI("SaveCallbackReference start");
        std::shared_ptr<NapiSessionListenerCallback> cb =
            std::static_pointer_cast<NapiSessionListenerCallback>(managerNapi->sessionListenerCallback_);
        cb->SaveCallbackReference(callbackName, args[1], env);
        SLOGI("SaveCallbackReference end");
    }
    return AVSessionNapiUtils::NapiUndefined(env);
}

napi_value NapiAVSessionManager::Off(napi_env env, napi_callback_info info)
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
    SLOGI("NapiAVSessionManager::Off callbackName: %{public}s", callbackName.c_str());

    NapiAVSessionManager* managerNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&managerNapi));
    if (status != napi_ok || managerNapi == nullptr) {
        SLOGE("napi_unwrap managerNapi error");
    }

    if (managerNapi->sessionListenerCallback_ == nullptr) {
        SLOGI("NapiAVSessionManager::Off no callback ref ");
        return undefinedResult;
    }

    if (!callbackName.compare(SESSIONCREATED_CALLBACK) ||
        !callbackName.compare(SESSIONRELEASED_CALLBACK) ||
        !callbackName.compare(TOPSESSIONCHANGED_CALLBACK) ||
        !callbackName.compare(SESSIONSERVICEDIED_CALLBACK)) {
        std::shared_ptr<NapiSessionListenerCallback> cb =
            std::static_pointer_cast<NapiSessionListenerCallback>(managerNapi->sessionListenerCallback_);
        cb->ReleaseCallbackReference(callbackName);
    }

    return AVSessionNapiUtils::NapiUndefined(env);
}

void GetKeyEvent(const napi_env& env, const napi_value& object, ManagerAsyncContext* asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_object) {
        napi_status status = napi_unwrap(env, object, reinterpret_cast<void**>(&asyncContext->keyEvent));
        if (status != napi_ok || asyncContext->keyEvent == nullptr) {
            SLOGE("napi_unwrap asyncContext->keyEvent error");
        }
    }
}

napi_value NapiAVSessionManager::SendSystemAVKeyEvent(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<ManagerAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<ManagerAsyncContext>::InputParser> parsers;
    parsers.push_back(GetKeyEvent);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "SendSystemAVKeyEvent",
        [](ManagerAsyncContext* asyncContext) {
            return OK;
        },
        [](ManagerAsyncContext* asyncContext, napi_value& output) {
            int32_t ret = AVSessionManager::SendSystemAVKeyEvent(*(asyncContext->keyEvent.get()));
            if (ret) {
                SLOGE("native SendSystemAVKeyEvent Failed");
                return ERR;
            }
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}

void GetArgvAVControlCommand(const napi_env& env, const napi_value& object, ManagerAsyncContext* asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_object) {
        std::string strCommand = AVSessionNapiUtils::GetValueString(env,"command", object);
        if (strCommand.empty()) {
            SLOGE("SendSystemControlCommand:: get param command  fail ");
            return ;
        }
        int32_t command = AVControlCommand::SESSION_CMD_MAX;
        if (aVControlCommandMap.find(strCommand) != aVControlCommandMap.end()) {
            command = aVControlCommandMap[strCommand];
            asyncContext->aVControlCommand = make_shared<AVControlCommand>();
            asyncContext->aVControlCommand->SetCommand(command);

            napi_value res = nullptr;
            if (napi_get_named_property(env, object, "parameter", &res) == napi_ok) {
                napi_typeof(env, res, &valueType);
                if (valueType == napi_number && command == AVControlCommand::SESSION_CMD_SEEK) {
                    int64_t time = 0;
                    napi_get_value_int64(env, res, &time);
                    asyncContext->aVControlCommand->SetSeekTime(time);
                }
                if (valueType == napi_number && command == AVControlCommand::SESSION_CMD_SET_SPEED) {
                    double speed = 0;
                    napi_get_value_double(env, res, &speed);
                    asyncContext->aVControlCommand->SetSpeed((float)speed);
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
        }
    }
}

napi_value NapiAVSessionManager::SendSystemControlCommand(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<ManagerAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<ManagerAsyncContext>::InputParser> parsers;
    parsers.push_back(GetArgvAVControlCommand);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "SendSystemControlCommand",
        [](ManagerAsyncContext* asyncContext) {
            return OK;
        },
        [](ManagerAsyncContext* asyncContext, napi_value& output) {
            SLOGI(" NapiAVSession::SendSystemControlCommand() async");
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            int32_t ret = AVSessionManager::SendSystemControlCommand(*asyncContext->aVControlCommand);
            if (ret) {
                SLOGE(" native SendSystemControlCommand fail ");
                return ERR;
            }
            return OK;
        });
}

void GetArgvSession(const napi_env& env, const napi_value& object, ManagerAsyncContext* asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);

    if (valueType == napi_object) {
        asyncContext->sessionId = AVSessionNapiUtils::GetValueInt32(env, "sessionId", object);
        asyncContext->pid = AVSessionNapiUtils::GetValueInt32(env, "pid", object);
        asyncContext->uid = AVSessionNapiUtils::GetValueInt32(env, "uid", object);
    } else if (valueType == napi_string) {
        std::string session = AVSessionNapiUtils::GetValueString(env, "session", object);
        if (session.empty()) {
            SLOGI("GetArgvSession:: get param fail ");
        } else if (!session.compare("all")) {
            asyncContext->session = session;
        }
    }
}

void GetArgvAudioDevices(const napi_env& env, const napi_value& object, ManagerAsyncContext* asyncContext)
{
    bool present = false;
    bool isArray = false;
    uint32_t len = 0;
    AudioDeviceDescriptor descriptor;

    napi_value property = nullptr;
    napi_value deviceDescriptorItem = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);

    if (valueType == napi_object) {
        napi_has_named_property(env, object, "audioDevices", &present);
        if (present && napi_get_named_property(env, object, "audioDevices", &property) == napi_ok &&
            napi_is_array(env, property, &isArray) == napi_ok && isArray) {
            napi_get_array_length(env, property, &len);
            for (size_t i = 0; i < len; i++) {
                napi_get_element(env, property, i, &deviceDescriptorItem);

                valueType = napi_undefined;
                napi_typeof(env, deviceDescriptorItem, &valueType);
                if (valueType == napi_object) {
                    descriptor.deviceRole = AVSessionNapiUtils::GetValueInt32(env, "deviceRole", deviceDescriptorItem);
                    descriptor.deviceType = AVSessionNapiUtils::GetValueInt32(env, "deviceType",deviceDescriptorItem);
                    asyncContext->audioDeviceDescriptors.push_back(descriptor);
                }
            }
        } else {
            SLOGE("GetArgvAudioDevices:: get param fail ");
        }
    }
}

napi_value NapiAVSessionManager::CastAudio(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<ManagerAsyncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<ManagerAsyncContext>::InputParser> parsers;
    parsers.push_back(GetArgvSession);
    parsers.push_back(GetArgvAudioDevices);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "CastAudio",
        [](ManagerAsyncContext* asyncContext) {
            SLOGE("No local CastAudio methods .");
            return ERR;
        },
        [](ManagerAsyncContext* asyncContext, napi_value& output) {
            output = AVSessionNapiUtils::WrapVoidToJS(asyncContext->env);
            return OK;
        });
}
} // namespace OHOS