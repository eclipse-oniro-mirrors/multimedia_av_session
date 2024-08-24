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

#include <cstdio>

#include "napi_avsession.h"
#include "avsession_controller.h"
#include "napi_async_work.h"
#include "napi_utils.h"
#include "napi_avcall_meta_data.h"
#include "napi_avcall_state.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_media_description.h"
#include "napi_queue_item.h"
#include "want_params.h"
#include "want_agent.h"
#include "avsession_trace.h"
#include "napi_avsession_controller.h"
#include "napi_avsession_manager.h"
#include "curl/curl.h"
#include "image_source.h"
#include "pixel_map.h"
#include "avsession_pixel_map_adapter.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "avcast_controller.h"
#include "napi_avcast_controller.h"
#endif
namespace OHOS::AVSession {

static __thread napi_ref AVSessionConstructorRef = nullptr;
std::map<std::string, NapiAVSession::OnEventHandlerType> NapiAVSession::onEventHandlers_ = {
    { "play", OnPlay },
    { "pause", OnPause },
    { "stop", OnStop },
    { "playNext", OnPlayNext },
    { "playPrevious", OnPlayPrevious },
    { "fastForward", OnFastForward },
    { "rewind", OnRewind },
    { "seek", OnSeek },
    { "setSpeed", OnSetSpeed },
    { "setLoopMode", OnSetLoopMode },
    { "toggleFavorite", OnToggleFavorite },
    { "handleKeyEvent", OnMediaKeyEvent },
    { "outputDeviceChange", OnOutputDeviceChange },
    { "commonCommand", OnCommonCommand },
    { "skipToQueueItem", OnSkipToQueueItem },
    { "answer", OnAVCallAnswer },
    { "hangUp", OnAVCallHangUp },
    { "toggleCallMute", OnAVCallToggleCallMute },
    { "playFromAssetId", OnPlayFromAssetId },
    { "castDisplayChange", OnCastDisplayChange },
};
std::map<std::string, NapiAVSession::OffEventHandlerType> NapiAVSession::offEventHandlers_ = {
    { "play", OffPlay },
    { "pause", OffPause },
    { "stop", OffStop },
    { "playNext", OffPlayNext },
    { "playPrevious", OffPlayPrevious },
    { "fastForward", OffFastForward },
    { "rewind", OffRewind },
    { "seek", OffSeek },
    { "setSpeed", OffSetSpeed },
    { "setLoopMode", OffSetLoopMode },
    { "toggleFavorite", OffToggleFavorite },
    { "handleKeyEvent", OffMediaKeyEvent },
    { "outputDeviceChange", OffOutputDeviceChange },
    { "commonCommand", OffCommonCommand },
    { "skipToQueueItem", OffSkipToQueueItem },
    { "answer", OffAVCallAnswer },
    { "hangUp", OffAVCallHangUp },
    { "toggleCallMute", OffAVCallToggleCallMute },
    { "playFromAssetId", OffPlayFromAssetId },
    { "castDisplayChange", OffCastDisplayChange },
};

NapiAVSession::NapiAVSession()
{
    SLOGI("construct");
}

NapiAVSession::~NapiAVSession()
{
    SLOGI("destroy");
}

napi_value NapiAVSession::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("setAVMetadata", SetAVMetaData),
        DECLARE_NAPI_FUNCTION("setCallMetadata", SetAVCallMetaData),
        DECLARE_NAPI_FUNCTION("setAVPlaybackState", SetAVPlaybackState),
        DECLARE_NAPI_FUNCTION("setAVCallState", SetAVCallState),
        DECLARE_NAPI_FUNCTION("setLaunchAbility", SetLaunchAbility),
        DECLARE_NAPI_FUNCTION("setExtras", SetExtras),
        DECLARE_NAPI_FUNCTION("setAudioStreamId", SetAudioStreamId),
        DECLARE_NAPI_FUNCTION("getController", GetController),
        DECLARE_NAPI_FUNCTION("activate", Activate),
        DECLARE_NAPI_FUNCTION("deactivate", Deactivate),
        DECLARE_NAPI_FUNCTION("destroy", Destroy),
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
        DECLARE_NAPI_FUNCTION("getOutputDevice", GetOutputDevice),
        DECLARE_NAPI_FUNCTION("getOutputDeviceSync", GetOutputDeviceSync),
        DECLARE_NAPI_FUNCTION("dispatchSessionEvent", SetSessionEvent),
        DECLARE_NAPI_FUNCTION("setAVQueueItems", SetAVQueueItems),
        DECLARE_NAPI_FUNCTION("setAVQueueTitle", SetAVQueueTitle),
        DECLARE_NAPI_FUNCTION("getAVCastController", GetAVCastController),
        DECLARE_NAPI_FUNCTION("stopCasting", ReleaseCast),
        DECLARE_NAPI_FUNCTION("getAllCastDisplays", GetAllCastDisplays),
    };
    auto propertyCount = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor {};
    auto status = napi_define_class(env, "AVSession", NAPI_AUTO_LENGTH, ConstructorCallback, nullptr,
                                    propertyCount, descriptors, &constructor);
    if (status != napi_ok) {
        SLOGE("define class failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_create_reference(env, constructor, 1, &AVSessionConstructorRef);
    return exports;
}

napi_value NapiAVSession::ConstructorCallback(napi_env env, napi_callback_info info)
{
    napi_value self;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr), nullptr);
    auto finalize = [](napi_env env, void* data, void* hint) {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(data);
        napi_delete_reference(env, napiSession->wrapperRef_);
        delete napiSession;
        napiSession = nullptr;
    };
    auto* napiSession = new(std::nothrow) NapiAVSession();
    if (napiSession == nullptr) {
        SLOGE("no memory");
        return nullptr;
    }
    if (napi_wrap(env, self, static_cast<void*>(napiSession), finalize, nullptr, nullptr) != napi_ok) {
        SLOGE("wrap failed");
        return nullptr;
    }
    return self;
}

napi_status NapiAVSession::NewInstance(napi_env env, std::shared_ptr<AVSession>& nativeSession, napi_value& out)
{
    napi_value constructor {};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, AVSessionConstructorRef, &constructor), napi_generic_failure);
    napi_value instance{};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);
    NapiAVSession* napiAvSession{};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&napiAvSession)), napi_generic_failure);
    napiAvSession->session_ = std::move(nativeSession);
    napiAvSession->sessionId_ = napiAvSession->session_->GetSessionId();
    napiAvSession->sessionType_ = napiAvSession->session_->GetSessionType();
    SLOGI("sessionId=%{public}s, sessionType:%{public}s", napiAvSession->sessionId_.c_str(),
        napiAvSession->sessionType_.c_str());

    napi_value property {};
    auto status = NapiUtils::SetValue(env, napiAvSession->sessionId_, property);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    NAPI_CALL_BASE(env, napi_set_named_property(env, instance, "sessionId", property), napi_generic_failure);

    status = NapiUtils::SetValue(env, napiAvSession->sessionType_, property);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    NAPI_CALL_BASE(env, napi_set_named_property(env, instance, "sessionType", property), napi_generic_failure);
    out = instance;
    return napi_ok;
}

napi_value NapiAVSession::OnEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        return ThrowErrorAndReturn(env, "OnEvent failed : no memory", ERR_NO_MEMORY);
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
    auto it = onEventHandlers_.find(eventName);
    if (it == onEventHandlers_.end()) {
        SLOGE("event name invalid");
        return ThrowErrorAndReturn(env, "event name invalid", ERR_INVALID_PARAM);
    }
    auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
    if (napiSession->session_ == nullptr) {
        SLOGE("OnEvent failed : session is nullptr");
        return ThrowErrorAndReturn(env, "OnEvent failed : session is nullptr", ERR_SESSION_NOT_EXIST);
    }
    if (napiSession->callback_ == nullptr) {
        napiSession->callback_ = std::make_shared<NapiAVSessionCallback>();
        if (napiSession->callback_ == nullptr) {
            SLOGE("OnEvent failed : no memory");
            return ThrowErrorAndReturn(env, "OnEvent failed : no memory", ERR_NO_MEMORY);
        }
        int32_t ret = napiSession->session_->RegisterCallback(napiSession->callback_);
        if (ret != AVSESSION_SUCCESS) {
            return ThrowErrorAndReturnByErrCode(env, "OnEvent", ret);
        }
    }
    if (it->second(env, napiSession, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSession::ThrowErrorAndReturn(napi_env env, const std::string& message, int32_t errCode)
{
    std::string tempMessage = message;
    NapiUtils::ThrowError(env, tempMessage.c_str(), NapiAVSessionManager::errcode_[errCode]);
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSession::ThrowErrorAndReturnByErrCode(napi_env env, const std::string& message, int32_t errCode)
{
    std::string tempMessage = message;
    if (errCode == ERR_SESSION_NOT_EXIST) {
        tempMessage.append(" failed : native session not exist");
    } else if (errCode == ERR_INVALID_PARAM) {
        tempMessage.append(" failed : native invalid parameters");
    } else if (errCode == ERR_NO_PERMISSION) {
        tempMessage.append(" failed : native no permission");
    } else {
        tempMessage.append(" failed : native server exception");
    }
    SLOGI("throw error message: %{public}s", tempMessage.c_str());
    NapiUtils::ThrowError(env, tempMessage.c_str(), NapiAVSessionManager::errcode_[errCode]);
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSession::OffEvent(napi_env env, napi_callback_info info)
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
    auto it = offEventHandlers_.find(eventName);
    if (it == offEventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
    if (napiSession == nullptr) {
        SLOGE("OffEvent failed : napiSession is nullptr");
        NapiUtils::ThrowError(env, "OffEvent failed : napiSession is nullptr",
            NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    if (napiSession->session_ == nullptr) {
        SLOGE("OffEvent failed : session is nullptr");
        NapiUtils::ThrowError(env, "OffEvent failed : session is nullptr",
            NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST]);
        return NapiUtils::GetUndefinedValue(env);
    }
    if (napiSession != nullptr && it->second(env, napiSession, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSession::SetAVCallMetaData(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVCallMetadata");
    struct ConcreteContext : public ContextBase {
        AVCallMetaData avCallMetaData;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAVCallMetaData failed : no memory");
        NapiUtils::ThrowError(env, "SetAVCallMetaData failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiAVCallMetaData::GetValue(env, argv[ARGV_FIRST], context->avCallMetaData);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get av call meta data failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AVCALL_META_DATA_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVCallMetaData failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVCallMetaData(context->avCallMetaData);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVCallMetaData failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVCallMetaData failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVCallMetaData failed : native no permission";
            } else {
                context->errMessage = "SetAVCallMetaData failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVCallMetaData", executor, complete);
}

napi_value NapiAVSession::SetAVCallState(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVCallState");
    struct ConcreteContext : public ContextBase {
        AVCallState avCallState;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAVCallState failed : no memory");
        NapiUtils::ThrowError(env, "SetAVCallState failed : no memory",
                              NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiAVCallState::GetValue(env, argv[ARGV_FIRST], context->avCallState);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get avCallState failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_CALL_STATE_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVCallState failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVCallState(context->avCallState);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVCallState failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVCallState failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVCallState failed : native no permission";
            } else {
                context->errMessage = "SetAVCallState failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVCallState", executor, complete);
}

int32_t DoDownload(AVMetaData& meta, const std::string uri)
{
    SLOGI("DoDownload with title %{public}s", meta.GetTitle().c_str());

    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    bool ret = NapiUtils::DoDownloadInCommon(pixelMap, uri);
    SLOGI("DoDownload with ret %{public}d, %{public}d", static_cast<int>(ret), static_cast<int>(pixelMap == nullptr));
    if (ret && pixelMap != nullptr) {
        SLOGI("DoDownload success");
        meta.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
        return AVSESSION_SUCCESS;
    }
    return AVSESSION_ERROR;
}

void processErrMsg(std::shared_ptr<ContextBase> context, int32_t ret)
{
    if (ret == ERR_SESSION_NOT_EXIST) {
        context->errMessage = "SetAVMetaData failed : native session not exist";
    } else if (ret == ERR_INVALID_PARAM) {
        context->errMessage = "SetAVMetaData failed : native invalid parameters";
    } else if (ret == ERR_NO_PERMISSION) {
        context->errMessage = "SetAVMetaData failed : native no permission";
    } else {
        context->errMessage = "SetAVMetaData failed : native server exception";
    }
    context->status = napi_generic_failure;
    context->errCode = NapiAVSessionManager::errcode_[ret];
}

bool doMetaDataSetNapi(std::shared_ptr<ContextBase> context, std::shared_ptr<AVSession> sessionPtr, AVMetaData& data)
{
    SLOGI("do metadata set with online download prepare with uri alive");
    auto uri = data.GetMediaImageUri();
    int32_t ret = sessionPtr->SetAVMetaData(data);
    if (ret != AVSESSION_SUCCESS) {
        processErrMsg(context, ret);
    } else if (data.GetMediaImage() == nullptr) {
        ret = DoDownload(data, uri);
        SLOGI("DoDownload complete with ret %{public}d", ret);
        CHECK_AND_RETURN_RET_LOG(sessionPtr != nullptr, false, "doMetaDataSet without session");
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("DoDownload failed but not repeat setmetadata again");
        } else {
            return true;
        }
    }
    return false;
}

napi_value NapiAVSession::SetAVMetaData(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVMetadata");
    struct ConcreteContext : public ContextBase {
        AVMetaData metaData;
        std::chrono::system_clock::time_point metadataTs;
    };
    auto context = std::make_shared<ConcreteContext>();
    CHECK_AND_RETURN_RET_LOG(context != nullptr, NapiUtils::GetUndefinedValue(env), "SetAVMetaData failed: no memory");
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiMetaData::GetValue(env, argv[ARGV_FIRST], context->metaData);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get metaData failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);

    auto* napiAvSession = reinterpret_cast<NapiAVSession*>(context->native);
    CHECK_AND_RETURN_RET_LOG(napiAvSession != nullptr, NapiUtils::GetUndefinedValue(env), "napiAvSession is nullptr");
    if (napiAvSession->metaData_.EqualWithUri((context->metaData))) {
        SLOGI("metadata with uri is the same as last time");
        auto executor = []() {};
        auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };
        return NapiAsyncWork::Enqueue(env, context, "SetAVMetaData", executor, complete);
    }
    napiAvSession->metaData_ = context->metaData;
    context->taskId = NAPI_SET_AV_META_DATA_TASK_ID;
    context->metadataTs = std::chrono::system_clock::now();
    reinterpret_cast<NapiAVSession*>(context->native)->latestMetadataTs_ = context->metadataTs;
    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVMetaData failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            context->metaData.Reset();
            return;
        }
        bool res = doMetaDataSetNapi(context, napiSession->session_, context->metaData);
        bool timeAvailable = context->metadataTs >= napiSession->latestMetadataTs_;
        SLOGI("doMetaDataSet res:%{public}d, time:%{public}d", static_cast<int>(res), static_cast<int>(timeAvailable));
        if (res && timeAvailable && napiSession->session_ != nullptr) {
            napiSession->session_->SetAVMetaData(context->metaData);
        }
        context->metaData.Reset();
    };
    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, context, "SetAVMetaData", executor, complete);
}

napi_value NapiAVSession::SetAVPlaybackState(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVPlaybackState");
    struct ConcreteContext : public ContextBase {
        AVPlaybackState playBackState_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAVPlaybackState failed : no memory");
        NapiUtils::ThrowError(env, "SetAVPlaybackState failed : no memory",
                              NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiPlaybackState::GetValue(env, argv[ARGV_FIRST], context->playBackState_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get playBackState failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_PLAYBACK_STATE_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVPlaybackState failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVPlaybackState(context->playBackState_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVPlaybackState failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVPlaybackState failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVPlaybackState failed : native no permission";
            } else {
                context->errMessage = "SetAVPlaybackState failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVPlaybackState", executor, complete);
}

napi_value NapiAVSession::SetAVQueueItems(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVQueueItems");
    struct ConcreteContext : public ContextBase { std::vector<AVQueueItem> items_; };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        NapiUtils::ThrowError(env, "SetAVQueueItems failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->items_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get queueItems failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        for (auto &item : context->items_) {
            CHECK_ARGS_RETURN_VOID(context, item.IsValid(), "invalid queue item content",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        }
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_QUEUE_ITEMS_TASK_ID;
    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVQueueItems failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVQueueItems(context->items_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVQueueItems failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVQueueItems failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVQueueItems failed : native no permission";
            } else if (ret == ERR_MARSHALLING) {
                context->errMessage = "SetAVQueueItems failed : item number is out of range";
            } else {
                context->errMessage = "SetAVQueueItems failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, context, "SetAVQueueItems", executor, complete);
}

napi_value NapiAVSession::SetAVQueueTitle(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetAVQueueTitle");
    struct ConcreteContext : public ContextBase {
        std::string title;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAVQueueTitle failed : no memory");
        NapiUtils::ThrowError(env, "SetAVQueueTitle failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->title);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get queueItems failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_QUEUE_TITLE_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAVQueueTitle failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetAVQueueTitle(context->title);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetAVQueueTitle failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetAVQueueTitle failed : native invalid parameters";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetAVQueueTitle failed : native no permission";
            } else {
                context->errMessage = "SetAVQueueTitle failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAVQueueTitle", executor, complete);
}

napi_value NapiAVSession::SetLaunchAbility(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AbilityRuntime::WantAgent::WantAgent* wantAgent_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetLaunchAbility failed : no memory");
        NapiUtils::ThrowError(env, "SetLaunchAbility failed : no memory",
                              NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->wantAgent_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get  wantAgent failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetLaunchAbility failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetLaunchAbility(*context->wantAgent_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetLaunchAbility failed : native session not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetLaunchAbility failed : native no permission";
            } else {
                context->errMessage = "SetLaunchAbility failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetLaunchAbility", executor, complete);
}

napi_value NapiAVSession::SetExtras(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetExtras");
    struct ConcreteContext : public ContextBase {
        AAFwk::WantParams extras_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetExtras failed : no memory");
        NapiUtils::ThrowError(env, "SetExtras failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->extras_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get extras failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_EXTRAS_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetExtras failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetExtras(context->extras_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetExtras failed : native session not exist";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetExtras failed : native invalid parameters";
            } else {
                context->errMessage = "SetExtras failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetExtras", executor, complete);
}

napi_value NapiAVSession::SetAudioStreamId(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<int32_t> streamIds_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetAudioStreamId failed : no memory");
        NapiUtils::ThrowError(env, "SetAudioStreamId failed : no memory",
                              NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->streamIds_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get streamIds_ failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetAudioStreamId failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetAudioStreamId", executor, complete);
}

napi_value NapiAVSession::GetController(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::shared_ptr<AVSessionController> controller_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("GetController failed : no memory");
        NapiUtils::ThrowError(env, "GetController failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetController failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        context->controller_ = napiSession->session_->GetController();
        if (context->controller_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetController failed : native get controller failed";
            context->errCode = NapiAVSessionManager::errcode_[AVSESSION_ERROR];
        }
    };
    auto complete = [env, context](napi_value& output) {
        CHECK_STATUS_RETURN_VOID(context, "get controller failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        CHECK_ARGS_RETURN_VOID(context, context->controller_ != nullptr, "controller is nullptr",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        context->status = NapiAVSessionController::NewInstance(env, context->controller_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to js object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetController", executor, complete);
}

napi_value NapiAVSession::GetAVCastController(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    struct ConcreteContext : public ContextBase {
        std::shared_ptr<AVCastController> castController_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("GetAVCastController failed : no memory");
        NapiUtils::ThrowError(env, "GetAVCastController failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetAVCastController failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        context->castController_ = napiSession->session_->GetAVCastController();
        if (context->castController_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetAVCastController failed : native get controller failed";
            context->errCode = NapiAVSessionManager::errcode_[AVSESSION_ERROR];
        }
    };
    auto complete = [env, context](napi_value& output) {
        CHECK_STATUS_RETURN_VOID(context, "get controller failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        CHECK_ARGS_RETURN_VOID(context, context->castController_ != nullptr, "controller is nullptr",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        context->status = NapiAVCastController::NewInstance(env, context->castController_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to js object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetAVCastController", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSession::GetOutputDevice(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        OutputDeviceInfo outputDeviceInfo_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("GetOutputDevice failed : no memory");
        NapiUtils::ThrowError(env, "GetOutputDevice failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetOutputDevice failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        AVSessionDescriptor descriptor;
        AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(napiSession->session_->GetSessionId(),
                                                                         descriptor);
        context->outputDeviceInfo_ = descriptor.outputDeviceInfo_;
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->outputDeviceInfo_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetOutputDevice", executor, complete);
}

napi_value NapiAVSession::GetOutputDeviceSync(napi_env env, napi_callback_info info)
{
    SLOGD("Start GetOutputDeviceSync");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("GetOutputDeviceSync failed : no memory");
        NapiUtils::ThrowError(env, "GetOutputDeviceSync failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info, NapiCbInfoParser(), true);

    auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
    if (napiSession->session_ == nullptr) {
        context->status = napi_generic_failure;
        context->errMessage = "GetOutputDeviceSync failed : session is nullptr";
        context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
        return NapiUtils::GetUndefinedValue(env);
    }

    AVSessionDescriptor descriptor;
    AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(napiSession->session_->GetSessionId(),
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

napi_value NapiAVSession::Activate(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Activate failed : no memory");
        NapiUtils::ThrowError(env, "Activate failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "Activate session failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->Activate();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "Activate session failed : native session not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "Activate failed : native no permission";
            } else {
                context->errMessage = "Activate session failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Activate", executor, complete);
}

napi_value NapiAVSession::Deactivate(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Deactivate failed : no memory");
        NapiUtils::ThrowError(env, "Deactivate failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "Deactivate session failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->Deactivate();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "Deactivate session failed : native session not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "Deactivate failed : native no permission";
            } else {
                context->errMessage = "Deactivate session failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Deactivate", executor, complete);
}

napi_value NapiAVSession::Destroy(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Destroy failed : no memory");
        NapiUtils::ThrowError(env, "Destroy failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "Destroy session failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->Destroy();
        if (ret == AVSESSION_SUCCESS) {
            napiSession->session_ = nullptr;
            napiSession->callback_ = nullptr;
        } else if (ret == ERR_SESSION_NOT_EXIST) {
            context->status = napi_generic_failure;
            context->errMessage = "Destroy session failed : native session not exist";
            context->errCode = NapiAVSessionManager::errcode_[ret];
        } else if (ret == ERR_NO_PERMISSION) {
            context->status = napi_generic_failure;
            context->errMessage = "Destroy failed : native no permission";
            context->errCode = NapiAVSessionManager::errcode_[ret];
        } else {
            context->status = napi_generic_failure;
            context->errMessage = "Destroy session failed : native server exception";
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Destroy", executor, complete);
}

napi_value NapiAVSession::SetSessionEvent(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSession::SetSessionEvent");
    struct ConcreteContext : public ContextBase {
        std::string event_;
        AAFwk::WantParams args_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("SetSessionEvent failed : no memory");
        NapiUtils::ThrowError(env, "SetSessionEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->event_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get event failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->args_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get args failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_SET_AV_META_DATA_TASK_ID;

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "SetSessionEvent failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->SetSessionEvent(context->event_, context->args_);
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, context->errMessage);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "SetSessionEvent", executor, complete);
}

napi_value NapiAVSession::ReleaseCast(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("ReleaseCast failed : no memory");
        NapiUtils::ThrowError(env, "ReleaseCast failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "ReleaseCast failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->ReleaseCast();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "ReleaseCast failed : native session not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "ReleaseCast failed : native no permission";
            } else {
                context->errMessage = "ReleaseCast failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "ReleaseCast", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSession::GetAllCastDisplays(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    struct ConcreteContext : public ContextBase {
        std::vector<CastDisplayInfo> castDisplays_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("GetAllCastDisplays failed : no memory");
        NapiUtils::ThrowError(env, "GetAllCastDisplays failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);

    auto executor = [context]() {
        auto* napiSession = reinterpret_cast<NapiAVSession*>(context->native);
        if (napiSession->session_ == nullptr) {
            context->status = napi_generic_failure;
            context->errMessage = "GetAllCastDisplays failed : session is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_SESSION_NOT_EXIST];
            return;
        }
        int32_t ret = napiSession->session_->GetAllCastDisplays(context->castDisplays_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAllCastDisplays failed : native session not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAllCastDisplays failed : native no permission";
            } else {
                context->errMessage = "GetAllCastDisplays failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->castDisplays_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetAllCastDisplays", executor, complete);
#else
        return nullptr;
#endif
}

void NapiAVSession::ErrCodeToMessage(int32_t errCode, std::string& message)
{
    switch (errCode) {
        case ERR_SESSION_NOT_EXIST:
            message = "SetSessionEvent failed : native session not exist";
            break;
        case ERR_INVALID_PARAM:
            message = "SetSessionEvent failed : native invalid parameters";
            break;
        case ERR_NO_PERMISSION:
            message = "SetSessionEvent failed : native no permission";
            break;
        default:
            message = "SetSessionEvent failed : native server exception";
            break;
    }
}

napi_status NapiAVSession::OnPlay(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY, callback);
}

napi_status NapiAVSession::OnPause(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PAUSE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PAUSE, callback);
}

napi_status NapiAVSession::OnStop(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_STOP);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_STOP, callback);
}

napi_status NapiAVSession::OnPlayNext(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY_NEXT, callback);
}

napi_status NapiAVSession::OnPlayPrevious(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY_PREVIOUS, callback);
}

napi_status NapiAVSession::OnFastForward(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_FAST_FORWARD);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_FAST_FORWARD, callback);
}

napi_status NapiAVSession::OnRewind(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_REWIND);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_REWIND, callback);
}

napi_status NapiAVSession::OnSeek(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SEEK);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SEEK, callback);
}

napi_status NapiAVSession::OnSetSpeed(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_SPEED);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SET_SPEED, callback);
}

napi_status NapiAVSession::OnSetLoopMode(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SET_LOOP_MODE, callback);
}

napi_status NapiAVSession::OnToggleFavorite(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_TOGGLE_FAVORITE, callback);
}

napi_status NapiAVSession::OnMediaKeyEvent(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT);
    SLOGI("add media key event listen ret %{public}d", static_cast<int>(ret));
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_MEDIA_KEY_EVENT, callback);
}

napi_status NapiAVSession::OnOutputDeviceChange(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_OUTPUT_DEVICE_CHANGE, callback);
}

napi_status NapiAVSession::OnCommonCommand(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SEND_COMMON_COMMAND, callback);
}

napi_status NapiAVSession::OnSkipToQueueItem(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_SKIP_TO_QUEUE_ITEM, callback);
}

napi_status NapiAVSession::OnAVCallAnswer(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_AVCALL_ANSWER);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_AVCALL_ANSWER, callback);
}

napi_status NapiAVSession::OnAVCallHangUp(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_AVCALL_HANG_UP);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_AVCALL_HANG_UP, callback);
}

napi_status NapiAVSession::OnAVCallToggleCallMute(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_AVCALL_TOGGLE_CALL_MUTE, callback);
}

napi_status NapiAVSession::OnPlayFromAssetId(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    int32_t ret = napiSession->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add command failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_PLAY_FROM_ASSETID, callback);
}

napi_status NapiAVSession::OnCastDisplayChange(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
                             "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->AddCallback(env, NapiAVSessionCallback::EVENT_DISPLAY_CHANGE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "AddCallback failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->session_ != nullptr, napi_generic_failure,
                             "NapiAVSession object is nullptr");
    napiSession->session_->StartCastDisplayListener();
#else
    return napi_generic_failure;
#endif
    return napi_ok;
}

napi_status NapiAVSession::OffPlay(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PLAY, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PLAY)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PLAY);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffPause(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PAUSE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PAUSE)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PAUSE);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffStop(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_STOP, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_STOP)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_STOP);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffPlayNext(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PLAY_NEXT, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PLAY_NEXT)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffPlayPrevious(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PLAY_PREVIOUS, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");

    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PLAY_PREVIOUS)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffFastForward(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_FAST_FORWARD, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_FAST_FORWARD)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_FAST_FORWARD);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffRewind(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_REWIND, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_REWIND)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_REWIND);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffSeek(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SEEK, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_SEEK)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_SEEK);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffSetSpeed(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SET_SPEED, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_SET_SPEED)) {
        CHECK_AND_RETURN_RET_LOG(napiSession->session_ != nullptr, napi_generic_failure,
            "NapiAVSession_session is nullptr");
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_SET_SPEED);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffSetLoopMode(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SET_LOOP_MODE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_SET_LOOP_MODE)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffToggleFavorite(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_TOGGLE_FAVORITE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_TOGGLE_FAVORITE)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffMediaKeyEvent(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_MEDIA_KEY_EVENT, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_MEDIA_KEY_EVENT)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffOutputDeviceChange(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_OUTPUT_DEVICE_CHANGE, callback);
}

napi_status NapiAVSession::OffCommonCommand(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SEND_COMMON_COMMAND, callback);
}

napi_status NapiAVSession::OffSkipToQueueItem(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_SKIP_TO_QUEUE_ITEM, callback);
}

napi_status NapiAVSession::OffAVCallAnswer(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_AVCALL_ANSWER, callback);
}

napi_status NapiAVSession::OffAVCallHangUp(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_AVCALL_HANG_UP, callback);
}

napi_status NapiAVSession::OffAVCallToggleCallMute(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    return napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_AVCALL_TOGGLE_CALL_MUTE, callback);
}

napi_status NapiAVSession::OffPlayFromAssetId(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
        "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_PLAY_FROM_ASSETID, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");

    if (napiSession->callback_->IsCallbacksEmpty(NapiAVSessionCallback::EVENT_PLAY_FROM_ASSETID)) {
        int32_t ret = napiSession->session_->DeleteSupportCommand(AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "delete cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVSession::OffCastDisplayChange(napi_env env, NapiAVSession* napiSession, napi_value callback)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CHECK_AND_RETURN_RET_LOG(napiSession->callback_ != nullptr, napi_generic_failure,
                             "NapiAVSessionCallback object is nullptr");
    auto status = napiSession->callback_->RemoveCallback(env, NapiAVSessionCallback::EVENT_DISPLAY_CHANGE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    CHECK_AND_RETURN_RET_LOG(napiSession->session_ != nullptr, napi_generic_failure,
                             "NapiAVSession object is nullptr");
    napiSession->session_->StopCastDisplayListener();
#else
    return napi_generic_failure;
#endif
    return napi_ok;
}
}
