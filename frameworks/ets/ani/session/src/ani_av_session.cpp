/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ani_av_session.h"
#include "ani.h"
#include "avsession_trace.h"
#include "ani_class_name.h"

using namespace std;

namespace OHOS::AVSession {
std::map<std::string, AVSessionAni::OnEventHandlerType> AVSessionAni::onEventHandlers_ = {
    { "play", OnPlay },
    { "pause", OnPause },
    { "stop", OnStop },
    { "playNext", OnPlayNext },
    { "playPrevious", OnPlayPrevious },
    { "fastForward", OnFastForward },
    { "rewind", OnRewind },
    { "seek", OnSeek },
    { "setSpeed", OnSetSpeed },
    { "toggleFavorite", OnToggleFavorite },
    { "skipToQueueItem", OnSkipToQueueItem },
    { "answer", OnAVCallAnswer },
    { "hangUp", OnAVCallHangUp },
    { "toggleCallMute", OnAVCallToggleCallMute },
    { "playFromAssetId", OnPlayFromAssetId },
    { "castDisplayChange", OnCastDisplayChange },
};

std::list<int32_t> registerEventList_;
std::map<std::string, int32_t> convertEventType_ = {
    { "play", AVControlCommand::SESSION_CMD_PLAY },
    { "pause", AVControlCommand::SESSION_CMD_PAUSE },
    { "stop", AVControlCommand::SESSION_CMD_STOP },
    { "playNext", AVControlCommand::SESSION_CMD_PLAY_NEXT },
    { "playPrevious", AVControlCommand::SESSION_CMD_PLAY_PREVIOUS },
    { "fastForward", AVControlCommand::SESSION_CMD_FAST_FORWARD },
    { "rewind", AVControlCommand::SESSION_CMD_REWIND },
    { "seek", AVControlCommand::SESSION_CMD_SEEK },
    { "setSpeed", AVControlCommand::SESSION_CMD_SET_SPEED },
    { "setLoopMode", AVControlCommand::SESSION_CMD_SET_LOOP_MODE },
    { "toggleFavorite", AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE },
    { "handleKeyEvent", AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT },
    { "playFromAssetId", AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID }
};

std::recursive_mutex registerEventLock_;
std::shared_ptr<AVSessionAni> AVSessionAni::aniAVSession_ = nullptr;

AVSessionAni::AVSessionAni()
{
    SLOGI("construct");
}

AVSessionAni::~AVSessionAni()
{
    SLOGI("destroy");
    std::lock_guard lockGuard(registerEventLock_);
    registerEventList_.clear();
}

ani_status AVSessionAni::AVSessionAniInit(ani_env *env)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    static const char *className = ANI_CLASS_AV_SESSION_HANDLE.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        SLOGE("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"activateInner", nullptr, reinterpret_cast<void *>(AVSessionAni::Activate) },
        ani_native_function {"destroyInner", nullptr, reinterpret_cast<void *>(AVSessionAni::Destroy) },
        ani_native_function {"on", nullptr, reinterpret_cast<void *>(AVSessionAni::OnEvent) },
        ani_native_function {"getAllCastDisplaysInner", nullptr,
            reinterpret_cast<void *>(AVSessionAni::GetAllCastDisplays) },
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        SLOGE("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_object AVSessionAni::Constructor([[maybe_unused]] ani_env *env, ani_object context, ani_string tag, ani_string type)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, nullptr, "env is null");
    ani_object avSession_object = nullptr;
    auto *avSessionAni = new(std::nothrow) AVSessionAni();
    if (avSessionAni == nullptr) {
        SLOGE("no memory");
        return avSession_object;
    }

    static const char *className = ANI_CLASS_AV_SESSION_HANDLE.c_str();
    ani_class cls;

    if (ANI_OK != env->FindClass(className, &cls)) {
        SLOGE("Failed to find class: %{public}s", className);
        return avSession_object;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        SLOGE("Failed to find method: %{public}s", "ctor");
        return avSession_object;
    }

    if (ANI_OK !=env->Object_New(cls, ctor, &avSession_object, reinterpret_cast<ani_long>(avSessionAni))) {
        SLOGE("New AudioManager Fail");
    }

    return AVSessionManagerAni::CreateAVSession(env, avSession_object, context, tag, type);
}

AVSessionAni* AVSessionAni::Unwrap(ani_env *env, ani_object object)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, nullptr, "env is null");
    ani_long avSession;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeAVSession", &avSession)) {
        return nullptr;
    }
    return reinterpret_cast<AVSessionAni*>(avSession);
}

std::string AVSessionAni::GetSessionTag()
{
    return sessionTag_;
}

void AVSessionAni::SetSessionTag(std::string sessionTag)
{
    sessionTag_ = sessionTag;
}

std::string AVSessionAni::GetSessionType()
{
    return sessionType_;
}

AppExecFwk::ElementName AVSessionAni::GetSessionElement()
{
    return elementName_;
}

void AVSessionAni::SetSessionElement(AppExecFwk::ElementName elementName)
{
    elementName_ = elementName;
}

ani_status AVSessionAni::ReCreateInstance(std::shared_ptr<AVSession> nativeSession)
{
    if (aniAVSession_ == nullptr || nativeSession == nullptr) {
        return ANI_ERROR;
    }
    SLOGI("sessionId=%{public}s", aniAVSession_->sessionId_.c_str());
    aniAVSession_->session_ = std::move(nativeSession);
    aniAVSession_->sessionId_ = aniAVSession_->session_->GetSessionId();
    aniAVSession_->sessionType_ = aniAVSession_->session_->GetSessionType();
    if (aniAVSession_->callback_ == nullptr) {
        aniAVSession_->callback_ = std::make_shared<AniAVSessionCallback>();
    }
    int32_t ret = aniAVSession_->session_->RegisterCallback(aniAVSession_->callback_);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("RegisterCallback fail, ret=%{public}d", ret);
    }

    {
        std::lock_guard lockGuard(registerEventLock_);
        for (int32_t event : registerEventList_) {
            int32_t res = aniAVSession_->session_->AddSupportCommand(event);
            if (res != AVSESSION_SUCCESS) {
                SLOGE("AddSupportCommand fail, ret=%{public}d", res);
                continue;
            }
        }
    }

    aniAVSession_->session_->Activate();
    return ANI_OK;
}

ani_status AVSessionAni::NewInstance(ani_env *env, ani_object object,
    std::shared_ptr<AVSession>& nativeSession, std::shared_ptr<AVSessionAni>& aniSession)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    aniAVSession_ = std::shared_ptr<AVSessionAni>(AVSessionAni::Unwrap(env, object));
    CHECK_AND_RETURN_RET_LOG(aniAVSession_ != nullptr, ANI_ERROR, "aniAVSession_ is null");
    aniAVSession_->session_ = std::move(nativeSession);
    aniAVSession_->sessionId_ = aniAVSession_->session_->GetSessionId();
    aniAVSession_->sessionType_ = aniAVSession_->session_->GetSessionType();
    SLOGI("sessionId=%{public}s, sessionType:%{public}s", aniAVSession_->sessionId_.c_str(),
        aniAVSession_->sessionType_.c_str());

    ani_string property;
    ani_status status = AniUtils::ToAniString(env, aniAVSession_->sessionId_, property);
    CHECK_RETURN(status == ANI_OK, "create object failed", ANI_ERROR);
    status = env->Object_SetPropertyByName_Ref(object, "sessionId", property);
    if (status != ANI_OK) {
        SLOGE("Object_SetPropertyByName_Ref failed");
        return status;
    }

    status = AniUtils::ToAniString(env, aniAVSession_->sessionType_, property);
    CHECK_RETURN(status == ANI_OK, "create object failed", ANI_ERROR);
    status = env->Object_SetPropertyByName_Ref(object, "sessionType", property);
    if (status != ANI_OK) {
        SLOGE("Object_SetPropertyByName_Ref failed");
        return status;
    }
    aniSession = aniAVSession_;
    return ANI_OK;
}

void AddRegisterEvent(std::string eventName)
{
    std::lock_guard lockGuard(registerEventLock_);
    registerEventList_.push_back(convertEventType_[eventName]);
}

ani_ref AVSessionAni::OnEvent(ani_env *env, ani_object object, ani_string type, ani_object callbackOn)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, AniUtils::GetUndefinedValue(env), "env is null");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        return ThrowErrorAndReturn(env, "OnEvent failed : no memory", ERR_NO_MEMORY);
    }
    std::string eventName;
    context->status = AniUtils::GetString(env, type, eventName);
    if (context->status != ANI_OK) {
        return (ani_object)ThrowErrorAndReturn(env, "get event name failed", ERR_INVALID_PARAM);
    }

    ani_boolean isUndefined;
    context->status = env->Reference_IsUndefined(callbackOn, &isUndefined);
    if (context->status != ANI_OK) {
        return (ani_object)ThrowErrorAndReturn(env, "get callback failed", ERR_INVALID_PARAM);
    }

    ani_ref cbOnRef {};
    if (!isUndefined) {
        env->GlobalReference_Create(static_cast<ani_ref>(callbackOn), &cbOnRef);
    } else {
        return (ani_object)ThrowErrorAndReturn(env, "GlobalReference_Create failed", ERR_INVALID_PARAM);
    }

    context->native = AVSessionAni::Unwrap(env, object);

    auto it = onEventHandlers_.find(eventName);
    if (it == onEventHandlers_.end()) {
        SLOGE("event name invalid");
        return ThrowErrorAndReturn(env, "event name invalid", ERR_INVALID_PARAM);
    }
    auto *aVSessionAni = reinterpret_cast<AVSessionAni*>(context->native);
    if (aVSessionAni->session_ == nullptr) {
        SLOGE("OnEvent failed : session is nullptr");
        return ThrowErrorAndReturn(env, "OnEvent failed : session is nullptr", ERR_SESSION_NOT_EXIST);
    }
    if (aVSessionAni->callback_ == nullptr) {
        aVSessionAni->callback_ = std::make_shared<AniAVSessionCallback>();
        if (aVSessionAni->callback_ == nullptr) {
            return ThrowErrorAndReturn(env, "OnEvent failed : no memory", ERR_NO_MEMORY);
        }
        int32_t ret = aVSessionAni->session_->RegisterCallback(aVSessionAni->callback_);
        if (ret != AVSESSION_SUCCESS) {
            return ThrowErrorAndReturnByErrCode(env, "OnEvent", ret);
        }
    }
    if (it->second(env, aVSessionAni, cbOnRef) != ANI_OK) {
        AniUtils::ThrowError(env, "add event callback failed", AVSessionManagerAni::errcode_[AVSESSION_ERROR]);
    }
    AddRegisterEvent(eventName);
    return AniUtils::GetUndefinedValue(env);
}

ani_ref AVSessionAni::ThrowErrorAndReturn(ani_env *env, const std::string& message, int32_t errCode)
{
    std::string tempMessage = message;
    AniUtils::ThrowError(env, tempMessage.c_str(), AVSessionManagerAni::errcode_[errCode]);
    return AniUtils::GetUndefinedValue(env);
}

ani_ref AVSessionAni::ThrowErrorAndReturnByErrCode(ani_env *env, const std::string& message, int32_t errCode)
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
    AniUtils::ThrowError(env, tempMessage.c_str(), AVSessionManagerAni::errcode_[errCode]);
    return AniUtils::GetUndefinedValue(env);
}

ani_ref AVSessionAni::Activate(ani_env *env, ani_object object)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Activate failed : no memory");
        AniUtils::ThrowError(env, "Activate failed : no memory", AVSessionManagerAni::errcode_[ERR_NO_MEMORY]);
        return AniUtils::GetUndefinedValue(env);
    }

    context->native = AVSessionAni::Unwrap(env, object);
    auto *aVSessionAni = reinterpret_cast<AVSessionAni*>(context->native);

    if (aVSessionAni->session_ == nullptr) {
        AniUtils::ThrowError(env, "Activate session failed : session is nullptr",
            AVSessionManagerAni::errcode_[ERR_SESSION_NOT_EXIST]);
        return AniUtils::GetUndefinedValue(env);
    }

    int32_t ret = aVSessionAni->session_->Activate();
    if (ret != AVSESSION_SUCCESS) {
        if (ret == ERR_SESSION_NOT_EXIST) {
            context->errMessage = "Activate session failed : native session not exist";
        } else if (ret == ERR_NO_PERMISSION) {
            context->errMessage = "Activate failed : native no permission";
        } else {
            context->errMessage = "Activate session failed : native server exception";
        }
        AniUtils::ThrowError(env, context->errMessage.c_str(), AVSessionManagerAni::errcode_[ret]);
        return AniUtils::GetUndefinedValue(env);
    }
    return AniUtils::GetUndefinedValue(env);
}

ani_ref AVSessionAni::Destroy(ani_env *env, ani_object object)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Destroy failed : no memory");
        AniUtils::ThrowError(env, "Destroy failed : no memory", AVSessionManagerAni::errcode_[ERR_NO_MEMORY]);
        return AniUtils::GetUndefinedValue(env);
    }

    context->native = AVSessionAni::Unwrap(env, object);
    SLOGI("Destroy session begin");
    auto *aVSessionAni = reinterpret_cast<AVSessionAni*>(context->native);

    if (aVSessionAni->session_ == nullptr) {
        AniUtils::ThrowError(env, "Destroy session failed : session is nullptr",
            AVSessionManagerAni::errcode_[ERR_SESSION_NOT_EXIST]);
        return AniUtils::GetUndefinedValue(env);
    }

    int32_t ret = aVSessionAni->session_->Destroy();
    if (ret == AVSESSION_SUCCESS) {
        aVSessionAni->session_ = nullptr;
        aVSessionAni->callback_ = nullptr;
        aniAVSession_ = nullptr;
    } else if (ret == ERR_SESSION_NOT_EXIST) {
        return ThrowErrorAndReturn(env, "Destroy session failed : native session not exist", ret);
    } else if (ret == ERR_NO_PERMISSION) {
        return ThrowErrorAndReturn(env, "Destroy failed : native no permission", ret);
    } else {
        return ThrowErrorAndReturn(env, "Destroy session failed : native server exception", ret);
    }
    return AniUtils::GetUndefinedValue(env);
}

ani_ref AVSessionAni::GetAllCastDisplays(ani_env *env, ani_object object)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    struct ConcreteContext : public ContextBase {
        std::vector<CastDisplayInfo> castDisplays_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("GetAllCastDisplays failed : no memory");
        AniUtils::ThrowError(env, "GetAllCastDisplays failed : no memory",
            AVSessionManagerAni::errcode_[ERR_NO_MEMORY]);
        return AniUtils::GetUndefinedValue(env);
    }

    context->native = AVSessionAni::Unwrap(env, object);
    auto *aVSessionAni = reinterpret_cast<AVSessionAni*>(context->native);
    if (aVSessionAni->session_ == nullptr) {
        AniUtils::ThrowError(env, "GetAllCastDisplays failed : session is nullptr",
            AVSessionManagerAni::errcode_[ERR_SESSION_NOT_EXIST]);
        return AniUtils::GetUndefinedValue(env);
    }

    int32_t ret = aVSessionAni->session_->GetAllCastDisplays(context->castDisplays_);
    if (ret != AVSESSION_SUCCESS) {
        if (ret == ERR_SESSION_NOT_EXIST) {
            context->errMessage = "GetAllCastDisplays failed : native session not exist";
        } else if (ret == ERR_NO_PERMISSION) {
            context->errMessage = "GetAllCastDisplays failed : native no permission";
        } else {
            context->errMessage = "GetAllCastDisplays failed : native server exception";
        }
        AniUtils::ThrowError(env, context->errMessage.c_str(), AVSessionManagerAni::errcode_[ret]);
        return AniUtils::GetUndefinedValue(env);
    }

    ani_object aniArray;
    context->status = AniUtils::SetValue(env, context->castDisplays_, aniArray);
    if (context->status != ANI_OK) {
        AniUtils::ThrowError(env, "convert native object to javascript object failed",
            AVSessionManagerAni::errcode_[AVSESSION_ERROR]);
        return AniUtils::GetUndefinedValue(env);
    }
    return aniArray;
#else
    SLOGE("GetAllCastDisplays CASTPLUS_CAST_ENGINE_ENABLE is not support");
    return ThrowErrorAndReturn(env, "OnEvent failed : no memory", ERR_NO_MEMORY);
#endif
}

ani_status AVSessionAni::OnPlay(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_PLAY, callback);
}

ani_status AVSessionAni::OnPause(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PAUSE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_PAUSE, callback);
}

ani_status AVSessionAni::OnStop(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_STOP);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_STOP, callback);
}

ani_status AVSessionAni::OnPlayNext(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_PLAY_NEXT, callback);
}

ani_status AVSessionAni::OnPlayPrevious(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_PLAY_PREVIOUS, callback);
}

ani_status AVSessionAni::OnFastForward(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_FAST_FORWARD);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_FAST_FORWARD, callback);
}

ani_status AVSessionAni::OnRewind(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_REWIND);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_REWIND, callback);
}

ani_status AVSessionAni::OnSeek(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SEEK);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_SEEK, callback);
}

ani_status AVSessionAni::OnSetSpeed(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_SPEED);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_SET_SPEED, callback);
}

ani_status AVSessionAni::OnToggleFavorite(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_TOGGLE_FAVORITE, callback);
}

ani_status AVSessionAni::OnSkipToQueueItem(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_SKIP_TO_QUEUE_ITEM, callback);
}

ani_status AVSessionAni::OnAVCallAnswer(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_AVCALL_ANSWER);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_AVCALL_ANSWER, callback);
}

ani_status AVSessionAni::OnAVCallHangUp(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_AVCALL_HANG_UP);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_AVCALL_HANG_UP, callback);
}

ani_status AVSessionAni::OnAVCallToggleCallMute(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR, "session_ is nullptr");
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_AVCALL_TOGGLE_CALL_MUTE, callback);
}

ani_status AVSessionAni::OnPlayFromAssetId(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
    int32_t ret = aVSessionAni->session_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ANI_ERROR, "add command failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
        "AniAVSessionCallback object is nullptr");
    return aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_PLAY_FROM_ASSETID, callback);
}

ani_status AVSessionAni::OnCastDisplayChange(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->callback_ != nullptr, ANI_ERROR,
                             "AniAVSessionCallback object is nullptr");
    auto status = aVSessionAni->callback_->AddCallback(env, AniAVSessionCallback::EVENT_DISPLAY_CHANGE, callback);
    CHECK_AND_RETURN_RET_LOG(status == ANI_OK, status, "AddCallback failed");
    CHECK_AND_RETURN_RET_LOG(aVSessionAni->session_ != nullptr, ANI_ERROR,
                             "AVSessionAni object is nullptr");
    aVSessionAni->session_->StartCastDisplayListener();
#else
    return ANI_ERROR;
#endif
    return ANI_OK;
}
} // namespace OHOS::AVSession
