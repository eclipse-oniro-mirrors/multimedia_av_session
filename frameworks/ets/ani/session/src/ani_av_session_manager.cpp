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
#include "ani_av_session_manager.h"
#include "ani.h"
#include "avsession_errors.h"

using namespace std;

namespace OHOS::AVSession {
std::map<int32_t, int32_t> AVSessionManagerAni::errcode_ = {
    {AVSESSION_ERROR, 6600101},
    {ERR_NO_MEMORY, 6600101},
    {ERR_SERVICE_NOT_EXIST, 6600101},
    {ERR_SESSION_LISTENER_EXIST, 6600101},
    {ERR_MARSHALLING, 6600101},
    {ERR_UNMARSHALLING, 6600101},
    {ERR_IPC_SEND_REQUEST, 6600101},
    {ERR_CONTROLLER_IS_EXIST, 6600101},
    {ERR_START_ABILITY_IS_RUNNING, 6600101},
    {ERR_ABILITY_NOT_AVAILABLE, 6600101},
    {ERR_START_ABILITY_TIMEOUT, 6600101},
    {ERR_SESSION_NOT_EXIST, 6600102},
    {ERR_CONTROLLER_NOT_EXIST, 6600103},
    {ERR_RPC_SEND_REQUEST, 6600104},
    {ERR_COMMAND_NOT_SUPPORT, 6600105},
    {ERR_SESSION_DEACTIVE, 6600106},
    {ERR_COMMAND_SEND_EXCEED_MAX, 6600107},
    {ERR_DEVICE_CONNECTION_FAILED, 6600108},
    {ERR_REMOTE_CONNECTION_NOT_EXIST, 6600109},
    {ERR_SESSION_IS_EXIST, 6600101},
    {ERR_PERMISSION_DENIED, 201},
    {ERR_NO_PERMISSION, 202},
    {ERR_INVALID_PARAM, 401},
};

std::shared_ptr<AVSessionAni> aniSession = nullptr;

ani_status NewInstanceMork(ani_env *env, ani_object object,
    std::shared_ptr<AVSession> session, std::string tag, AppExecFwk::ElementName elementName)
{
    ani_status status = AVSessionAni::NewInstance(env, object, session, aniSession);
    if (aniSession) {
        SLOGI("NewInstance aniSession");
        aniSession->SetSessionTag(tag);
        aniSession->SetSessionElement(elementName);
    }
    return status;
}

ani_object AVSessionManagerAni::CreateAVSession(ani_env *env, ani_object object,
    ani_object createAVSessioncontext, ani_string tag, ani_string type)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerAni::CreateAVSession");
    struct ConcreteContext : public ContextBase {
        std::string tag_;
        int32_t type_{};
        AppExecFwk::ElementName elementName_;
        std::shared_ptr<AVSession> session_;
    };
    auto context = std::make_shared<ConcreteContext>();

    context->status = AniUtils::GetValue(env, createAVSessioncontext, context->elementName_);
    if (context->status != ANI_OK) {
        return (ani_object)AVSessionAni::ThrowErrorAndReturn(env, "invalid context", ERR_INVALID_PARAM);
    }

    context->status = AniUtils::GetString(env, tag, context->tag_);
    if (context->status != ANI_OK || context->tag_.empty()) {
        return (ani_object)AVSessionAni::ThrowErrorAndReturn(env, "invalid tag", ERR_INVALID_PARAM);
    }

    std::string typeStr;
    context->status = AniUtils::GetString(env, type, typeStr);
    if (context->status != ANI_OK && typeStr.empty()) {
        return (ani_object)AVSessionAni::ThrowErrorAndReturn(env, "invalid type", ERR_INVALID_PARAM);
    }

    context->type_ = AniUtils::ConvertSessionType(typeStr);
    if (context->type_ < 0) {
        return (ani_object)AVSessionAni::ThrowErrorAndReturn(env, "wrong session type", ERR_INVALID_PARAM);
    }

    context->native = AVSessionAni::Unwrap(env, object);

    auto res = AVSessionManager::GetInstance().RegisterServiceStartCallback(AVSessionManagerAni::HandleServiceStart);
    SLOGI("RegisterServiceStartCallback res=%{public}d", res);

    int32_t ret = AVSessionManager::GetInstance().CreateSession(context->tag_,
        context->type_, context->elementName_, context->session_);
    if (ret != AVSESSION_SUCCESS) {
        if (ret == ERR_SESSION_IS_EXIST) {
            context->errMessage = "CreateAVSession failed : session is existed";
        } else {
            context->errMessage = "CreateAVSession failed : native create session failed";
        }
        AniUtils::ThrowError(env, context->errMessage.c_str(), AVSessionManagerAni::errcode_[ret]);
        return (ani_object)AniUtils::GetUndefinedValue(env);
    }

    context->status = NewInstanceMork(env, object, context->session_, context->tag_, context->elementName_);
    if (context->status != ANI_OK) {
        return (ani_object)AVSessionAni::ThrowErrorAndReturn(env,
            "convert native object to javascript object failed", ERR_INVALID_PARAM);
    }

    return object;
}

void AVSessionManagerAni::HandleServiceStart()
{
    SLOGI("HandleServiceStart enter");
    if (aniSession) {
        std::shared_ptr<AVSession> session;
        int32_t ret = AVSessionManager::GetInstance().CreateSession(aniSession->GetSessionTag(),
            AniUtils::ConvertSessionType(aniSession->GetSessionType()),
            aniSession->GetSessionElement(), session);
        SLOGI("HandleServiceStart CreateSession ret=%{public}d", ret);
        if (ret == AVSESSION_SUCCESS) {
            auto res = AVSessionAni::ReCreateInstance(session);
            SLOGI("HandleServiceStart ReCreateInstance ret=%{public}d", res);
        }
    }
}
} // namespace OHOS::AVSession
