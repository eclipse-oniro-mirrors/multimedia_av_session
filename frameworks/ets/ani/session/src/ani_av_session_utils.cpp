/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_av_session_utils.h"
#include "ani.h"
#include "ability.h"
#include "ability_context.h"
#include "av_session.h"
#include "extension_context.h"
#include "ani_base_context.h"
#include "ani_class_name.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS::AVSession {
ani_object AniUtils::CreateCastDisplayInfoAniObject(ani_env *env)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, nullptr, "env is null");
    ani_class castDisplayInfoCls {};
    static const char *className = ANI_CLASS_CAST_DISPLAY_INFO_HANDLE.c_str();
    CHECK_AND_RETURN_RET_LOG(env->FindClass(className, &castDisplayInfoCls),
        nullptr, "Find CastDisplayInfo class fail");

    ani_method castDisplayInfoCtor {};
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(castDisplayInfoCls, "<ctor>", nullptr, &castDisplayInfoCtor),
        nullptr, "Find CastDisplayInfo ctor fail");

    ani_object castDisplayInfoObj {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(castDisplayInfoCls, castDisplayInfoCtor, &castDisplayInfoObj),
        nullptr, "New CastDisplayInfo object fail");
    return castDisplayInfoObj;
}

ani_object AniUtils::CreateCastDisplayInfoAniObject(ani_env *env, ani_ref ref)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, nullptr, "env is null");
    ani_class castDisplayInfoCls {};
    static const char *className = ANI_CLASS_CAST_DISPLAY_INFO_HANDLE.c_str();
    CHECK_AND_RETURN_RET_LOG(env->FindClass(className, &castDisplayInfoCls),
        nullptr, "Find CastDisplayInfo class fail");

    ani_method castDisplayInfoCtor {};
    CHECK_AND_RETURN_RET_LOG(env->Class_FindMethod(castDisplayInfoCls, "<ctor>", nullptr, &castDisplayInfoCtor),
        nullptr, "Find CastDisplayInfo ctor fail");

    ani_object castDisplayInfoObj {};
    CHECK_AND_RETURN_RET_LOG(env->Object_New(castDisplayInfoCls, castDisplayInfoCtor, &castDisplayInfoObj, ref),
        nullptr, "New CastDisplayInfo object fail");
    return castDisplayInfoObj;
}

int32_t AniUtils::ConvertSessionType(const std::string& typeString)
{
    if (typeString == "audio") {
        return AVSession::SESSION_TYPE_AUDIO;
    } else if (typeString == "video") {
        return AVSession::SESSION_TYPE_VIDEO;
    } else if (typeString == "voice_call") {
        return AVSession::SESSION_TYPE_VOICE_CALL;
    } else if (typeString == "video_call") {
        return AVSession::SESSION_TYPE_VIDEO_CALL;
    } else {
        return AVSession::SESSION_TYPE_INVALID;
    }
}

ani_status AniUtils::GetString(ani_env *env, ani_string arg, std::string &str)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    CHECK_AND_RETURN_RET_LOG(arg != nullptr, ANI_INVALID_ARGS, "GetString invalid arg");
    ani_size srcSize = 0;
    ani_status status = env->String_GetUTF8Size(arg, &srcSize);
    if (status != ANI_OK) {
        SLOGE("String_GetUTF8Size failed");
        return status;
    }

    std::vector<char> buffer(srcSize + 1);
    ani_size dstSize = 0;
    status = env->String_GetUTF8SubString(arg, 0, srcSize, buffer.data(), buffer.size(), &dstSize);
    if (status != ANI_OK) {
        SLOGE("String_GetUTF8SubString failed");
        return status;
    }

    str.assign(buffer.data(), dstSize);
    return ANI_OK;
}

ani_status AniUtils::GetValue(ani_env *env, ani_object object, AppExecFwk::ElementName& out)
{
    CHECK_RETURN(GetStageElementName(env, object, out) == ANI_OK, "get StagContext failed", ANI_ERROR);
    return ANI_OK;
}

ani_boolean AniUtils::Equals(ani_env *env, ani_ref value, ani_ref copy)
{
    if (copy == nullptr) {
        return (value == nullptr);
    }

    CHECK_RETURN(env != nullptr, "env is nullptr", ANI_FALSE);
    ani_wref wref;
    CHECK_RETURN(env->WeakReference_Create(copy, &wref) == ANI_OK, "WeakReference_Create failed", ANI_FALSE);
    ani_ref copyValue;
    ani_boolean wasReleased;
    CHECK_RETURN(env->WeakReference_GetReference(wref, &wasReleased, &copyValue) == ANI_OK,
        "WeakReference_GetReference failed", ANI_FALSE);
    ani_boolean isEquals = ANI_FALSE;
    CHECK_RETURN(env->Reference_StrictEquals(value, copyValue, &isEquals) == ANI_OK,
        "get equals result failed", ANI_FALSE);
    return isEquals;
}

ani_status AniUtils::GetRefByCallback(ani_env *env, std::list<ani_ref> callbackList,
    ani_ref callback, ani_ref& callbackRef)
{
    for (auto ref = callbackList.begin(); ref != callbackList.end(); ++ref) {
        if (Equals(env, callback, *ref)) {
            SLOGD("Callback has been matched");
            callbackRef = *ref;
            break;
        }
    }
    return ANI_OK;
}

ani_status AniUtils::GetStageElementName(ani_env *env, ani_object object, AppExecFwk::ElementName& out)
{
    std::shared_ptr<OHOS::AbilityRuntime::Context> stageContext = GetStageModeContext(env, object);
    CHECK_RETURN(stageContext != nullptr, "get StagContext failed", ANI_ERROR);
    std::shared_ptr <AppExecFwk::AbilityInfo> abilityInfo;
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(stageContext);
    if (abilityContext != nullptr) {
        abilityInfo = abilityContext->GetAbilityInfo();
    } else {
        auto extensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::ExtensionContext>(stageContext);
        CHECK_RETURN(extensionContext != nullptr, "context ConvertTo AbilityContext and ExtensionContext fail",
            ANI_ERROR);
        abilityInfo = extensionContext->GetAbilityInfo();
    }
    out.SetBundleName(abilityInfo->bundleName);
    out.SetAbilityName(abilityInfo->name);
    return ANI_OK;
}

/* ani_object <-> double */
ani_status AniUtils::SetValue(ani_env *env, const double& in, ani_object& object)
{
    return ToAniBooleanObject(env, in, object);
}

/* ani_status <-> int32_t */
ani_status AniUtils::SetValue(ani_env *env, const int32_t& in, ani_object &object)
{
    return ToAniIntObject(env, in, object);
}

/* ani_object <-> int64_t */
ani_status AniUtils::SetValue(ani_env *env, const int64_t& in, ani_object &object)
{
    return ToAniLongObject(env, in, object);
}

/* ani_object <-> std::string */
ani_status AniUtils::SetValue(ani_env *env, const std::string& in, ani_object& object)
{
    ani_string aniString {};
    ToAniString(env, in, aniString);
    object = reinterpret_cast<ani_object>(aniString);
    return ANI_OK;
}

/* ani_object <-> CastDisplayInfo */
ani_status AniUtils::SetValue(ani_env *env, const CastDisplayInfo& in, ani_object &object)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    if (object == nullptr) {
        object = CreateCastDisplayInfoAniObject(env);
        CHECK_RETURN(object != nullptr, "creat castDisplayInfoObject failed", ANI_ERROR);
    }
    ani_enum_item displayState = 0;
    ani_status status = AVSessionEnumAni::ToAniEnum(env, in.displayState, displayState);
    status = env->Object_SetPropertyByName_Ref(object, "state", displayState);

    ani_double displayId = static_cast<ani_double>(in.displayId);
    status = env->Object_SetPropertyByName_Double(object, "id", displayId);

    ani_string name {};
    status = env->String_NewUTF8(in.name.c_str(), in.name.size(), &name);
    status = env->Object_SetPropertyByName_Ref(object, "name", name);

    ani_double width = static_cast<ani_double>(in.width);
    status = env->Object_SetPropertyByName_Double(object, "width", width);

    ani_double height = static_cast<ani_double>(in.height);
    status = env->Object_SetPropertyByName_Double(object, "height", height);
    CHECK_RETURN(status == ANI_OK, "set property failed", status);
    return status;
}

/* ani_object <-> CastDisplayInfo Array */
ani_status AniUtils::SetValue(ani_env *env, const std::vector<CastDisplayInfo>& array, ani_object &aniArray)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    ani_status status = env->FindClass(className.c_str(), &cls);
    if (status != ANI_OK) {
        SLOGE("Can't find Lescompat/Array.");
        return status;
    }

    ani_method arrayConstructor {};
    status = env->Class_FindMethod(cls, "<ctor>", "I:V;", &arrayConstructor);
    if (status != ANI_OK) {
        SLOGE("Can't find method <ctor> in Lescompat/Array.");
        return status;
    }

    status = env->Object_New(cls, arrayConstructor, &aniArray, array.size());
    if (status != ANI_OK) {
        SLOGE("Call method <ctor> failed.");
        return status;
    }

    ani_method setMethod {};
    status = env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod);
    if (status != ANI_OK) {
        SLOGE("Can't find method $_set in Lescompat/Array.");
        return status;
    }

    ani_int index = 0;
    for (auto& item : array) {
        ani_object castDisplayInfoAni = CreateCastDisplayInfoAniObject(env);
        SetValue(env, item, castDisplayInfoAni);
        ani_status status = env->Object_CallMethod_Void(aniArray, setMethod, index++, castDisplayInfoAni);
        CHECK_RETURN(status == ANI_OK, "Object_CallMethod_Void failed", status);
    }
    return ANI_OK;
}

ani_status AniUtils::ToAniString(ani_env *env, const std::string &str, ani_string &aniStr)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        SLOGE("String_NewUTF8 failed");
        return status;
    }
    return ANI_OK;
}

ani_status AniUtils::ToAniBooleanObject(ani_env *env, bool src, ani_object &aniObj)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    static const char *className = "Lstd/core/Boolean;";
    ani_class cls {};
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        SLOGE("Failed to find class: %{public}s", className);
        return status;
    }

    ani_method ctor {};
    status = env->Class_FindMethod(cls, "<ctor>", "Z:V", &ctor);
    if (status != ANI_OK) {
        SLOGE("Failed to find method: ctor");
        return status;
    }

    ani_boolean aniBool = src ? ANI_TRUE : ANI_FALSE;
    status = env->Object_New(cls, ctor, &aniObj, aniBool);
    if (status != ANI_OK) {
        SLOGE("New bool Object Fail");
        return status;
    }
    return ANI_OK;
}

ani_status AniUtils::ToAniIntObject(ani_env *env, int32_t src, ani_object &aniObj)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    static const char *className = "Lstd/core/Int;";
    ani_class cls {};
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        SLOGE("Failed to find class: %{public}s", className);
        return status;
    }

    ani_method ctor {};
    status = env->Class_FindMethod(cls, "<ctor>", "I:V", &ctor);
    if (status != ANI_OK) {
        SLOGE("Failed to find method: ctor");
        return status;
    }

    status = env->Object_New(cls, ctor, &aniObj, static_cast<ani_int>(src));
    if (status != ANI_OK) {
        SLOGE("New int32 Object Fail");
        return status;
    }
    return ANI_OK;
}

ani_status AniUtils::ToAniLongObject(ani_env *env, int64_t src, ani_object &aniObj)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    static const char *className = "Lescompat/BigInt;";
    ani_class cls {};
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        SLOGE("Failed to find class: %{public}s", className);
        return status;
    }

    ani_method ctor {};
    status = env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor);
    if (status != ANI_OK) {
        SLOGE("Failed to find method: ctor");
        return status;
    }

    status = env->Object_New(cls, ctor, &aniObj, static_cast<ani_long>(src));
    if (status != ANI_OK) {
        SLOGE("New int64_t Object Fail");
        return status;
    }
    return ANI_OK;
}

ani_status AniUtils::ThrowError(ani_env *env, const char *aniMessage, int32_t aniCode)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_ERROR, "env is null");
    static const std::string className = "L@ohos/multimedia/avsession/AvSessionAniError;";
    ani_class cls;
    ani_status status = env->FindClass(className.c_str(), &cls);
    if (status != ANI_OK) {
        SLOGE("Can't find class %{public}s", className.c_str());
        return ANI_ERROR;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "DLstd/core/String;:V", &ctor)) {
        SLOGE("Can't find <ctor> from class %{public}s", className.c_str());
        return ANI_ERROR;
    }
    ani_string error_msg;
    if (ANI_OK != AniUtils::ToAniString(env, aniMessage, error_msg)) {
        SLOGE("Call ToAniString function failed.");
        return ANI_ERROR;
    }

    ani_object errObj;
    if (ANI_OK != env->Object_New(cls, ctor, &errObj, (ani_double)aniCode, error_msg)) {
        SLOGE("New MediaLibraryAniError object failed.");
        return ANI_ERROR;
    }

    env->ThrowError(static_cast<ani_error>(errObj));
    return ANI_OK;
}

ani_ref AniUtils::GetUndefinedValue(ani_env *env)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, nullptr, "env is null");
    ani_ref result;
    env->GetUndefined(&result);
    return result;
}
}
