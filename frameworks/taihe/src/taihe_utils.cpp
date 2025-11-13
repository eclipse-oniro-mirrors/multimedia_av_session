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
#ifndef LOG_TAG
#define LOG_TAG "TaiheUtils"
#endif

#include <cstdio>

#include "taihe_utils.h"

#include "ability_context.h"
#include "ability.h"
#include "ani_base_context.h"
#include "ani_common_want.h"
#include "ani_common_want_agent.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "av_session.h"
#include "curl/curl.h"
#include "extension_context.h"
#include "image_source.h"
#include "pixel_map.h"
#include "pixel_map_taihe_ani.h"
#include "taihe_avsession_controller.h"
#include "taihe_media_description.h"
#include "taihe_meta_data.h"
#include "taihe_playback_state.h"
#include "taihe_avcall_meta_data.h"
#include "taihe_avcall_state.h"
#include "taihe_queue_item.h"
#include "taihe_avsession_manager.h"

namespace ANI::AVSession {
static constexpr size_t STR_MAX_LENGTH = 40960;

ani_object TaiheUtils::CreateAniEmptyRecord()
{
    ani_object aniRecord {};
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", aniRecord);

    ani_class cls {};
    static const std::string className = "escompat.Record";
    CHECK_RETURN(env->FindClass(className.c_str(), &cls) == ANI_OK, "Can't find escompat.Record", aniRecord);

    ani_method constructor {};
    CHECK_RETURN(env->Class_FindMethod(cls, "<ctor>", "C{std.core.Object}:", &constructor) == ANI_OK,
        "Can't find method <ctor> in escompat.Record", aniRecord);

    CHECK_RETURN(env->Object_New(cls, constructor, &aniRecord, nullptr) == ANI_OK,
        "Call method <ctor> fail", aniRecord);
    return aniRecord;
}

void TaiheUtils::ThrowError(int32_t errCode, const std::string &errMsg)
{
    SLOGE("ThrowError errCode: %{public}d, errMsg: %{public}s", errCode, errMsg.c_str());
    taihe::set_business_error(errCode, errMsg);
}

void TaiheUtils::ThrowAddCallbackError()
{
    TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
        "add event callback failed");
}

void TaiheUtils::ThrowRemoveCallbackError()
{
    TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
        "remove event callback failed");
}

size_t TaiheUtils::WriteCallback(std::uint8_t *ptr, size_t size, size_t nmemb, std::vector<std::uint8_t> *imgBuffer)
{
    size_t realsize = size * nmemb;
    if (realsize == 0 || imgBuffer == nullptr || ptr == nullptr) {
        SLOGE("WriteCallback realsize is zero, no data received");
        return 0;
    }
    imgBuffer->reserve(realsize + imgBuffer->capacity());
    for (size_t i = 0; i < realsize; i++) {
        imgBuffer->push_back(ptr[i]);
    }
    return realsize;
}

bool TaiheUtils::CurlSetRequestOptions(std::vector<std::uint8_t> &imgBuffer, const std::string &uri)
{
    CURL *easyHandle_ = curl_easy_init();
    if (easyHandle_) {
        // set request options
        curl_easy_setopt(easyHandle_, CURLOPT_URL, uri.c_str());
        curl_easy_setopt(easyHandle_, CURLOPT_CONNECTTIMEOUT, TaiheUtils::TIME_OUT_SECOND);
        curl_easy_setopt(easyHandle_, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(easyHandle_, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(easyHandle_, CURLOPT_CAINFO, "/etc/ssl/certs/" "cacert.pem");
        curl_easy_setopt(easyHandle_, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(easyHandle_, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(easyHandle_, CURLOPT_WRITEDATA, &imgBuffer);

        // perform request
        CURLcode res = curl_easy_perform(easyHandle_);
        if (res != CURLE_OK) {
            SLOGI("DoDownload curl easy_perform failure: %{public}s\n", curl_easy_strerror(res));
            curl_easy_cleanup(easyHandle_);
            easyHandle_ = nullptr;
            return false;
        } else {
            int64_t httpCode = 0;
            curl_easy_getinfo(easyHandle_, CURLINFO_RESPONSE_CODE, &httpCode);
            SLOGI("DoDownload Http result " "%{public}" PRId64, httpCode);
            CHECK_AND_RETURN_RET_LOG(httpCode < TaiheUtils::HTTP_ERROR_CODE, false, "recv Http ERROR");
            curl_easy_cleanup(easyHandle_);
            easyHandle_ = nullptr;
            return true;
        }
    }
    return false;
}

bool TaiheUtils::DoDownloadInCommon(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap, const std::string &uri)
{
    SLOGI("DoDownloadInCommon with uri");
    std::vector<std::uint8_t> imgBuffer(0);
    if (CurlSetRequestOptions(imgBuffer, uri) == true) {
        std::uint8_t* buffer = (std::uint8_t*) calloc(imgBuffer.size(), sizeof(uint8_t));
        if (buffer == nullptr) {
            SLOGE("buffer malloc fail");
            free(buffer);
            return false;
        }
        std::copy(imgBuffer.begin(), imgBuffer.end(), buffer);
        uint32_t errorCode = 0;
        OHOS::Media::SourceOptions opts;
        SLOGD("DoDownload get size %{public}zu", imgBuffer.size());
        auto imageSource = OHOS::Media::ImageSource::CreateImageSource(buffer, imgBuffer.size(), opts, errorCode);
        free(buffer);
        if (errorCode != 0 || imageSource == nullptr) {
            SLOGE("DoDownload create imageSource fail: %{public}u", errorCode);
            return false;
        }
        OHOS::Media::DecodeOptions decodeOpts;
        pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
        if (errorCode != 0 || pixelMap == nullptr) {
            SLOGE("DoDownload CreatePixelMap fail: %{public}u, %{public}d",
                errorCode, static_cast<int>(pixelMap != nullptr));
            return false;
        }
        return true;
    }
    return false;
}

int32_t TaiheUtils::GetRefByCallback(std::list<std::shared_ptr<uintptr_t>> callbackList,
    std::shared_ptr<uintptr_t> callback, std::shared_ptr<uintptr_t> &targetCb)
{
    for (auto ref = callbackList.begin(); ref != callbackList.end(); ++ref) {
        if (Equals(callback, *ref)) {
            SLOGD("Callback has been matched");
            targetCb = *ref;
            break;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

bool TaiheUtils::Equals(std::shared_ptr<uintptr_t> src, std::shared_ptr<uintptr_t> dst)
{
    std::shared_ptr<taihe::callback<void()>> srcPtr = std::reinterpret_pointer_cast<taihe::callback<void()>>(src);
    std::shared_ptr<taihe::callback<void()>> dstPtr = std::reinterpret_pointer_cast<taihe::callback<void()>>(dst);
    if (srcPtr == nullptr || dstPtr == nullptr) {
        SLOGE("srcPtr or dstPtr is nullptr");
        return false;
    }
    return *srcPtr == *dstPtr;
}

int32_t TaiheUtils::ConvertSessionType(const std::string& typeString)
{
    if (typeString == "audio") {
        return OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO;
    } else if (typeString == "video") {
        return OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO;
    } else if (typeString == "voice_call") {
        return OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    } else if (typeString == "video_call") {
        return OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO_CALL;
    } else {
        return OHOS::AVSession::AVSession::SESSION_TYPE_INVALID;
    }
}

std::string TaiheUtils::ConvertSessionType(int32_t type)
{
    if (type == OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO) {
        return "audio";
    } else if (type == OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO) {
        return "video";
    } else if (type == OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL) {
        return "voice_call";
    } else if (type == OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO_CALL) {
        return "video_call";
    } else {
        return "";
    }
}

bool TaiheUtils::IsAniUndefined(ani_env *env, ani_object obj)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", true);
    ani_boolean isUndefined = ANI_TRUE;
    if (env->Reference_IsUndefined(obj, &isUndefined) != ANI_OK) {
        SLOGE("Reference_IsUndefined failed");
        return true;
    }
    return isUndefined == ANI_TRUE;
}

bool TaiheUtils::IsAniArray(ani_env *env, ani_object obj)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", false);
    ani_class cls {};
    static const std::string className = "escompat.Array";
    CHECK_RETURN(env->FindClass(className.c_str(), &cls) == ANI_OK, "Can't find escompat.Array.", false);

    ani_static_method isArrayMethod {};
    CHECK_RETURN(env->Class_FindStaticMethod(cls, "isArray", nullptr, &isArrayMethod) == ANI_OK,
        "Can't find method isArray in Lescompat/Array.", false);

    ani_boolean isArray = ANI_FALSE;
    CHECK_RETURN(env->Class_CallStaticMethod_Boolean(cls, isArrayMethod, &isArray, obj) == ANI_OK,
        "Call method isArray failed.", false);
    return isArray == ANI_TRUE;
}

int32_t TaiheUtils::GetAniPropertyObject(ani_env *env, ani_object obj, const std::string &name, ani_object &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_ref aniRef {};
    if (env->Object_GetPropertyByName_Ref(obj, name.c_str(), &aniRef) != ANI_OK) {
        SLOGE("GetAniPropertyObject [%{public}s] failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    value = static_cast<ani_object>(aniRef);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAniPropertyInt32(ani_env *env, ani_object obj, const std::string &name, int32_t &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_int aniInt = 0;
    if (env->Object_GetPropertyByName_Int(obj, name.c_str(), &aniInt) != ANI_OK) {
        SLOGE("GetAniPropertyInt32 [%{public}s] failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    value = static_cast<int32_t>(aniInt);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAniOptionalPropertyInt32(ani_env *env, ani_object obj, const std::string &name, int32_t &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_object valueObj {};
    if (TaiheUtils::GetAniPropertyObject(env, obj, name, valueObj) != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("GetAniOptionalPropertyInt32 [%{public}s] GetAniPropertyObject failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    if (TaiheUtils::IsAniUndefined(env, valueObj)) {
        SLOGI("GetAniOptionalPropertyInt32 [%{public}s] is undefined", name.c_str());
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    ani_class cls {};
    if (env->FindClass("std.core.Int", &cls) != ANI_OK) {
        SLOGE("GetAniOptionalPropertyInt32 [%{public}s] find std.core.Int failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    ani_method method {};
    if (env->Class_FindMethod(cls, "intValue", nullptr, &method) != ANI_OK) {
        SLOGE("GetAniOptionalPropertyInt32 [%{public}s] find method intValue failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    ani_int aniInt = 0;
    if (env->Object_CallMethod_Int(valueObj, method, &aniInt) != ANI_OK) {
        SLOGE("GetAniOptionalPropertyInt32 [%{public}s] Object_CallMethod_Int failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    value = static_cast<int32_t>(aniInt);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

static int32_t GetAniInt32(ani_env *env, ani_object obj, int32_t &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    CHECK_RETURN(!TaiheUtils::IsAniUndefined(env, obj), "undefined object", OHOS::AVSession::AVSESSION_ERROR);

    ani_class cls {};
    static const std::string className = "std.core.Int";
    CHECK_RETURN(env->FindClass(className.c_str(), &cls) == ANI_OK,
        "Can't find std.core.Int", OHOS::AVSession::AVSESSION_ERROR);

    ani_method method {};
    CHECK_RETURN(env->Class_FindMethod(cls, "unboxed", nullptr, &method) == ANI_OK,
        "Can't find method unboxed in std.core.Int", OHOS::AVSession::AVSESSION_ERROR);

    ani_int aniInt = 0;
    CHECK_RETURN(env->Object_CallMethod_Int(obj, method, &aniInt) == ANI_OK,
        "Call method unboxed failed.", OHOS::AVSession::AVSESSION_ERROR);
    value = static_cast<int32_t>(aniInt);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAniPropertyInt32Array(ani_env *env, ani_object obj, const std::string &name,
    std::vector<int32_t> &array)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_object valueObj {};
    CHECK_RETURN(TaiheUtils::GetAniPropertyObject(env, obj, name, valueObj) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAniPropertyObject failed", OHOS::AVSession::AVSESSION_ERROR);
    CHECK_RETURN(!TaiheUtils::IsAniUndefined(env, valueObj), "undefined property", OHOS::AVSession::AVSESSION_ERROR);
    CHECK_RETURN(TaiheUtils::IsAniArray(env, valueObj), "property is not array", OHOS::AVSession::AVSESSION_ERROR);

    ani_double length = 0;
    CHECK_RETURN(env->Object_GetPropertyByName_Double(valueObj, "length", &length) == ANI_OK,
        "Call method <get>length failed", OHOS::AVSession::AVSESSION_ERROR);
    for (ani_int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref ref;
        CHECK_RETURN(env->Object_CallMethodByName_Ref(valueObj, "$_get", "i:C{std.core.Object}", &ref, i) == ANI_OK,
            "Call method $_get failed.", OHOS::AVSession::AVSESSION_ERROR);

        int32_t value = 0;
        CHECK_RETURN(GetAniInt32(env, static_cast<ani_object>(ref), value) == OHOS::AVSession::AVSESSION_SUCCESS,
            "Call method GetInt32 failed.", OHOS::AVSession::AVSESSION_ERROR);
        array.emplace_back(value);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAniPropertyEnumInt32(ani_env *env, ani_object obj, const std::string &name, int32_t &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_object enumObj {};
    CHECK_RETURN(TaiheUtils::GetAniPropertyObject(env, obj, name, enumObj) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAniPropertyObject enum failed", OHOS::AVSession::AVSESSION_ERROR);
    CHECK_RETURN(!TaiheUtils::IsAniUndefined(env, enumObj), "undefined enum", OHOS::AVSession::AVSESSION_ERROR);

    ani_int aniInt = 0;
    CHECK_RETURN(env->EnumItem_GetValue_Int(static_cast<ani_enum_item>(enumObj), &aniInt),
        "EnumItem_GetValue_Int failed", OHOS::AVSession::AVSESSION_ERROR);
    value = static_cast<int32_t>(aniInt);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAniPropertyInt64(ani_env *env, ani_object obj, const std::string &name, int64_t &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_long aniLong = 0;
    if (env->Object_GetPropertyByName_Long(obj, name.c_str(), &aniLong) != ANI_OK) {
        SLOGE("GetAniPropertyInt64 [%{public}s] failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    value = static_cast<int64_t>(aniLong);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAniOptionalPropertyInt64(ani_env *env, ani_object obj, const std::string &name, int64_t &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_object valueObj {};
    if (TaiheUtils::GetAniPropertyObject(env, obj, name, valueObj) != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("GetAniOptionalPropertyInt64 [%{public}s] GetAniPropertyObject failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    if (TaiheUtils::IsAniUndefined(env, valueObj)) {
        SLOGI("GetAniOptionalPropertyInt64 [%{public}s] is undefined", name.c_str());
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    ani_class cls {};
    if (env->FindClass("std.core.Int", &cls) != ANI_OK) {
        SLOGE("GetAniOptionalPropertyInt64 [%{public}s] find Lstd/core/Int failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    ani_method method {};
    if (env->Class_FindMethod(cls, "longValue", nullptr, &method) != ANI_OK) {
        SLOGE("GetAniOptionalPropertyInt64 [%{public}s] find method longValue failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    ani_long aniLong = 0;
    if (env->Object_CallMethod_Long(valueObj, method, &aniLong) != ANI_OK) {
        SLOGE("GetAniOptionalPropertyInt64 [%{public}s] Object_CallMethod_Long failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    value = static_cast<int64_t>(aniLong);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

static int32_t GetAniString(ani_env *env, ani_string aniString, std::string &value)
{
    CHECK_RETURN(env != nullptr && aniString != nullptr, "env or aniString is nullptr",
        OHOS::AVSession::AVSESSION_ERROR);
    ani_size srcSize = 0;
    if (env->String_GetUTF8Size(aniString, &srcSize) != ANI_OK) {
        SLOGE("String_GetUTF8Size failed");
        return OHOS::AVSession::AVSESSION_ERROR;
    }

    std::vector<char> buffer(srcSize + 1);
    ani_size dstSize = 0;
    if (env->String_GetUTF8SubString(aniString, 0, srcSize, buffer.data(), buffer.size(), &dstSize) != ANI_OK) {
        SLOGE("String_GetUTF8SubString failed");
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    value.assign(buffer.data(), dstSize);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::ToAniDoubleObject(ani_env *env, double in, ani_object &out)
{
    CHECK_RETURN(env != nullptr, "env is nullptr", OHOS::AVSession::AVSESSION_ERROR);

    ani_class cls {};
    CHECK_RETURN(env->FindClass("std.core.Double", &cls) == ANI_OK,
        "FindClass std.core.Double failed", OHOS::AVSession::AVSESSION_ERROR);

    ani_method ctorMethod {};
    CHECK_RETURN(env->Class_FindMethod(cls, "<ctor>", "d:", &ctorMethod) == ANI_OK,
        "Class_FindMethod std.core.Double <ctor> failed", OHOS::AVSession::AVSESSION_ERROR);

    CHECK_RETURN(env->Object_New(cls, ctorMethod, &out, static_cast<ani_double>(in)) == ANI_OK,
        "Object_New std.core.Double failed", OHOS::AVSession::AVSESSION_ERROR);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

static int32_t ToAniString(ani_env *env, const std::string &str, ani_string &aniString)
{
    CHECK_RETURN(env != nullptr, "env is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    if (env->String_NewUTF8(str.c_str(), str.size(), &aniString) != ANI_OK) {
        SLOGE("String_NewUTF8 failed");
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAniPropertyString(ani_env *env, ani_object obj, const std::string &name, std::string &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_ref aniRef {};
    if (env->Object_GetPropertyByName_Ref(obj, name.c_str(), &aniRef) != ANI_OK || aniRef == nullptr) {
        SLOGE("GetAniPropertyString [%{public}s] failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }

    if (GetAniString(env, static_cast<ani_string>(aniRef), value) != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("GetAniPropertyString [%{public}s] GetAniString failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAniOptionalPropertyString(ani_env *env, ani_object obj, const std::string &name,
    std::string &value)
{
    CHECK_RETURN(env != nullptr && obj != nullptr, "env or obj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_object valueObj {};
    if (TaiheUtils::GetAniPropertyObject(env, obj, name, valueObj) != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("GetAniOptionalPropertyString [%{public}s] GetAniPropertyObject failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    if (TaiheUtils::IsAniUndefined(env, valueObj)) {
        SLOGI("GetAniOptionalPropertyString [%{public}s] is undefined", name.c_str());
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    if (GetAniString(env, static_cast<ani_string>(valueObj), value) != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("GetAniOptionalPropertyString [%{public}s] GetAniString failed", name.c_str());
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetStageElementName(uintptr_t context, OHOS::AppExecFwk::ElementName &out)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_object aniContext = reinterpret_cast<ani_object>(context);
    CHECK_RETURN(aniContext != nullptr, "aniContext is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    auto stageContext = OHOS::AbilityRuntime::GetStageModeContext(env, aniContext);
    CHECK_RETURN(stageContext != nullptr, "get StagContext failed", OHOS::AVSession::AVSESSION_ERROR);
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo;
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(stageContext);
    if (abilityContext != nullptr) {
        abilityInfo = abilityContext->GetAbilityInfo();
    } else {
        auto extensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::ExtensionContext>(stageContext);
        CHECK_RETURN(extensionContext != nullptr, "context ConvertTo AbilityContext and ExtensionContext fail",
            OHOS::AVSession::AVSESSION_ERROR);
        abilityInfo = extensionContext->GetAbilityInfo();
    }
    CHECK_RETURN(abilityInfo != nullptr, "get abilityInfo failed", OHOS::AVSession::AVSESSION_ERROR);
    out.SetBundleName(abilityInfo->bundleName);
    out.SetAbilityName(abilityInfo->name);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetString(string_view in, std::string &out)
{
    if (in.size() >= STR_MAX_LENGTH) {
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    out = std::string(in);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetString(string in, std::string &out)
{
    string_view inView(in);
    return TaiheUtils::GetString(inView, out);
}

int32_t TaiheUtils::GetOptionalString(optional<string> in, std::string &out)
{
    if (in.has_value()) {
        return TaiheUtils::GetString(in.value(), out);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetStringArray(const array<string> &in, std::vector<std::string> &out)
{
    std::vector<std::string> stringVec;
    for (const auto &item : in) {
        std::string str;
        int32_t status = GetString(item, str);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get single string failed", status);
        stringVec.emplace_back(str);
    }
    out = std::move(stringVec);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetUIntArray(const array<uint32_t> &in, std::vector<uint32_t> &out)
{
    std::vector<uint32_t> intVec;
    for (const auto &item : in) {
        uint32_t ele = static_cast<uint32_t>(item);
        intVec.emplace_back(ele);
    }
    out = std::move(intVec);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetSessionToken(SessionToken const &in, OHOS::AVSession::SessionToken &out)
{
    int32_t status = TaiheUtils::GetString(in.sessionId, out.sessionId);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get string sessionId failed", status);
    out.pid = in.pid.has_value() ? static_cast<pid_t>(in.pid.value()) : 0;
    out.uid = in.uid.has_value() ? static_cast<pid_t>(in.uid.value()) : 0;
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetDeviceInfo(DeviceInfo const &in, OHOS::AVSession::DeviceInfo &out)
{
    out.castCategory_ = in.castCategory.get_value();
    int32_t status = TaiheUtils::GetString(in.deviceId, out.deviceId_);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get string deviceId failed", status);
    status = TaiheUtils::GetString(in.deviceName, out.deviceName_);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get string deviceName failed", status);
    out.deviceType_ = in.deviceType.get_value();
    status = TaiheUtils::GetOptionalString(in.manufacturer, out.manufacturer_);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get optional string manufacturer failed", status);
    status = TaiheUtils::GetOptionalString(in.modelName, out.modelName_);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get optional string modelName failed", status);
    status = TaiheUtils::GetOptionalString(in.networkId, out.networkId_);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get optional string networkId failed", status);
    status = TaiheUtils::GetOptionalString(in.ipAddress, out.ipAddress_);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get optional string ipAddress failed", status);
    out.providerId_ = in.providerId.has_value() ? in.providerId.value() : 0;
    out.supportedProtocols_ = in.supportedProtocols.has_value() ?
        in.supportedProtocols.value() : OHOS::AVSession::ProtocolType::TYPE_CAST_PLUS_STREAM;
    if (in.supportedDrmCapabilities.has_value()) {
        status = GetStringArray(in.supportedDrmCapabilities.value(), out.supportedDrmCapabilities_);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get supportedDrmCapabilities failed", status);
    }
    out.authenticationStatus_ = in.authenticationStatus.has_value() ? in.authenticationStatus.value() : 0;
    out.isLegacy_ = in.isLegacy.has_value() ? in.isLegacy.value() : false;
    out.mediumTypes_ = in.mediumTypes.has_value() ? in.mediumTypes.value() : COAP;

    if (in.supportedPullClients.has_value()) {
        status = GetUIntArray(in.supportedPullClients.value(), out.supportedPullClients_);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get supportedPullClients failed", status);
    }
    if (in.audioCapabilities.has_value()) {
        status = GetAudioCapabilities(in.audioCapabilities.value(), out.audioCapabilities_);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get audioCapabilities failed", status);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetOutputDeviceInfo(OutputDeviceInfo const &in, OHOS::AVSession::OutputDeviceInfo &out)
{
    for (const auto &item : in.devices) {
        OHOS::AVSession::DeviceInfo deviceInfo;
        int32_t status = GetDeviceInfo(item, deviceInfo);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get device info failed", status);
        out.deviceInfos_.emplace_back(deviceInfo);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetWantParams(uintptr_t in, OHOS::AAFwk::WantParams &out)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_ref aniRef = reinterpret_cast<ani_ref>(in);
    CHECK_RETURN(aniRef != nullptr, "aniRef is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    CHECK_RETURN(OHOS::AppExecFwk::UnwrapWantParams(env, aniRef, out),
        "UnwrapWantParams failed", OHOS::AVSession::AVSESSION_ERROR);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetWantAgent(uintptr_t in, OHOS::AbilityRuntime::WantAgent::WantAgent* &out)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    ani_object aniObj = reinterpret_cast<ani_object>(in);
    CHECK_RETURN(aniObj != nullptr, "aniObj is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    OHOS::AppExecFwk::UnwrapWantAgent(env, aniObj, reinterpret_cast<void **>(&out));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAVFileDescriptor(uintptr_t in, OHOS::AVSession::AVFileDescriptor &out)
{
    ani_env *env = taihe::get_env();
    ani_object aniObj = reinterpret_cast<ani_object>(in);
    CHECK_RETURN(GetAniPropertyInt32(env, aniObj, "fd", out.fd_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAVFileDescriptor get fd failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetAniOptionalPropertyInt64(env, aniObj, "offset", out.offset_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAVFileDescriptor get offset failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetAniOptionalPropertyInt64(env, aniObj, "length", out.length_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAVFileDescriptor get length failed", OHOS::AVSession::ERR_INVALID_PARAM);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAVDataSrcDescriptor(uintptr_t in, OHOS::AVSession::AVDataSrcDescriptor &out)
{
    ani_env *env = taihe::get_env();
    ani_object aniObj = reinterpret_cast<ani_object>(in);
    CHECK_RETURN(
        GetAniOptionalPropertyInt64(env, aniObj, "fileSize", out.fileSize) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAVDataSrcDescriptor get fileSize failed", OHOS::AVSession::ERR_INVALID_PARAM);
    out.callback_ = [](void* buffer, uint32_t length, int64_t pos) -> int32_t {
        ani_env *env = taihe::get_env();
        CHECK_RETURN(env != nullptr, "env is nullptr", 0);

        ani_class cls {};
        CHECK_RETURN(env->FindClass("@ohos.multimedia.avsession.MediaAVDataSrcDescriptorImpl", &cls) == ANI_OK,
            "FindClass MediaAVDataSrcDescriptorImpl failed", 0);
        ani_static_method onData {};
        CHECK_RETURN(env->Class_FindStaticMethod(cls, "OnData", nullptr, &onData) == ANI_OK,
            "Class_FindStaticMethod OnData failed", 0);

        void **dataResult = nullptr;
        ani_arraybuffer aniBuffer {};
        CHECK_RETURN(env->CreateArrayBuffer(length, dataResult, &aniBuffer) == ANI_OK, "CreateArrayBuffer failed", 0);
        *dataResult = buffer;

        ani_int aniLength = static_cast<ani_int>(length);
        ani_long aniPos = static_cast<ani_long>(pos);
        CHECK_RETURN(env->Class_CallStaticMethod_Void(cls, onData, aniBuffer, aniLength, aniPos) == ANI_OK,
            "Class_CallStaticMethod_Void OnData failed", 0);
        return 0;
    };
    out.hasCallback = true;
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

std::shared_ptr<OHOS::Media::PixelMap> TaiheUtils::GetImagePixelMap(uintptr_t in)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);
    ani_object aniPixelMap = reinterpret_cast<ani_object>(in);
    CHECK_RETURN(aniPixelMap != nullptr, "aniPixelMap is nullptr", nullptr);
    return OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(env, aniPixelMap);
}

static int32_t GetStreamInfo(const OHOS::AudioStandard::DeviceStreamInfo &in,
    std::list<OHOS::AudioStandard::DeviceStreamInfo> &out)
{
    out = {in};
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

static int32_t GetSampleRate(ani_env *env, ani_object aniObj, OHOS::AudioStandard::DeviceStreamInfo &streamInfo)
{
    std::vector<int32_t> valArray;
    int32_t ret = TaiheUtils::GetAniPropertyInt32Array(env, aniObj, "sampleRates", valArray);
    CHECK_RETURN(ret == OHOS::AVSession::AVSESSION_SUCCESS, "GetSampleRate failed", false);
    if (valArray.size() > 0) {
        OHOS::AudioStandard::AudioSamplingRate audioSamplingRate {};
        audioSamplingRate = static_cast<OHOS::AudioStandard::AudioSamplingRate>(valArray[0]);
        streamInfo.samplingRate = {audioSamplingRate};
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

static int32_t GetChannels(ani_env *env, ani_object aniObj, OHOS::AudioStandard::DeviceStreamInfo &streamInfo)
{
    std::vector<int32_t> valArray;
    int32_t ret = TaiheUtils::GetAniPropertyInt32Array(env, aniObj, "channelCounts", valArray);
    CHECK_RETURN(ret == OHOS::AVSession::AVSESSION_SUCCESS, "GetChannels failed", false);
    if (valArray.size() > 0) {
        OHOS::AudioStandard::AudioChannel audioChannel {};
        audioChannel = static_cast<OHOS::AudioStandard::AudioChannel>(valArray[0]);
        streamInfo.SetChannels({audioChannel});
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

static int32_t GetChannelMasks(ani_env *env, ani_object aniObj, int32_t &out)
{
    std::vector<int32_t> valArray;
    int32_t ret = TaiheUtils::GetAniPropertyInt32Array(env, aniObj, "channelMasks", valArray);
    CHECK_RETURN(ret == OHOS::AVSession::AVSESSION_SUCCESS, "GetChannelMasks failed", false);
    if (valArray.size() > 0) {
        out = valArray[0];
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAudioDeviceDescriptor(uintptr_t in, OHOS::AudioStandard::AudioDeviceDescriptor &out)
{
    ani_env *env = taihe::get_env();
    ani_object aniObj = reinterpret_cast<ani_object>(in);
    int32_t valInt = 0;
    OHOS::AudioStandard::DeviceStreamInfo streamInfo;
    CHECK_RETURN(GetAniPropertyEnumInt32(env, aniObj, "deviceRole", valInt) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get deviceRole failed", OHOS::AVSession::ERR_INVALID_PARAM);
    out.deviceRole_ = static_cast<OHOS::AudioStandard::DeviceRole>(valInt);

    CHECK_RETURN(GetAniPropertyEnumInt32(env, aniObj, "deviceType", valInt) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get deviceType failed", OHOS::AVSession::ERR_INVALID_PARAM);
    out.deviceType_ = static_cast<OHOS::AudioStandard::DeviceType>(valInt);

    CHECK_RETURN(GetAniPropertyInt32(env, aniObj, "id", out.deviceId_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get id failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetAniPropertyString(env, aniObj, "name", out.deviceName_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get name failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetAniPropertyString(env, aniObj, "networkId", out.networkId_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get networkId failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetAniPropertyString(env, aniObj, "address", out.macAddress_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get address failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetAniPropertyInt32(env, aniObj, "interruptGroupId", out.interruptGroupId_) ==
        OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get interruptGroupId failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(
        GetAniPropertyInt32(env, aniObj, "volumeGroupId", out.volumeGroupId_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get volumeGroupId failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetSampleRate(env, aniObj, streamInfo) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get sampleRates failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetChannels(env, aniObj, streamInfo) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get channelCounts failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetStreamInfo(streamInfo, out.audioStreamInfo_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get streamInfo failed", OHOS::AVSession::ERR_INVALID_PARAM);
    CHECK_RETURN(GetChannelMasks(env, aniObj, out.channelMasks_) == OHOS::AVSession::AVSESSION_SUCCESS,
        "GetAudioDeviceDescriptor get channelMasks failed", OHOS::AVSession::ERR_INVALID_PARAM);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAudioDeviceDescriptors(array_view<uintptr_t> in,
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> &out)
{
    for (const auto &item : in) {
        OHOS::AudioStandard::AudioDeviceDescriptor descriptor {};
        int32_t status = TaiheUtils::GetAudioDeviceDescriptor(item, descriptor);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "GetAudioDeviceDescriptor failed", status);
        out.emplace_back(descriptor);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAudioCapabilities(AudioCapabilities const &in, OHOS::AVSession::AudioCapabilities &out)
{
    taihe::array<uintptr_t> streamInfos = in.streamInfos;
    std::vector<OHOS::AVSession::AudioStreamInfo> outStreamInfos {};
    for (const auto &info : streamInfos) {
        ani_env *env = taihe::get_env();
        ani_object aniObj = reinterpret_cast<ani_object>(info);
        int32_t valInt = 0;
        OHOS::AVSession::AudioStreamInfo streamInfo {};
        CHECK_RETURN(GetAniPropertyEnumInt32(env, aniObj, "samplingRate", valInt) == OHOS::AVSession::AVSESSION_SUCCESS,
            "GetAudioCapabilities get samplingRate failed", OHOS::AVSession::ERR_INVALID_PARAM);
        streamInfo.samplingRate = static_cast<OHOS::AVSession::AudioSamplingRate>(valInt);
        CHECK_RETURN(GetAniPropertyEnumInt32(env, aniObj, "channels", valInt) == OHOS::AVSession::AVSESSION_SUCCESS,
            "GetAudioCapabilities get channels failed", OHOS::AVSession::ERR_INVALID_PARAM);
        streamInfo.channels = static_cast<OHOS::AVSession::AudioChannel>(valInt);
        CHECK_RETURN(GetAniPropertyEnumInt32(env, aniObj, "sampleFormat", valInt) == OHOS::AVSession::AVSESSION_SUCCESS,
            "GetAudioCapabilities get sampleFormat failed", OHOS::AVSession::ERR_INVALID_PARAM);
        streamInfo.format = static_cast<OHOS::AVSession::AudioSampleFormat>(valInt);
        CHECK_RETURN(GetAniPropertyEnumInt32(env, aniObj, "encodingType", valInt) == OHOS::AVSession::AVSESSION_SUCCESS,
            "GetAudioCapabilities get encodingType failed", OHOS::AVSession::ERR_INVALID_PARAM);
        streamInfo.encoding = static_cast<OHOS::AVSession::AudioEncodingType>(valInt);
        CHECK_RETURN(
            GetAniPropertyEnumInt32(env, aniObj, "channelLayout", valInt) == OHOS::AVSession::AVSESSION_SUCCESS,
            "GetAudioCapabilities get channelLayout failed", OHOS::AVSession::ERR_INVALID_PARAM);
        streamInfo.channelLayout = static_cast<OHOS::AVSession::AudioChannelLayout>(valInt);
        outStreamInfos.emplace_back(streamInfo);
    }

    out.streamInfos_ = std::move(outStreamInfos);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

static void GetKeyItem(keyEvent::Key const &in, OHOS::MMI::KeyEvent::KeyItem &out)
{
    int32_t code = in.code.get_value();
    SLOGI("code=%{public}d", code);
    out.SetKeyCode(code);

    int64_t pressedTime = in.pressedTime;
    SLOGI("pressedTime=%{public}ld", pressedTime);
    out.SetDownTime(pressedTime);

    int32_t deviceId = in.deviceId;
    SLOGI("deviceId=%{public}d", deviceId);
    out.SetDeviceId(deviceId);
    out.SetPressed(true);
}

int32_t TaiheUtils::GetKeyEvent(keyEvent::KeyEvent const &in, OHOS::MMI::KeyEvent &out)
{
    int32_t action = in.action.get_value();
    SLOGI("action=%{public}d", action);
    action += KEYEVENT_ACTION_JS_NATIVE_DELTA;
    out.SetKeyAction(action);

    OHOS::MMI::KeyEvent::KeyItem key;
    GetKeyItem(in.key, key);
    out.SetKeyCode(key.GetKeyCode());

    for (const auto &item : in.keys) {
        OHOS::MMI::KeyEvent::KeyItem keyItem;
        GetKeyItem(item, keyItem);
        if ((key.GetKeyCode() == keyItem.GetKeyCode()) && (action == OHOS::MMI::KeyEvent::KEY_ACTION_UP)) {
            keyItem.SetPressed(false);
        }
        out.AddKeyItem(keyItem);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAVCallState(const AVCallState &in, OHOS::AVSession::AVCallState &out)
{
    return TaiheAVCallState::GetAVCallState(in, out);
}

int32_t TaiheUtils::GetAVQueueItem(const AVQueueItem &in, OHOS::AVSession::AVQueueItem &out)
{
    return TaiheQueueItem::GetAVQueueItem(in, out);
}

int32_t TaiheUtils::GetAVQueueItemArray(const array<AVQueueItem> &in, std::vector<OHOS::AVSession::AVQueueItem> &out)
{
    for (const auto &item : in) {
        OHOS::AVSession::AVQueueItem avQueueItem;
        int32_t ret = GetAVQueueItem(item, avQueueItem);
        CHECK_RETURN(ret == OHOS::AVSession::AVSESSION_SUCCESS, "GetAVQueueItem failed", ret);
        out.emplace_back(avQueueItem);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheUtils::GetAVCallMetaData(const CallMetadata &in, OHOS::AVSession::AVCallMetaData &out)
{
    return TaiheAVCallMetaData::GetCallMetadata(in, out);
}

ani_object TaiheUtils::ToAniElementName(const OHOS::AppExecFwk::ElementName &in)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);
    return OHOS::AppExecFwk::WrapElementName(env, in);
}

DeviceInfo TaiheUtils::ToTaiheDeviceInfo(const OHOS::AVSession::DeviceInfo &in)
{
    std::vector<taihe::string> capabilityVec;
    for (const auto &item : in.supportedDrmCapabilities_) {
        capabilityVec.emplace_back(taihe::string(item));
    }
    DeviceInfo deviceInfo {
        .castCategory = AVCastCategory::from_value(in.castCategory_),
        .deviceId = taihe::string(in.deviceId_),
        .deviceName = taihe::string(in.deviceName_),
        .deviceType = DeviceType::from_value(in.deviceType_),
        .manufacturer = optional<taihe::string>(std::in_place_t {}, taihe::string(in.manufacturer_)),
        .modelName = optional<taihe::string>(std::in_place_t {}, taihe::string(in.modelName_)),
        .networkId = optional<taihe::string>(std::in_place_t {}, taihe::string(in.networkId_)),
        .ipAddress = optional<taihe::string>(std::in_place_t {}, taihe::string(in.ipAddress_)),
        .providerId = optional<int32_t>(std::in_place_t {}, in.providerId_),
        .supportedProtocols = optional<int32_t>(std::in_place_t {}, in.supportedProtocols_),
        .supportedDrmCapabilities =
            optional<taihe::array<taihe::string>>(std::in_place_t {}, taihe::array<taihe::string>(capabilityVec)),
        .authenticationStatus = optional<int32_t>(std::in_place_t {}, in.authenticationStatus_),
        .isLegacy = optional<bool>(std::in_place_t {}, in.isLegacy_),
        .mediumTypes = optional<int32_t>(std::in_place_t {}, in.mediumTypes_),
        .audioCapabilities = optional<AudioCapabilities>(
            std::in_place_t {}, ToTaiheAudioCapabilities(in.audioCapabilities_)),
    };
    return deviceInfo;
}

OutputDeviceInfo TaiheUtils::ToTaiheOutputDeviceInfo(const OHOS::AVSession::OutputDeviceInfo &in)
{
    SLOGD("taihe object <- OutputDeviceInfo");
    std::vector<DeviceInfo> deviceInfoVec;
    for (const auto &item : in.deviceInfos_) {
        DeviceInfo deviceInfo = ToTaiheDeviceInfo(item);
        deviceInfoVec.emplace_back(deviceInfo);
    }

    OutputDeviceInfo output {
        .devices = taihe::array<DeviceInfo>(deviceInfoVec),
    };
    return output;
}

OutputDeviceInfo TaiheUtils::CreateUndefinedOutputDeviceInfo()
{
    std::vector<DeviceInfo> deviceInfoVec;
    OutputDeviceInfo output {
        .devices = taihe::array<DeviceInfo>(deviceInfoVec),
    };
    return output;
}

DeviceState TaiheUtils::ToTaiheDeviceState(const OHOS::AVSession::DeviceState &in)
{
    DeviceState deviceState {
        .deviceId = taihe::string(in.deviceId),
        .deviceState = static_cast<int32_t>(in.deviceState),
        .reasonCode = static_cast<int32_t>(in.reasonCode),
        .radarErrorCode = static_cast<int32_t>(in.radarErrorCode),
    };
    return deviceState;
}

AVSessionDescriptor TaiheUtils::ToTaiheAVSessionDescriptor(const OHOS::AVSession::AVSessionDescriptor &in)
{
    auto elementName = ToAniElementName(in.elementName_);
    AVSessionDescriptor descriptor {
        .sessionId = taihe::string(in.sessionId_),
        .type = taihe::string(ConvertSessionType(in.sessionType_)),
        .sessionTag = taihe::string(in.sessionTag_),
        .elementName = reinterpret_cast<uintptr_t>(elementName),
        .isActive = in.isActive_,
        .isTopSession = in.isTopSession_,
        .outputDevice = ToTaiheOutputDeviceInfo(in.outputDeviceInfo_),
    };
    return descriptor;
}

taihe::array<AVSessionDescriptor> TaiheUtils::ToTaiheAVSessionDescriptorArray(
    const std::vector<OHOS::AVSession::AVSessionDescriptor> &in)
{
    SLOGD("taihe object <- std::vector<AVSessionDescriptor> %{public}d", static_cast<int>(in.size()));
    std::vector<AVSessionDescriptor> resultVec;
    for (const auto &item : in) {
        AVSessionDescriptor result = ToTaiheAVSessionDescriptor(item);
        resultVec.emplace_back(result);
    }
    return taihe::array<AVSessionDescriptor>(resultVec);
}

AVImageType TaiheUtils::ToTaiheAVImageType(const std::shared_ptr<OHOS::AVSession::AVSessionPixelMap> &avPixelMap,
    const std::string &uri)
{
    AVImageType result = AVImageType::make_typeString("");
    if (avPixelMap != nullptr) {
        auto pixelMap = OHOS::AVSession::AVSessionPixelMapAdapter::ConvertFromInner(avPixelMap);
        auto aniPixelMap = TaiheUtils::ToAniImagePixelMap(pixelMap);
        result = AVImageType::make_typePixelMap(reinterpret_cast<uintptr_t>(aniPixelMap));
    }
    if (!uri.empty()) {
        result = AVImageType::make_typeString(uri);
    }
    return result;
}

AVQueueInfo TaiheUtils::ToTaiheAVQueueInfo(const OHOS::AVSession::AVQueueInfo &in)
{
    AVQueueInfo avQueueInfo {
        .bundleName = taihe::string(in.GetBundleName()),
        .avQueueName = taihe::string(in.GetAVQueueName()),
        .avQueueId = taihe::string(in.GetAVQueueId()),
        .avQueueImage = ToTaiheAVImageType(in.GetAVQueueImage(), in.GetAVQueueImageUri()),
        .lastPlayedTime = optional<int64_t>(std::nullopt),
    };
    return avQueueInfo;
}

taihe::array<AVQueueInfo> TaiheUtils::ToTaiheAVQueueInfoArray(const std::vector<OHOS::AVSession::AVQueueInfo> &in)
{
    SLOGD("taihe object <- std::vector<AVQueueInfo> %{public}d", static_cast<int>(in.size()));
    std::vector<AVQueueInfo> resultVec;
    for (const auto &item : in) {
        AVQueueInfo result = ToTaiheAVQueueInfo(item);
        resultVec.emplace_back(result);
    }
    return taihe::array<AVQueueInfo>(resultVec);
}

ani_object TaiheUtils::ToAniWantParams(const OHOS::AAFwk::WantParams &in)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);
    ani_ref out = OHOS::AppExecFwk::WrapWantParams(env, in);
    return reinterpret_cast<ani_object>(out);
}

ani_object TaiheUtils::ToAniWantAgent(OHOS::AbilityRuntime::WantAgent::WantAgent* &in)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);
    return OHOS::AppExecFwk::WrapWantAgent(env, in);
}

ani_object TaiheUtils::ToAniAVFileDescriptor(const OHOS::AVSession::AVFileDescriptor &in)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);

    ani_class cls {};
    CHECK_RETURN(env->FindClass("@ohos.multimedia.avsession.MediaAVFileDescriptorImpl", &cls) == ANI_OK,
        "FindClass MediaAVFileDescriptorImpl failed", nullptr);
    ani_method ctorMethod {};
    CHECK_RETURN(env->Class_FindMethod(cls, "<ctor>", nullptr, &ctorMethod) == ANI_OK,
        "Class_FindMethod MediaAVFileDescriptorImpl <ctor> failed", nullptr);

    ani_int aniFd = static_cast<ani_int>(in.fd_);
    ani_long aniOffset = static_cast<ani_long>(in.offset_);
    ani_long aniLength = static_cast<ani_long>(in.length_);
    ani_object result {};
    CHECK_RETURN(env->Object_New(cls, ctorMethod, &result, aniFd, aniOffset, aniLength) == ANI_OK,
        "Object_New MediaAVFileDescriptorImpl failed", nullptr);
    return result;
}

ani_object TaiheUtils::ToAniAVDataSrcDescriptor(const OHOS::AVSession::AVDataSrcDescriptor &in)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);

    ani_class cls {};
    CHECK_RETURN(env->FindClass("@ohos.multimedia.avsession.MediaAVDataSrcDescriptorImpl", &cls) == ANI_OK,
        "FindClass MediaAVDataSrcDescriptorImpl failed", nullptr);
    ani_method ctorMethod {};
    CHECK_RETURN(env->Class_FindMethod(cls, "<ctor>", nullptr, &ctorMethod) == ANI_OK,
        "Class_FindMethod MediaAVDataSrcDescriptorImpl <ctor> failed", nullptr);

    ani_long aniFileSize = static_cast<ani_long>(in.fileSize);
    ani_object result {};
    CHECK_RETURN(env->Object_New(cls, ctorMethod, &result, aniFileSize) == ANI_OK,
        "Object_New MediaAVDataSrcDescriptorImpl failed", nullptr);
    return result;
}

ani_object TaiheUtils::ToAniAudioStreamInfo(const OHOS::AVSession::AudioStreamInfo &in)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);

    ani_class cls {};
    CHECK_RETURN(env->FindClass("@ohos.multimedia.avsession.AudioStreamInfoImpl", &cls) == ANI_OK,
        "FindClass AudioStreamInfoImpl failed", nullptr);
    ani_method ctorMethod {};
    CHECK_RETURN(env->Class_FindMethod(cls, "<ctor>", nullptr, &ctorMethod) == ANI_OK,
        "Class_FindMethod AudioStreamInfoImpl <ctor> failed", nullptr);

    ani_enum_item aniSamplingRate = reinterpret_cast<ani_enum_item>(in.samplingRate);
    ani_enum_item aniChannels = reinterpret_cast<ani_enum_item>(in.channels);
    ani_enum_item aniFormat = reinterpret_cast<ani_enum_item>(in.format);
    ani_enum_item aniEncoding = reinterpret_cast<ani_enum_item>(in.encoding);
    auto aniChannelLayout = reinterpret_cast<ani_enum_item>(in.channelLayout);
    ani_object result {};
    CHECK_RETURN(env->Object_New(cls, ctorMethod, &result, aniSamplingRate, aniChannels, aniFormat,
        aniEncoding, aniChannelLayout) == ANI_OK,
        "Object_New AudioStreamInfoImpl failed", nullptr);
    return result;
}

ani_object TaiheUtils::ToAniImagePixelMap(std::shared_ptr<OHOS::Media::PixelMap> &in)
{
    CHECK_RETURN(in != nullptr, "ToAniImagePixelMap input is null", nullptr);
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);
    return OHOS::Media::PixelMapTaiheAni::CreateEtsPixelMap(env, in);
}

ani_object TaiheUtils::ToAniKeyEvent(const OHOS::MMI::KeyEvent &in)
{
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", nullptr);

    ani_namespace scope {};
    CHECK_RETURN(env->FindNamespace("@ohos.multimedia.avsession.avSession", &scope) == ANI_OK,
        "FindNamespace @ohos.multimedia.avsession.avSession failed", nullptr);

    ani_function function {};
    CHECK_RETURN(env->Namespace_FindFunction(scope, "createAVKeyEventSync", nullptr, &function) == ANI_OK,
        "Namespace_FindFunction createAVKeyEventSync failed", nullptr);

    ani_ref aniRef {};
    CHECK_RETURN(env->Function_Call_Ref(function, &aniRef, reinterpret_cast<ani_long>(&in)) == ANI_OK,
        "Namespace_FindFunction createAVKeyEventSync failed", nullptr);
    return static_cast<ani_object>(aniRef);
}

CastDisplayInfo TaiheUtils::ToTaiheCastDisplayInfo(const OHOS::AVSession::CastDisplayInfo &in)
{
    CastDisplayInfo castDisplayInfo {
        .id = static_cast<int64_t>(in.displayId),
        .name = taihe::string(in.name),
        .state = CastDisplayState::from_value(static_cast<int32_t>(in.displayState)),
        .width = in.width,
        .height = in.height,
    };
    return castDisplayInfo;
}

taihe::array<CastDisplayInfo> TaiheUtils::ToTaiheCastDisplayInfoArray(
    const std::vector<OHOS::AVSession::CastDisplayInfo> &in)
{
    SLOGD("taihe object <- std::vector<CastDisplayInfo> %{public}d", static_cast<int>(in.size()));
    std::vector<CastDisplayInfo> resultVec;
    for (const auto &item : in) {
        CastDisplayInfo result = ToTaiheCastDisplayInfo(item);
        resultVec.emplace_back(result);
    }
    return taihe::array<CastDisplayInfo>(resultVec);
}

AVMediaDescription TaiheUtils::ToTaiheAVMediaDescription(const std::shared_ptr<OHOS::AVSession::AVMediaDescription> &in)
{
    AVMediaDescription out = TaiheMediaDescription::CreateUndefinedAVMediaDescription();
    if (in == nullptr) {
        SLOGD("ToTaiheAVMediaDescription input is null");
        return out;
    }
    TaiheMediaDescription::SetAVMediaDescription(*in, out);
    return out;
}

AVQueueItem TaiheUtils::ToTaiheAVQueueItem(const OHOS::AVSession::AVQueueItem &in)
{
    AVQueueItem out = TaiheQueueItem::CreateUndefinedAVQueueItem();
    TaiheQueueItem::SetAVQueueItem(in, out);
    return out;
}

taihe::array<AVQueueItem> TaiheUtils::ToTaiheAVQueueItemArray(const std::vector<OHOS::AVSession::AVQueueItem> &in)
{
    SLOGD("taihe object <- std::vector<AVQueueItem> %{public}d", static_cast<int>(in.size()));
    std::vector<AVQueueItem> resultVec;
    for (const auto &item : in) {
        AVQueueItem result = ToTaiheAVQueueItem(item);
        resultVec.emplace_back(result);
    }
    return taihe::array<AVQueueItem>(resultVec);
}

AVMetadata TaiheUtils::ToTaiheAVMetaData(const OHOS::AVSession::AVMetaData &in)
{
    AVMetadata out = TaiheMetaData::CreateUndefinedAVMetaData();
    TaiheMetaData::SetAVMetaData(in, out);
    return out;
}

PlaybackPosition TaiheUtils::ToTaihePlaybackPosition(const OHOS::AVSession::AVPlaybackState::Position &in)
{
    PlaybackPosition playbackPosition {
        .elapsedTime = in.elapsedTime_,
        .updateTime = in.updateTime_,
    };
    return playbackPosition;
}

AVPlaybackState TaiheUtils::ToTaiheAVPlaybackState(const OHOS::AVSession::AVPlaybackState &in)
{
    AVPlaybackState out = TaihePlaybackState::CreateUndefinedAVPlaybackState();
    TaihePlaybackState::SetAVPlaybackState(in, out);
    return out;
}

CallMetadata TaiheUtils::ToTaiheAVCallMetaData(const OHOS::AVSession::AVCallMetaData &in)
{
    CallMetadata out = TaiheAVCallMetaData::CreateUndefinedCallMetadata();
    TaiheAVCallMetaData::SetCallMetadata(in, out);
    return out;
}

AVCallState TaiheUtils::ToTaiheAVCallState(const OHOS::AVSession::AVCallState &in)
{
    AVCallState out = TaiheAVCallState::CreateUndefinedAVCallState();
    TaiheAVCallState::SetAVCallState(in, out);
    return out;
}

taihe::array<string> TaiheUtils::ToTaiheStringArray(const std::vector<std::string> &in)
{
    std::vector<string> resultVec;
    for (const auto &item : in) {
        string result(item);
        resultVec.emplace_back(result);
    }
    return taihe::array<string>(resultVec);
}

taihe::array<uint8_t> TaiheUtils::ToTaiheUint8Array(const std::vector<uint8_t> &in)
{
    std::vector<uint8_t> resultVec;
    for (const auto &item : in) {
        resultVec.emplace_back(item);
    }
    return taihe::array<uint8_t>(resultVec);
}

ani_object TaiheUtils::ToBusinessError(ani_env *env, int32_t code, const std::string &message)
{
    CHECK_ERROR_RETURN_RET_LOG(env != nullptr, ani_object {}, "env is nullptr");
    ani_object err {};
    ani_class cls {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->FindClass(CLASS_NAME_BUSINESSERROR, &cls), err,
        "find class %{public}s failed", CLASS_NAME_BUSINESSERROR);
    ani_method ctor {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":", &ctor), err,
        "find method BusinessError constructor failed");
    ani_object error {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Object_New(cls, ctor, &error), err,
        "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    CHECK_ERROR_RETURN_RET_LOG(
        ANI_OK != env->Object_SetPropertyByName_Double(error, "code", static_cast<ani_double>(code)), err,
        "set property BusinessError.code failed");
    ani_string messageRef {};
    CHECK_ERROR_RETURN_RET_LOG(ToAniString(env, message, messageRef) != OHOS::AVSession::AVSESSION_SUCCESS, err,
        "new message string failed");
    CHECK_ERROR_RETURN_RET_LOG(
        ANI_OK != env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)), err,
        "set property BusinessError.message failed");
    return error;
}

taihe::array<AVSessionController> TaiheUtils::ToTaiheAVSessionControllerArray(
    const std::vector<std::shared_ptr<OHOS::AVSession::AVSessionController>> &in)
{
    std::vector<AVSessionController> resultVec;
    for (const auto &item : in) {
        AVSessionController result = make_holder<AVSessionControllerImpl, AVSessionController>();
        AVSessionControllerImpl::NewInstance(item, result);
        resultVec.emplace_back(result);
    }
    return taihe::array<AVSessionController>(resultVec);
}

taihe::array<DecoderType> TaiheUtils::ToTaiheDecoderTypeArray(const std::vector<std::string> &in)
{
    std::vector<DecoderType> resultVec;
    for (const auto &item : in) {
        DecoderType decoderType = DecoderType::from_value(item);
        resultVec.emplace_back(decoderType);
    }
    return taihe::array<DecoderType>(resultVec);
}

static inputEvent::InputEvent ToTaiheInputEvent(const OHOS::MMI::KeyEvent &in)
{
    auto key = in.GetKeyItem();
    bool isNull = (key == std::nullopt);
    inputEvent::InputEvent out = {
        .id = isNull ? 0 : in.GetKeyItem()->GetKeyCode(),
        .deviceId = isNull ? 0 : in.GetKeyItem()->GetDeviceId(),
        .actionTime = isNull ? 0 : in.GetKeyItem()->GetDownTime(),
        .screenId = 0,
        .windowId = 0,
    };
    return out;
}

static keyEvent::Key ToTaiheKey(const std::optional<OHOS::MMI::KeyEvent::KeyItem> &in)
{
    bool isNull = (in == std::nullopt);
    int32_t keyCode = isNull ? OHOS::MMI::KeyEvent::KEYCODE_UNKNOWN : in->GetKeyCode();
    keyEvent::Key out = {
        .code = keyCode::KeyCode::from_value(keyCode),
        .pressedTime = isNull ? 0 : in->GetDownTime(),
        .deviceId = isNull ? 0 : in->GetDeviceId(),
    };
    return out;
}

static taihe::array<keyEvent::Key> ToTaiheKeys(const std::vector<OHOS::MMI::KeyEvent::KeyItem> &in)
{
    std::vector<keyEvent::Key> resultVec;
    for (const auto &item : in) {
        keyEvent::Key result = ToTaiheKey(item);
        resultVec.emplace_back(result);
    }
    return taihe::array<keyEvent::Key>(resultVec);
}

keyEvent::KeyEvent TaiheUtils::ToTaiheKeyEvent(const OHOS::MMI::KeyEvent &in)
{
    auto key = in.GetKeyItem();
    int32_t unicodeChar = (key == std::nullopt) ? 0 : static_cast<int32_t>(key->GetUnicode());
    keyEvent::KeyEvent out = {
        .base = ToTaiheInputEvent(in),
        .action = keyEvent::Action::from_value(in.GetKeyAction()),
        .key = ToTaiheKey(key),
        .unicodeChar = unicodeChar,
        .keys = ToTaiheKeys(in.GetKeyItems()),
        .ctrlKey = false,
        .altKey = false,
        .shiftKey = false,
        .logoKey = false,
        .fnKey = in.GetFunctionKey(OHOS::MMI::KeyEvent::KEYCODE_FN),
        .capsLock = in.GetFunctionKey(OHOS::MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY),
        .numLock = in.GetFunctionKey(OHOS::MMI::KeyEvent::NUM_LOCK_FUNCTION_KEY),
        .scrollLock = in.GetFunctionKey(OHOS::MMI::KeyEvent::SCROLL_LOCK_FUNCTION_KEY),
    };
    return out;
}

AudioCapabilities TaiheUtils::ToTaiheAudioCapabilities(const OHOS::AVSession::AudioCapabilities &in)
{
    AudioCapabilities out {};
    std::vector<uintptr_t> streamInfos {};
    for (const auto &item : in.streamInfos_) {
        ani_object aniObj = ToAniAudioStreamInfo(item);
        streamInfos.emplace_back(reinterpret_cast<uintptr_t>(aniObj));
    }
    out.streamInfos = taihe::array<uintptr_t>(streamInfos);
    return out;
}
} // namespace ANI::AVSession