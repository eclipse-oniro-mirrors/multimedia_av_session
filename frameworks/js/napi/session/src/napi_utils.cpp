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

#include <cstdio>

#include "napi_utils.h"
#include "securec.h"
#include "avsession_log.h"
#include "av_session.h"
#include "napi_avcall_meta_data.h"
#include "napi_avcall_state.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_media_description.h"
#include "napi_queue_item.h"
#include "native_engine/native_value.h"
#include "native_engine/native_engine.h"
#include "extension_context.h"
#include "ability_context.h"
#include "napi_common_want.h"
#include "napi_media_info_holder.h"
#include "pixel_map_napi.h"
#include "avsession_pixel_map_adapter.h"
#include "curl/curl.h"
#include "image_source.h"
#include "pixel_map.h"
#include "napi_avsession_controller.h"

namespace OHOS::AVSession {
static constexpr int32_t STR_MAX_LENGTH = 40960;
static constexpr size_t STR_TAIL_LENGTH = 1;

size_t NapiUtils::WriteCallback(std::uint8_t *ptr, size_t size, size_t nmemb, std::vector<std::uint8_t> *imgBuffer)
{
    size_t realsize = size * nmemb;
    imgBuffer->reserve(realsize + imgBuffer->capacity());
    for (size_t i = 0; i < realsize; i++) {
        imgBuffer->push_back(ptr[i]);
    }
    return realsize;
}

bool NapiUtils::CurlSetRequestOptions(std::vector<std::uint8_t>& imgBuffer, const std::string uri)
{
    CURL *easyHandle_ = curl_easy_init();
    if (easyHandle_) {
        // set request options
        curl_easy_setopt(easyHandle_, CURLOPT_URL, uri.c_str());
        curl_easy_setopt(easyHandle_, CURLOPT_CONNECTTIMEOUT, NapiUtils::TIME_OUT_SECOND);
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
            CHECK_AND_RETURN_RET_LOG(httpCode < NapiUtils::HTTP_ERROR_CODE, false, "recv Http ERROR");
            curl_easy_cleanup(easyHandle_);
            easyHandle_ = nullptr;
            return true;
        }
    }
    return false;
}

bool NapiUtils::DoDownloadInCommon(std::shared_ptr<Media::PixelMap>& pixelMap, const std::string uri)
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
        Media::SourceOptions opts;
        SLOGD("DoDownload get size %{public}d", static_cast<int>(imgBuffer.size()));
        auto imageSource = Media::ImageSource::CreateImageSource(buffer, imgBuffer.size(), opts, errorCode);
        free(buffer);
        if (errorCode || !imageSource) {
            SLOGE("DoDownload create imageSource fail: %{public}u", errorCode);
            return false;
        }
        Media::DecodeOptions decodeOpts;
        pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
        if (errorCode || pixelMap == nullptr) {
            SLOGE("DoDownload creatPix fail: %{public}u, %{public}d", errorCode, static_cast<int>(pixelMap != nullptr));
            return false;
        }
        return true;
    }
    return false;
}

int32_t NapiUtils::ConvertSessionType(const std::string& typeString)
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

std::string NapiUtils::ConvertSessionType(int32_t type)
{
    if (type == AVSession::SESSION_TYPE_AUDIO) {
        return "audio";
    } else if (type == AVSession::SESSION_TYPE_VIDEO) {
        return "video";
    } else if (type == AVSession::SESSION_TYPE_VOICE_CALL) {
        return "voice_call";
    } else if (type == AVSession::SESSION_TYPE_VIDEO_CALL) {
        return "video_call";
    } else {
        return "";
    }
}

/* napi_value <-> bool */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, bool& out)
{
    return napi_get_value_bool(env, in, &out);
}

napi_status NapiUtils::SetValue(napi_env env, const bool& in, napi_value& out)
{
    return napi_get_boolean(env, in, &out);
}

/* napi_value <-> int32_t */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, int32_t& out)
{
    return napi_get_value_int32(env, in, &out);
}

napi_status NapiUtils::SetValue(napi_env env, const int32_t& in, napi_value& out)
{
    return napi_create_int32(env, in, &out);
}

/* napi_value <-> uint32_t */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, uint32_t& out)
{
    return napi_get_value_uint32(env, in, &out);
}

napi_status NapiUtils::SetValue(napi_env env, const uint32_t& in, napi_value& out)
{
    return napi_create_uint32(env, in, &out);
}

/* napi_value <-> int64_t */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, int64_t& out)
{
    return napi_get_value_int64(env, in, &out);
}

napi_status NapiUtils::SetValue(napi_env env, const int64_t& in, napi_value& out)
{
    return napi_create_int64(env, in, &out);
}

/* napi_value <-> double */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, double& out)
{
    return napi_get_value_double(env, in, &out);
}

napi_status NapiUtils::SetValue(napi_env env, const double& in, napi_value& out)
{
    return napi_create_double(env, in, &out);
}

/* napi_value <-> std::string */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::string& out)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, in, &type);
    CHECK_RETURN((status == napi_ok) && (type == napi_string), "invalid type", napi_invalid_arg);

    size_t maxLen = STR_MAX_LENGTH;
    status = napi_get_value_string_utf8(env, in, nullptr, 0, &maxLen);
    if (status != napi_ok || maxLen >= STR_MAX_LENGTH) {
        return napi_invalid_arg;
    }

    char buf[STR_MAX_LENGTH + STR_TAIL_LENGTH] {};
    size_t len = 0;
    status = napi_get_value_string_utf8(env, in, buf, maxLen + STR_TAIL_LENGTH, &len);
    if (status == napi_ok) {
        out = std::string(buf);
    }
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::string& in, napi_value& out)
{
    return napi_create_string_utf8(env, in.c_str(), in.size(), &out);
}

/* napi_value <-> AppExecFwk::ElementName */
napi_status NapiUtils::SetValue(napi_env env, const AppExecFwk::ElementName& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    napi_value property = nullptr;
    status = SetValue(env, in.GetDeviceID(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "deviceId", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.GetBundleName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "bundleName", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.GetAbilityName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "abilityName", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    return napi_ok;
}

bool NapiUtils::JudgeNumString(const std::string& str)
{
    std::string tempStr = str;
    return all_of(tempStr.begin(), tempStr.end(), [](char ch) {
        return isdigit(ch);
    });
}

napi_status NapiUtils::SetOutPutDeviceIdValue(napi_env env, const std::vector<std::string>& in, napi_value& out)
{
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN(status == napi_ok, "create array failed!", status);
    int index = 0;
    for (auto& item : in) {
        napi_value element = nullptr;
        if (!JudgeNumString(item)) {
            SLOGE("item is not num string");
            return napi_invalid_arg;
        }
        SetValue(env, static_cast<int32_t>(std::stoi(item)), element);
        status = napi_set_element(env, out, index++, element);
        CHECK_RETURN((status == napi_ok), "napi_set_element failed!", status);
    }
    return status;
}

/* napi_value <-> AVSessionDescriptor */
napi_status NapiUtils::SetValue(napi_env env, const AVSessionDescriptor& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    napi_value property = nullptr;
    status = SetValue(env, in.sessionId_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "sessionId", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, ConvertSessionType(in.sessionType_), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "type", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.sessionTag_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "sessionTag", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.elementName_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "elementName", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.isActive_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "isActive", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.isTopSession_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "isTopSession", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.outputDeviceInfo_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "outputDevice", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    return napi_ok;
}

/* napi_value <-> AVQueueInfo */
napi_status NapiUtils::SetValue(napi_env env, const AVQueueInfo& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    napi_value property = nullptr;
    status = SetValue(env, in.GetBundleName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "bundleName", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.GetAVQueueName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "avQueueName", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.GetAVQueueId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "avQueueId", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);
    
    auto pixelMap = in.GetAVQueueImage();
    if (pixelMap != nullptr) {
        SLOGD(" napi setvalue has avqueueimage");
        property = Media::PixelMapNapi::CreatePixelMap(env, AVSessionPixelMapAdapter::ConvertFromInner(pixelMap));
        status = napi_set_named_property(env, out, "avQueueImage", property);
        CHECK_RETURN(status == napi_ok, "set property failed", status);
    }

    auto uri = in.GetAVQueueImageUri();
    if (!uri.empty()) {
        SLOGD(" napi setvalue has avqueueimageuri");
        status = NapiUtils::SetValue(env, uri, property);
        CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
        status = napi_set_named_property(env, out, "avQueueImage", property);
        CHECK_RETURN(status == napi_ok, "set property failed", status);
    }

    return napi_ok;
}

/* napi_value <-> MMI::KeyEvent::KeyItem */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, MMI::KeyEvent::KeyItem& out)
{
    int32_t code {};
    auto status = GetNamedProperty(env, in, "code", code);
    CHECK_RETURN(status == napi_ok, "get code property failed", status);
    SLOGI("code=%{public}d", code);
    out.SetKeyCode(code);

    int64_t pressedTime {};
    status = GetNamedProperty(env, in, "pressedTime", pressedTime);
    CHECK_RETURN(status == napi_ok, "get pressedTime property failed", status);
    SLOGI("pressedTime=%{public}" PRIu64, pressedTime);
    out.SetDownTime(pressedTime);

    int32_t deviceId {};
    status = GetNamedProperty(env, in, "deviceId", deviceId);
    CHECK_RETURN(status == napi_ok, "get deviceId property failed", status);
    out.SetDeviceId(deviceId);
    out.SetPressed(true);

    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::optional<MMI::KeyEvent::KeyItem> in, napi_value& out)
{
    auto status = napi_create_object(env, &out);
    CHECK_RETURN(status == napi_ok, "create object failed", status);

    napi_value code {};
    CHECK_RETURN(in != std::nullopt, "parameter in of type optional is nullptr", status);
    status = SetValue(env, in->GetKeyCode(), code);
    CHECK_RETURN((status == napi_ok) && (code != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "code", code);
    CHECK_RETURN(status == napi_ok, "set property failed", status);

    napi_value pressedTime {};
    status = SetValue(env, in->GetDownTime(), pressedTime);
    CHECK_RETURN((status == napi_ok) && (pressedTime != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "pressedTime", pressedTime);
    CHECK_RETURN(status == napi_ok, "set property failed", status);

    napi_value deviceId {};
    status = SetValue(env, in->GetDeviceId(), deviceId);
    CHECK_RETURN((status == napi_ok) && (deviceId != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "deviceId", deviceId);
    CHECK_RETURN(status == napi_ok, "set property failed", status);

    return status;
}

/* napi_value <-> MMI::KeyEvent */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::shared_ptr<MMI::KeyEvent>& out)
{
    napi_valuetype valueType = napi_undefined;
    auto status = napi_typeof(env, in, &valueType);
    CHECK_RETURN((status == napi_ok) && (valueType == napi_object), "object type invalid", status);

    out = MMI::KeyEvent::Create();
    CHECK_RETURN(out != nullptr, "create keyEvent failed", napi_generic_failure);

    int32_t action {};
    status = GetNamedProperty(env, in, "action", action);
    CHECK_RETURN(status == napi_ok, "get action property failed", napi_generic_failure);
    SLOGI("action=%{public}d", action);
    action += KEYEVENT_ACTION_JS_NATIVE_DELTA;
    out->SetKeyAction(action);

    MMI::KeyEvent::KeyItem key;
    status = GetNamedProperty(env, in, "key", key);
    CHECK_RETURN(status == napi_ok, "get action property failed", napi_generic_failure);
    out->SetKeyCode(key.GetKeyCode());

    napi_value keyItems {};
    status = napi_get_named_property(env, in, "keys", &keyItems);
    CHECK_RETURN((status == napi_ok) && (keyItems != nullptr), "get keys property failed", status);

    uint32_t length {};
    status = napi_get_array_length(env, keyItems, &length);
    CHECK_RETURN(status == napi_ok, "get array length failed", status);

    for (uint32_t i = 0; i < length; ++i) {
        napi_value keyItem {};
        status = napi_get_element(env, keyItems, i, &keyItem);
        CHECK_RETURN((status == napi_ok) && (keyItem != nullptr), "get element failed", status);
        MMI::KeyEvent::KeyItem item;
        status = GetValue(env, keyItem, item);
        CHECK_RETURN(status == napi_ok, "get KeyItem failed", status);
        if ((key.GetKeyCode() == item.GetKeyCode()) && (action == MMI::KeyEvent::KEY_ACTION_UP)) {
            item.SetPressed(false);
        }
        out->AddKeyItem(item);
    }

    return napi_ok;
}

napi_status NapiUtils::SetValue(napi_env env, const std::shared_ptr<MMI::KeyEvent>& in, napi_value& out)
{
    CHECK_RETURN(in != nullptr, "key event is nullptr", napi_generic_failure);

    auto status = napi_create_object(env, &out);
    CHECK_RETURN(status == napi_ok, "create object failed", status);

    napi_value action {};
    status = SetValue(env, in->GetKeyAction() - KEYEVENT_ACTION_JS_NATIVE_DELTA, action);
    CHECK_RETURN((status == napi_ok) && (action != nullptr), "create action property failed", status);
    status = napi_set_named_property(env, out, "action", action);
    CHECK_RETURN(status == napi_ok, "set action property failed", status);

    napi_value key {};
    CHECK_RETURN(in->GetKeyItem(), "get key item failed", napi_generic_failure);
    status = SetValue(env, in->GetKeyItem(), key);
    CHECK_RETURN((status == napi_ok) && (key != nullptr), "create key property failed", status);
    status = napi_set_named_property(env, out, "key", key);
    CHECK_RETURN(status == napi_ok, "set key property failed", status);

    napi_value keys {};
    status = napi_create_array(env, &keys);
    CHECK_RETURN(status == napi_ok, "create array failed", status);

    uint32_t idx = 0;
    std::vector<MMI::KeyEvent::KeyItem> keyItems = in->GetKeyItems();
    for (const auto& keyItem : keyItems) {
        napi_value item {};
        status = SetValue(env, keyItem, item);
        CHECK_RETURN((status == napi_ok) && (item != nullptr), "create keyItem failed", status);

        status = napi_set_element(env, keys, idx, item);
        CHECK_RETURN(status == napi_ok, "set element failed", status);
        ++idx;
    }

    status = napi_set_named_property(env, out, "keys", keys);
    CHECK_RETURN(status == napi_ok, "set keys property failed", status);
    return status;
}

/* napi_value <-> AbilityRuntime::WantAgent::WantAgent */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AbilityRuntime::WantAgent::WantAgent*& out)
{
    auto status = napi_unwrap(env, in, reinterpret_cast<void**>(&out));
    CHECK_RETURN(status == napi_ok, "unwrap failed", napi_invalid_arg);
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, AbilityRuntime::WantAgent::WantAgent& in, napi_value& out)
{
    auto status = napi_create_object(env, &out);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    auto finalizecb = [](napi_env env, void* data, void* hint) {};
    status = napi_wrap(env, out, static_cast<void*>(&in), finalizecb, nullptr, nullptr);
    CHECK_RETURN(status == napi_ok, "wrap object failed", napi_generic_failure);
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, AbilityRuntime::WantAgent::WantAgent* in, napi_value& out)
{
    auto status = napi_create_object(env, &out);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    auto finalizecb = [](napi_env env, void* data, void* hint) {};
    status = napi_wrap(env, out, static_cast<void*>(in), finalizecb, nullptr, nullptr);
    CHECK_RETURN(status == napi_ok, "wrap object failed", napi_generic_failure);
    return status;
}

/* napi_value <-> AAFwk::WantParams */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AAFwk::WantParams& out)
{
    auto status = AppExecFwk::UnwrapWantParams(env, in, out);
    CHECK_RETURN(status == true, "unwrap object failed", napi_generic_failure);
    return napi_ok;
}

napi_status NapiUtils::SetValue(napi_env env, const AAFwk::WantParams& in, napi_value& out)
{
    auto status = napi_create_object(env, &out);
    CHECK_RETURN(status == napi_ok, "create object failed", napi_generic_failure);
    out = AppExecFwk::WrapWantParams(env, in);
    return status;
}

/* napi_value <-> AVCallMetaData */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVCallMetaData& out)
{
    return NapiAVCallMetaData::GetValue(env, in, out);
}

napi_status NapiUtils::SetValue(napi_env env, const AVCallMetaData& in, napi_value& out)
{
    return NapiAVCallMetaData::SetValue(env, in, out);
}

/* napi_value <-> AVCallState */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVCallState& out)
{
    return NapiAVCallState::GetValue(env, in, out);
}

napi_status NapiUtils::SetValue(napi_env env, const AVCallState& in, napi_value& out)
{
    return NapiAVCallState::SetValue(env, in, out);
}

/* napi_value <-> AVMetaData */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVMetaData& out)
{
    return NapiMetaData::GetValue(env, in, out);
}

napi_status NapiUtils::SetValue(napi_env env, const AVMetaData& in, napi_value& out)
{
    return NapiMetaData::SetValue(env, in, out);
}

/* napi_value <-> AVMediaDescription */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVMediaDescription& out)
{
    return NapiMediaDescription::GetValue(env, in, out);
}

napi_status NapiUtils::SetValue(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    return NapiMediaDescription::SetValue(env, in, out);
}

/* napi_value <-> AVQueueItem */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVQueueItem& out)
{
    return NapiQueueItem::GetValue(env, in, out);
}

napi_status NapiUtils::SetValue(napi_env env, const AVQueueItem& in, napi_value& out)
{
    return NapiQueueItem::SetValue(env, in, out);
}

/* napi_value <-> std::vector<AVQueueItem> */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<AVQueueItem>& out)
{
    uint32_t length {};
    auto status = napi_get_array_length(env, in, &length);
    CHECK_RETURN(status == napi_ok, "get AVQueueItem array length failed", status);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element {};
        status = napi_get_element(env, in, i, &element);
        CHECK_RETURN((status == napi_ok) && (element != nullptr), "get element failed", status);
        AVQueueItem descriptor;
        status = GetValue(env, element, descriptor);
        out.push_back(descriptor);
    }
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::vector<AVQueueItem>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<std::string>");
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN(status == napi_ok, "create AVQueueItem array failed!", status);
    int index = 0;
    for (auto& item : in) {
        napi_value element = nullptr;
        SetValue(env, item, element);
        status = napi_set_element(env, out, index++, element);
        CHECK_RETURN((status == napi_ok), "napi_set_element failed!", status);
    }
    return status;
}

/* napi_value <-> AVPlaybackState */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVPlaybackState& out)
{
    return NapiPlaybackState::GetValue(env, in, out);
}

napi_status NapiUtils::SetValue(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    return NapiPlaybackState::SetValue(env, in, out);
}

/* napi_value <-> AVCastPlayerState */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVCastPlayerState& out)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, in, &type);
    CHECK_RETURN((status == napi_ok) && (type == napi_string), "invalid type", napi_invalid_arg);

    size_t maxLen = STR_MAX_LENGTH;
    status = napi_get_value_string_utf8(env, in, nullptr, 0, &maxLen);
    if (maxLen >= STR_MAX_LENGTH) {
        return napi_invalid_arg;
    }

    char buf[STR_MAX_LENGTH + STR_TAIL_LENGTH] {};
    size_t len = 0;
    status = napi_get_value_string_utf8(env, in, buf, maxLen + STR_TAIL_LENGTH, &len);
    if (status == napi_ok) {
        AVCastPlayerState castPlayerState;
        castPlayerState.castPlayerState_ = std::string(buf);
        out = castPlayerState;
    }
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const AVCastPlayerState& in, napi_value& out)
{
    return napi_create_string_utf8(env, in.castPlayerState_.c_str(), in.castPlayerState_.size(), &out);
}

/* napi_value <-> std::vector<std::string> */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<std::string>& out)
{
    SLOGD("napi_value -> std::vector<std::string>");
    out.clear();
    bool isArray = false;
    napi_is_array(env, in, &isArray);
    CHECK_RETURN(isArray, "not an array", napi_invalid_arg);

    uint32_t length = 0;
    napi_status status = napi_get_array_length(env, in, &length);
    CHECK_RETURN((status == napi_ok) && (length > 0 || length == 0), "get_array failed!", napi_invalid_arg);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        status = napi_get_element(env, in, i, &item);
        CHECK_RETURN((item != nullptr) && (status == napi_ok), "no element", napi_invalid_arg);
        std::string value;
        status = GetValue(env, item, value);
        CHECK_RETURN(status == napi_ok, "not a string", napi_invalid_arg);
        out.push_back(value);
    }
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::vector<std::string>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<std::string>");
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN(status == napi_ok, "create array failed!", status);
    int index = 0;
    for (auto& item : in) {
        napi_value element = nullptr;
        SetValue(env, item, element);
        status = napi_set_element(env, out, index++, element);
        CHECK_RETURN((status == napi_ok), "napi_set_element failed!", status);
    }
    return status;
}

/* napi_value <-> std::vector<uint8_t> */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<uint8_t>& out)
{
    out.clear();
    SLOGD("napi_value -> std::vector<uint8_t> ");
    napi_typedarray_type type = napi_biguint64_array;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    void* data = nullptr;
    napi_status status = napi_get_typedarray_info(env, in, &type, &length, &data, &buffer, &offset);
    SLOGD("array type=%{public}d length=%{public}d offset=%{public}d", static_cast<int>(type), static_cast<int>(length),
          static_cast<int>(offset));
    CHECK_RETURN(status == napi_ok, "napi_get_typedarray_info failed!", napi_invalid_arg);
    CHECK_RETURN(type == napi_uint8_array, "is not Uint8Array!", napi_invalid_arg);
    CHECK_RETURN((length > 0) && (data != nullptr), "invalid data!", napi_invalid_arg);
    out.assign(static_cast<uint8_t*>(data), static_cast<uint8_t*>(data) + length);
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::vector<uint8_t>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<uint8_t> ");
    CHECK_RETURN(!in.empty(), "invalid std::vector<uint8_t>", napi_invalid_arg);
    void* data = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_arraybuffer(env, in.size(), &data, &buffer);
    CHECK_RETURN((status == napi_ok), "create array buffer failed!", status);

    if (memcpy_s(data, in.size(), in.data(), in.size()) != EOK) {
        SLOGE("memcpy_s not EOK");
        return napi_invalid_arg;
    }
    status = napi_create_typedarray(env, napi_uint8_array, in.size(), buffer, 0, &out);
    CHECK_RETURN((status == napi_ok), "napi_value <- std::vector<uint8_t> invalid value", status);
    return status;
}

/* napi_value <-> CastDisplayInfo */
napi_status NapiUtils::SetValue(napi_env env, const CastDisplayInfo& in, napi_value& out)
{
    auto status = napi_create_object(env, &out);
    CHECK_RETURN(status == napi_ok, "create object failed", status);
    napi_value displayState = nullptr;
    napi_create_int32(env, static_cast<int>(in.displayState), &displayState);
    status = napi_set_named_property(env, out, "state", displayState);
    napi_value displayId = nullptr;
    napi_create_int64(env, in.displayId, &displayId);
    status = napi_set_named_property(env, out, "id", displayId);
    napi_value name = nullptr;
    napi_create_string_utf8(env, in.name.c_str(), in.name.size(), &name);
    status = napi_set_named_property(env, out, "name", name);
    napi_value width = nullptr;
    napi_create_int32(env, in.width, &width);
    status = napi_set_named_property(env, out, "width", width);
    napi_value height = nullptr;
    napi_create_int32(env, in.height, &height);
    status = napi_set_named_property(env, out, "height", height);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

/* napi_value <-> CastDisplayInfo Array */
napi_status NapiUtils::SetValue(napi_env env, const std::vector<CastDisplayInfo>& in, napi_value& out)
{
    auto status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN(status == napi_ok, "create CastDisplayInfo Array failed", status);
    int index = 0;
    for (auto& item : in) {
        napi_value element = nullptr;
        SetValue(env, item, element);
        status = napi_set_element(env, out, index++, element);
        CHECK_RETURN(status == napi_ok, "napi_set_element failed", status);
    }
    return status;
}

/* napi_value <-> NapiAVCastPickerOptions */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, NapiAVCastPickerOptions& out)
{
    napi_value value {};
    auto status = napi_get_named_property(env, in, "sessionType", &value);
    CHECK_RETURN(status == napi_ok, "get sessionType failed", status);
    status = GetValue(env, value, out.sessionType);
    CHECK_RETURN(status == napi_ok, "get sessionType value failed", status);

    return napi_ok;
}

template <typename T>
void TypedArray2Vector(uint8_t* data, size_t length, napi_typedarray_type type, std::vector<T>& out)
{
    auto convert = [&out](auto* data, size_t elements) {
        for (size_t index = 0; index < elements; index++) {
            out.push_back(static_cast<T>(data[index]));
        }
    };

    switch (type) {
        case napi_int8_array:
            convert(reinterpret_cast<int8_t*>(data), length);
            break;
        case napi_uint8_array:
            convert(data, length);
            break;
        case napi_uint8_clamped_array:
            convert(data, length);
            break;
        case napi_int16_array:
            convert(reinterpret_cast<int16_t*>(data), length / sizeof(int16_t));
            break;
        case napi_uint16_array:
            convert(reinterpret_cast<uint16_t*>(data), length / sizeof(uint16_t));
            break;
        case napi_int32_array:
            convert(reinterpret_cast<int32_t*>(data), length / sizeof(int32_t));
            break;
        case napi_uint32_array:
            convert(reinterpret_cast<uint32_t*>(data), length / sizeof(uint32_t));
            break;
        case napi_float32_array:
            convert(reinterpret_cast<float*>(data), length / sizeof(float));
            break;
        case napi_float64_array:
            convert(reinterpret_cast<double*>(data), length / sizeof(double));
            break;
        case napi_bigint64_array:
            convert(reinterpret_cast<int64_t*>(data), length / sizeof(int64_t));
            break;
        case napi_biguint64_array:
            convert(reinterpret_cast<uint64_t*>(data), length / sizeof(uint64_t));
            break;
        default:
            CHECK_RETURN_VOID(false, "[FATAL] invalid napi_typedarray_type!");
    }
}

/* napi_value <-> std::vector<int32_t> */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<int32_t>& out)
{
    out.clear();
    SLOGD("napi_value -> std::vector<int32_t> ");
    napi_typedarray_type type = napi_biguint64_array;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    uint8_t* data = nullptr;
    napi_status status = napi_get_typedarray_info(env, in, &type, &length,
                                                  reinterpret_cast<void**>(&data), &buffer, &offset);
    SLOGD("array type=%{public}d length=%{public}d offset=%{public}d", static_cast<int>(type), static_cast<int>(length),
          static_cast<int>(offset));
    CHECK_RETURN(status == napi_ok, "napi_get_typedarray_info failed!", napi_invalid_arg);
    CHECK_RETURN(type <= napi_int32_array, "is not int32 supported typed array!", napi_invalid_arg);
    CHECK_RETURN((length > 0) && (data != nullptr), "invalid data!", napi_invalid_arg);
    TypedArray2Vector<int32_t>(data, length, type, out);
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::vector<int32_t>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<int32_t> ");
    size_t bytes = in.size() * sizeof(int32_t);
    CHECK_RETURN(bytes > 0, "invalid std::vector<int32_t>", napi_invalid_arg);
    void* data = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_arraybuffer(env, bytes, &data, &buffer);
    CHECK_RETURN((status == napi_ok), "invalid buffer", status);

    if (memcpy_s(data, bytes, in.data(), bytes) != EOK) {
        SLOGE("memcpy_s not EOK");
        return napi_invalid_arg;
    }
    status = napi_create_typedarray(env, napi_int32_array, in.size(), buffer, 0, &out);
    CHECK_RETURN((status == napi_ok), "invalid buffer", status);
    return status;
}

/* napi_value <-> std::vector<uint32_t> */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<uint32_t>& out)
{
    out.clear();
    SLOGD("napi_value -> std::vector<uint32_t> ");
    napi_typedarray_type type = napi_biguint64_array;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    uint8_t* data = nullptr;
    napi_status status = napi_get_typedarray_info(env, in, &type, &length,
                                                  reinterpret_cast<void**>(&data), &buffer, &offset);
    SLOGD("napi_get_typedarray_info type=%{public}d", static_cast<int>(type));
    CHECK_RETURN(status == napi_ok, "napi_get_typedarray_info failed!", napi_invalid_arg);
    CHECK_RETURN((type <= napi_uint16_array) || (type == napi_uint32_array), "invalid type!", napi_invalid_arg);
    CHECK_RETURN((length > 0) && (data != nullptr), "invalid data!", napi_invalid_arg);
    TypedArray2Vector<uint32_t>(data, length, type, out);
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::vector<uint32_t>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<uint32_t> ");
    size_t bytes = in.size() * sizeof(uint32_t);
    CHECK_RETURN(bytes > 0, "invalid std::vector<uint32_t>", napi_invalid_arg);
    void* data = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_arraybuffer(env, bytes, &data, &buffer);
    CHECK_RETURN((status == napi_ok), "invalid buffer", status);

    if (memcpy_s(data, bytes, in.data(), bytes) != EOK) {
        SLOGE("memcpy_s not EOK");
        return napi_invalid_arg;
    }
    status = napi_create_typedarray(env, napi_uint32_array, in.size(), buffer, 0, &out);
    CHECK_RETURN((status == napi_ok), "invalid buffer", status);
    return status;
}

/* napi_value <-> std::vector<int64_t> */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<int64_t>& out)
{
    out.clear();
    SLOGD("napi_value -> std::vector<int64_t> ");
    napi_typedarray_type type = napi_biguint64_array;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    uint8_t* data = nullptr;
    napi_status status = napi_get_typedarray_info(env, in, &type, &length,
                                                  reinterpret_cast<void**>(&data), &buffer, &offset);
    SLOGD("array type=%{public}d length=%{public}d offset=%{public}d", static_cast<int>(type), static_cast<int>(length),
          static_cast<int>(offset));
    CHECK_RETURN(status == napi_ok, "napi_get_typedarray_info failed!", napi_invalid_arg);
    CHECK_RETURN((type <= napi_uint32_array) || (type == napi_bigint64_array), "invalid type!", napi_invalid_arg);
    CHECK_RETURN((length > 0) && (data != nullptr), "invalid data!", napi_invalid_arg);
    TypedArray2Vector<int64_t>(data, length, type, out);
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::vector<int64_t>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<int64_t> ");
    size_t bytes = in.size() * sizeof(int64_t);
    CHECK_RETURN(bytes > 0, "invalid std::vector<uint32_t>", napi_invalid_arg);
    void* data = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_arraybuffer(env, bytes, &data, &buffer);
    CHECK_RETURN((status == napi_ok), "invalid buffer", status);

    if (memcpy_s(data, bytes, in.data(), bytes) != EOK) {
        SLOGE("memcpy_s not EOK");
        return napi_invalid_arg;
    }
    status = napi_create_typedarray(env, napi_bigint64_array, in.size(), buffer, 0, &out);
    CHECK_RETURN((status == napi_ok), "invalid buffer", status);
    return status;
}
/* napi_value <-> std::vector<double> */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<double>& out)
{
    out.clear();
    bool isTypedArray = false;
    napi_status status = napi_is_typedarray(env, in, &isTypedArray);
    SLOGD("napi_value -> std::vector<double> input %{public}s a TypedArray", isTypedArray ? "is" : "is not");
    CHECK_RETURN((status == napi_ok), "napi_is_typedarray failed!", status);
    if (isTypedArray) {
        SLOGD("napi_value -> std::vector<double> ");
        napi_typedarray_type type = napi_biguint64_array;
        size_t length = 0;
        napi_value buffer = nullptr;
        size_t offset = 0;
        uint8_t* data = nullptr;
        status = napi_get_typedarray_info(env, in, &type, &length, reinterpret_cast<void**>(&data), &buffer, &offset);
        SLOGD("napi_get_typedarray_info status=%{public}d type=%{public}d", status, static_cast<int>(type));
        CHECK_RETURN(status == napi_ok, "napi_get_typedarray_info failed!", napi_invalid_arg);
        CHECK_RETURN((length > 0) && (data != nullptr), "invalid data!", napi_invalid_arg);
        TypedArray2Vector<double>(data, length, type, out);
    } else {
        bool isArray = false;
        status = napi_is_array(env, in, &isArray);
        SLOGD("napi_value -> std::vector<double> input %{public}s an Array", isArray ? "is" : "is not");
        CHECK_RETURN((status == napi_ok) && isArray, "invalid data!", napi_invalid_arg);
        uint32_t length = 0;
        status = napi_get_array_length(env, in, &length);
        CHECK_RETURN((status == napi_ok) && (length > 0), "invalid data!", napi_invalid_arg);
        for (uint32_t i = 0; i < length; ++i) {
            napi_value item = nullptr;
            status = napi_get_element(env, in, i, &item);
            CHECK_RETURN((item != nullptr) && (status == napi_ok), "no element", napi_invalid_arg);
            double vi = 0.0f;
            status = napi_get_value_double(env, item, &vi);
            CHECK_RETURN(status == napi_ok, "element not a double", napi_invalid_arg);
            out.push_back(vi);
        }
    }
    return status;
}

napi_status NapiUtils::SetValue(napi_env env, const std::vector<double>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<double> ");
    (void)(env);
    (void)(in);
    (void)(out);
    CHECK_RETURN(false, "std::vector<double> to napi_value, unsupported!", napi_invalid_arg);
    return napi_invalid_arg;
}

/* std::vector<AVSessionDescriptor> <-> napi_value */
napi_status NapiUtils::SetValue(napi_env env, const std::vector<AVSessionDescriptor>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<AVSessionDescriptor>  %{public}d", static_cast<int>(in.size()));
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN((status == napi_ok), "create_array failed!", status);
    int index = 0;
    for (const auto& item : in) {
        napi_value entry = nullptr;
        SetValue(env, item, entry);
        napi_set_element(env, out, index++, entry);
    }
    return status;
}

/* std::vector<AVQueueInfo> <-> napi_value */
napi_status NapiUtils::SetValue(napi_env env, const std::vector<AVQueueInfo>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<AVQueueInfo>  %{public}d", static_cast<int>(in.size()));
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN((status == napi_ok), "create_array failed!", status);
    int index = 0;
    for (const auto& item : in) {
        napi_value entry = nullptr;
        SetValue(env, item, entry);
        napi_set_element(env, out, index++, entry);
    }
    return status;
}

/* napi_value <-> std::vector<ResolutionLevel> */
napi_status NapiUtils::SetValue(napi_env env, const std::vector<ResolutionLevel>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<ResolutionLevel>  %{public}d", static_cast<int>(in.size()));
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN((status == napi_ok), "create_array failed!", status);
    int index = 0;
    for (const auto& item : in) {
        napi_value entry = nullptr;
        SetValue(env, item, entry);
        status = napi_set_element(env, out, index++, entry);
        CHECK_RETURN(status == napi_ok, "napi_set_element failed", status);
    }
    return status;
}

/* napi_value <-> std::vector<HDRFormat> */
napi_status NapiUtils::SetValue(napi_env env, const std::vector<HDRFormat>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<HDRFormat>  %{public}d", static_cast<int>(in.size()));
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN((status == napi_ok), "create_array failed!", status);
    int index = 0;
    for (const auto& item : in) {
        napi_value entry = nullptr;
        SetValue(env, item, entry);
        status = napi_set_element(env, out, index++, entry);
        CHECK_RETURN(status == napi_ok, "napi_set_element failed", status);
    }
    return status;
}

/* napi_value <-> std::vector<float> */
napi_status NapiUtils::SetValue(napi_env env, const std::vector<float>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<float>  %{public}d", static_cast<int>(in.size()));
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN((status == napi_ok), "create_array failed!", status);
    int index = 0;
    for (const auto& item : in) {
        napi_value entry = nullptr;
        SetValue(env, item, entry);
        status = napi_set_element(env, out, index++, entry);
        CHECK_RETURN(status == napi_ok, "napi_set_element failed", status);
    }
    return status;
}

/* napi_value <-> DeviceInfo */
napi_status NapiUtils::SetValue(napi_env env, const DeviceInfo& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);
    napi_value property = nullptr;
    status = SetValue(env, in.castCategory_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "castCategory", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.deviceId_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "deviceId", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.manufacturer_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "manufacturer", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.modelName_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "modelName", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.deviceName_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "deviceName", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.deviceType_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "deviceType", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.ipAddress_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "ipAddress", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.networkId_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "networkId", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.providerId_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "providerId", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.supportedProtocols_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "supportedProtocols", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.authenticationStatus_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "authenticationStatus", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.supportedDrmCapabilities_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "supportedDrmCapabilities", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.isLegacy_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "isLegacy", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.mediumTypes_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "mediumTypes", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.audioCapabilities_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "audioCapabilities", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);
    return napi_ok;
}

/* OutputDeviceInfo <-> napi_value */
napi_status NapiUtils::SetValue(napi_env env, const OutputDeviceInfo& in, napi_value& out)
{
    SLOGD("napi_value <- OutputDeviceInfo");
    napi_value temp {};
    napi_create_object(env, &out);

    napi_status status = napi_create_array_with_length(env, in.deviceInfos_.size(), &temp);
    CHECK_RETURN((status == napi_ok), "create_array failed!", status);
    int index = 0;
    SLOGD("The length of deviceInfos is %{public}d", static_cast<int32_t>(in.deviceInfos_.size()));
    for (const auto& item : in.deviceInfos_) {
        napi_value entry = nullptr;
        status = SetValue(env, item, entry);
        CHECK_RETURN((status == napi_ok) && (entry != nullptr), "create array failed!", status);
        napi_set_element(env, temp, index++, entry);
    }
    status = napi_set_named_property(env, out, "devices", temp);
    CHECK_RETURN((status == napi_ok), "set named property devices failed", status);
    return status;
}

napi_status NapiUtils::Unwrap(napi_env env, napi_value in, void** out, napi_value constructor)
{
    if (constructor != nullptr) {
        bool isInstance = false;
        napi_instanceof(env, in, constructor, &isInstance);
        if (!isInstance) {
            SLOGE("not a instance of *");
            return napi_invalid_arg;
        }
    }
    return napi_unwrap(env, in, out);
}

bool NapiUtils::Equals(napi_env env, napi_value value, napi_ref copy)
{
    if (copy == nullptr) {
        return (value == nullptr);
    }

    napi_value copyValue = nullptr;
    napi_get_reference_value(env, copy, &copyValue);
    CHECK_RETURN((napi_get_reference_value(env, copy, &copyValue) == napi_ok),
                 "get ref value failed", napi_generic_failure);
    bool isEquals = false;
    CHECK_RETURN(napi_strict_equals(env, value, copyValue, &isEquals) == napi_ok,
                 "get equals result failed", napi_generic_failure);
    return isEquals;
}

bool NapiUtils::TypeCheck(napi_env env, napi_value value, napi_valuetype expectType)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, value, &valueType);
    if (status != napi_ok || valueType != expectType) {
        return false;
    }
    return true;
}

napi_value NapiUtils::GetUndefinedValue(napi_env env)
{
    napi_value result {};
    napi_get_undefined(env, &result);
    return result;
}

napi_status NapiUtils::GetPropertyNames(napi_env env, napi_value in, std::vector<std::string>& out)
{
    napi_value names {};
    NAPI_CALL_BASE(env, napi_get_property_names(env, in, &names), napi_generic_failure);
    uint32_t length = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, names, &length), napi_generic_failure);

    for (uint32_t index = 0; index < length; ++index) {
        napi_value name {};
        std::string nameString;
        if (napi_get_element(env, names, index, &name) != napi_ok) {
            continue;
        }
        if (GetValue(env, name, nameString) != napi_ok) {
            continue;
        }
        out.push_back(nameString);
    }

    return napi_ok;
}

napi_status NapiUtils::GetDateValue(napi_env env, napi_value value, double& result)
{
    CHECK_RETURN(env != nullptr, "env is nullptr", napi_invalid_arg);
    CHECK_RETURN(value != nullptr, "value is nullptr", napi_invalid_arg);

    SLOGD("GetDateValue in");
    bool isDate = false;
    napi_is_date(env, value, &isDate);
    if (isDate) {
        napi_status status = napi_get_date_value(env, value, &result);
        if (status != napi_ok) {
            SLOGE("get date error");
        }
        SLOGD("GetDateValue out");
        return napi_ok;
    } else {
        SLOGE("value is not date type");
        return napi_date_expected;
    }
}

napi_status NapiUtils::SetDateValue(napi_env env, double time, napi_value& result)
{
    CHECK_RETURN(env != nullptr, "env is nullptr", napi_invalid_arg);

    SLOGD("SetDateValue in");
    napi_status status = napi_create_date(env, time, &result);
    if (status != napi_ok) {
        SLOGE("create date error");
    }
    SLOGD("SetDateValue out");
    return napi_ok;
}

napi_status NapiUtils::GetRefByCallback(napi_env env, std::list<napi_ref> callbackList, napi_value callback,
                                        napi_ref& callbackRef)
{
    for (auto ref = callbackList.begin(); ref != callbackList.end(); ++ref) {
        if (Equals(env, callback, *ref)) {
            SLOGD("Callback has been matched");
            callbackRef = *ref;
            break;
        }
    }
    return napi_ok;
}

/* napi_value is napi stage context */
napi_status NapiUtils::GetStageElementName(napi_env env, napi_value in, AppExecFwk::ElementName& out)
{
    std::shared_ptr<AbilityRuntime::Context> stageContext = AbilityRuntime::GetStageModeContext(env, in);
    CHECK_RETURN(stageContext != nullptr, "get StagContext failed", napi_generic_failure);
    std::shared_ptr <AppExecFwk::AbilityInfo> abilityInfo;
    auto abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(stageContext);
    if (abilityContext != nullptr) {
        abilityInfo = abilityContext->GetAbilityInfo();
    } else {
        auto extensionContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::ExtensionContext>(stageContext);
        CHECK_RETURN(extensionContext != nullptr, "context ConvertTo AbilityContext and ExtensionContext fail",
                     napi_generic_failure);
        abilityInfo = extensionContext->GetAbilityInfo();
    }
    out.SetBundleName(abilityInfo->bundleName);
    out.SetAbilityName(abilityInfo->name);
    return napi_ok;
}

napi_status NapiUtils::GetFaElementName(napi_env env, AppExecFwk::ElementName& out)
{
    auto* ability = AbilityRuntime::GetCurrentAbility(env);
    CHECK_RETURN(ability != nullptr, "get feature ability failed", napi_generic_failure);
    auto want = ability->GetWant();
    CHECK_RETURN(want != nullptr, "get want failed", napi_generic_failure);
    out = want->GetElement();
    return napi_ok;
}

napi_status NapiUtils::GetValue(napi_env env, napi_value in, AppExecFwk::ElementName& out)
{
    bool isStageMode = false;
    CHECK_RETURN(AbilityRuntime::IsStageContext(env, in, isStageMode) == napi_ok, "get context type failed",
                 napi_generic_failure);
    if (isStageMode) {
        CHECK_RETURN(GetStageElementName(env, in, out) == napi_ok, "get StagContext failed", napi_generic_failure);
    } else {
        CHECK_RETURN(GetFaElementName(env, out) == napi_ok, "get FaContext failed", napi_generic_failure);
    }
    return napi_ok;
}

napi_status NapiUtils::GetValue(napi_env env, napi_value in, SessionToken& out)
{
    napi_value value {};
    auto status = napi_get_named_property(env, in, "sessionId", &value);
    CHECK_RETURN(status == napi_ok, "get SessionToken sessionId failed", status);
    status = GetValue(env, value, out.sessionId);
    CHECK_RETURN(status == napi_ok, "get SessionToken sessionId value failed", status);

    bool hasPid = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, in, "pid", &hasPid), napi_invalid_arg);
    if (hasPid) {
        status = napi_get_named_property(env, in, "pid", &value);
        CHECK_RETURN(status == napi_ok, "get SessionToken pid failed", status);
        status = GetValue(env, value, out.pid);
        CHECK_RETURN(status == napi_ok, "get SessionToken pid value failed", status);
    } else {
        out.pid = 0;
    }

    bool hasUid = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, in, "uid", &hasUid), napi_invalid_arg);
    if (hasUid) {
        status = napi_get_named_property(env, in, "uid", &value);
        CHECK_RETURN(status == napi_ok, "get SessionToken uid failed", status);
        status = GetValue(env, value, out.pid);
        CHECK_RETURN(status == napi_ok, "get SessionToken uid value failed", status);
    } else {
        out.uid = 0;
    }
    return napi_ok;
}

napi_status NapiUtils::GetValue(napi_env env, napi_value in, AudioStandard::DeviceRole& out)
{
    int32_t deviceRole;
    auto status = GetValue(env, in, deviceRole);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor deviceRole failed", status);
    out = static_cast<AudioStandard::DeviceRole>(deviceRole);
    return napi_ok;
}

napi_status NapiUtils::GetValue(napi_env env, napi_value in, AudioStandard::DeviceType& out)
{
    int32_t deviceType;
    auto status = GetValue(env, in, deviceType);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor deviceType failed", status);
    out = static_cast<AudioStandard::DeviceType>(deviceType);
    return napi_ok;
}

napi_status NapiUtils::GetSampleRate(napi_env env, napi_value in, AudioStandard::AudioSamplingRate& out)
{
    napi_value value {};
    auto status = napi_get_named_property(env, in, "sampleRates", &value);
    uint32_t length {};
    napi_get_array_length(env, value, &length);
    CHECK_RETURN(status == napi_ok, "get array length failed", status);
    if (length > 0) {
        napi_value element {};
        status = napi_get_element(env, value, 0, &element);
        CHECK_RETURN((status == napi_ok) && (element != nullptr), "get element failed", status);
        int32_t samplingRate;
        status = GetValue(env, element, samplingRate);
        CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor audioStreamInfo_ samplingRate value failed", status);
        out = static_cast<AudioStandard::AudioSamplingRate>(samplingRate);
    }
    return status;
}

napi_status NapiUtils::GetChannels(napi_env env, napi_value in, AudioStandard::AudioChannel& out)
{
    napi_value value {};
    auto status = napi_get_named_property(env, in, "channelCounts", &value);
    uint32_t length {};
    napi_get_array_length(env, value, &length);
    CHECK_RETURN(status == napi_ok, "get array length failed", status);
    if (length > 0) {
        napi_value element {};
        status = napi_get_element(env, value, 0, &element);
        CHECK_RETURN((status == napi_ok) && (element != nullptr), "get element failed", status);
        int32_t channel;
        status = GetValue(env, element, channel);
        CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor audioStreamInfo_ channels value failed", status);
        out = static_cast<AudioStandard::AudioChannel>(channel);
    }
    return status;
}

napi_status NapiUtils::GetChannelMasks(napi_env env, napi_value in, int32_t& out)
{
    napi_value value {};
    auto status = napi_get_named_property(env, in, "channelMasks", &value);
    uint32_t length {};
    napi_get_array_length(env, value, &length);
    CHECK_RETURN(status == napi_ok, "get array length failed", status);
    if (length > 0) {
        napi_value element {};
        status = napi_get_element(env, value, 0, &element);
        CHECK_RETURN((status == napi_ok) && (element != nullptr), "get element failed", status);
        status = GetValue(env, element, out);
        CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor channelMasks_ value failed", status);
    }
    return status;
}

napi_status NapiUtils::GetValue(napi_env env, napi_value in, AudioStandard::AudioDeviceDescriptor& out)
{
    napi_value value {};
    auto status = napi_get_named_property(env, in, "id", &value);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor deviceId_ failed", status);
    status = GetValue(env, value, out.deviceId_);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor deviceId_ value failed", status);

    status = napi_get_named_property(env, in, "name", &value);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor deviceName_ failed", status);
    status = GetValue(env, value, out.deviceName_);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor deviceName_ value failed", status);

    status = napi_get_named_property(env, in, "networkId", &value);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor networkId failed", status);
    status = GetValue(env, value, out.networkId_);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor networkId value failed", status);

    status = napi_get_named_property(env, in, "deviceRole", &value);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor deviceRole_ failed", status);
    status = GetValue(env, value, out.deviceRole_);
    CHECK_RETURN(status == napi_ok, "get AudioDeviceDescriptor deviceRole_ value failed", status);

    if (napi_get_named_property(env, in, "address", &value) == napi_ok) {
        GetValue(env, value, out.macAddress_);
    }

    if (napi_get_named_property(env, in, "deviceType", &value) == napi_ok) {
        GetValue(env, value, out.deviceType_);
    }

    if (napi_get_named_property(env, in, "interruptGroupId", &value) == napi_ok) {
        GetValue(env, value, out.interruptGroupId_);
    }

    if (napi_get_named_property(env, in, "volumeGroupId", &value) == napi_ok) {
        GetValue(env, value, out.volumeGroupId_);
    }

    AudioStandard::AudioSamplingRate audioSamplingRate;
    GetSampleRate(env, in, audioSamplingRate);
    out.audioStreamInfo_.samplingRate = {audioSamplingRate};

    AudioStandard::AudioChannel audioChannel;
    GetChannels(env, in, audioChannel);
    out.audioStreamInfo_.channels = {audioChannel};

    GetChannelMasks(env, in, out.channelMasks_);
    return napi_ok;
}

napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<AudioStandard::AudioDeviceDescriptor>& out)
{
    uint32_t length {};
    auto status = napi_get_array_length(env, in, &length);
    CHECK_RETURN(status == napi_ok, "get array length failed", status);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element {};
        status = napi_get_element(env, in, i, &element);
        CHECK_RETURN((status == napi_ok) && (element != nullptr), "get element failed", status);
        AudioStandard::AudioDeviceDescriptor descriptor;
        status = GetValue(env, element, descriptor);
        out.push_back(descriptor);
    }
    return napi_ok;
}

napi_status NapiUtils::GetOptionalString(napi_env env, napi_value in, DeviceInfo& out)
{
    napi_value value {};
    bool hasIpAddress = false;
    napi_has_named_property(env, in, "ipAddress", &hasIpAddress);
    if (hasIpAddress) {
        napi_status status = napi_get_named_property(env, in, "ipAddress", &value);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo ipAddress failed", status);

        napi_valuetype type = napi_undefined;
        status = napi_typeof(env, value, &type);
        CHECK_RETURN((status == napi_ok) && type == napi_string, "invalid typ for ipAddress", napi_invalid_arg);

        size_t maxLen = STR_MAX_LENGTH;
        status = napi_get_value_string_utf8(env, value, nullptr, 0, &maxLen);
        if (maxLen == 0) {
            out.ipAddress_ = "";
        } else {
            if (maxLen >= static_cast<size_t>(STR_MAX_LENGTH)) {
                return napi_invalid_arg;
            }
            char buf[STR_MAX_LENGTH + STR_TAIL_LENGTH] {};
            size_t len = 0;
            status = napi_get_value_string_utf8(env, value, buf, maxLen + STR_TAIL_LENGTH, &len);
            if (status == napi_ok) {
                out.ipAddress_ = std::string(buf);
            }
        }
        CHECK_RETURN(status == napi_ok, "get DeviceInfo ipAddress value failed", status);
    } else {
        out.ipAddress_ = "";
    }
    return napi_ok;
}

/* napi_value -> DeviceInfo */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, DeviceInfo& out)
{
    napi_value value {};
    auto status = napi_get_named_property(env, in, "castCategory", &value);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo castCategory_ failed", status);
    status = GetValue(env, value, out.castCategory_);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo castCategory_ value failed", status);
    status = napi_get_named_property(env, in, "deviceId", &value);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo deviceId_ failed", status);
    status = GetValue(env, value, out.deviceId_);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo deviceId_ value failed", status);
    status = napi_get_named_property(env, in, "manufacturer", &value);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo manufacturer_ failed", status);
    status = GetValue(env, value, out.manufacturer_);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo manufacturer_ value failed", status);
    status = napi_get_named_property(env, in, "modelName", &value);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo modelName_ failed", status);
    status = GetValue(env, value, out.modelName_);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo modelName_ value failed", status);
    status = napi_get_named_property(env, in, "deviceName", &value);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo deviceName_ failed", status);
    status = GetValue(env, value, out.deviceName_);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo deviceName_ value failed", status);
    status = napi_get_named_property(env, in, "deviceType", &value);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo deviceType_ failed", status);
    status = GetValue(env, value, out.deviceType_);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo deviceType_ value failed", status);
    CHECK_RETURN(GetOptionalString(env, in, out) == napi_ok, "get DeviceInfo ip address value failed", status);
 
    bool hasKey = false;
    napi_has_named_property(env, in, "providerId", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "providerId", &value);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo providerId failed", status);
        status = GetValue(env, value, out.providerId_);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo providerId value failed", status);
    } else {
        out.providerId_ = 0;
    }

    status = ProcessDeviceInfoParams(env, in, out);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo ProcessDeviceInfoParams failed", status);

    status = ProcessDeviceInfoParamsExtra(env, in, out);
    CHECK_RETURN(status == napi_ok, "get DeviceInfo ProcessDeviceInfoParamsExtra failed", status);

    return napi_ok;
}

napi_status NapiUtils::ProcessDeviceInfoParams(napi_env env, napi_value in, DeviceInfo& out)
{
    napi_value value {};
    bool hasKey = false;
    napi_status status = napi_ok;
    napi_has_named_property(env, in, "supportedProtocols", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "supportedProtocols", &value);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo supportedProtocols failed", status);
        status = GetValue(env, value, out.supportedProtocols_);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo supportedProtocols value failed", status);
    } else {
        out.supportedProtocols_ = ProtocolType::TYPE_CAST_PLUS_STREAM;
    }
    napi_has_named_property(env, in, "authenticationStatus", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "authenticationStatus", &value);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo authenticationStatus failed", status);
        status = GetValue(env, value, out.authenticationStatus_);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo authenticationStatus value failed", status);
    } else {
        out.authenticationStatus_ = 0;
    }
    napi_has_named_property(env, in, "supportedDrmCapabilities", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "supportedDrmCapabilities", &value);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo supportedDrmCapabilities failed", status);
        status = GetValue(env, value, out.supportedDrmCapabilities_);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo supportedDrmCapabilities value failed", status);
    }
    napi_has_named_property(env, in, "isLegacy", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "isLegacy", &value);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo isLegacy failed", status);
        status = GetValue(env, value, out.isLegacy_);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo isLegacy value failed", status);
    } else {
        out.isLegacy_ = false;
    }
    napi_has_named_property(env, in, "mediumTypes", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "mediumTypes", &value);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo mediumTypes failed", status);
        status = GetValue(env, value, out.mediumTypes_);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo mediumTypes value failed", status);
    } else {
        out.mediumTypes_ = COAP;
    }
    return napi_ok;
}

napi_status NapiUtils::ProcessDeviceInfoParamsExtra(napi_env env, napi_value in, DeviceInfo& out)
{
    napi_value value {};
    bool hasKey = false;
    napi_status status = napi_ok;
    napi_has_named_property(env, in, "audioCapabilities", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "audioCapabilities", &value);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo audioCapabilities failed", status);
        status = GetValue(env, value, out.audioCapabilities_);
        CHECK_RETURN(status == napi_ok, "get DeviceInfo audioCapabilities value failed", status);
    }
    return napi_ok;
}

/* napi_value -> OutputDeviceInfo */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, OutputDeviceInfo& out)
{
    napi_value devices = nullptr;
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, in, "devices", &hasProperty), napi_invalid_arg);
    if (!hasProperty) {
        SLOGE("devices is not exit in OutputDeviceInfo");
        return napi_invalid_arg;
    }
    NAPI_CALL_BASE(env, napi_get_named_property(env, in, "devices", &devices), napi_invalid_arg);
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, devices, &isArray), napi_invalid_arg);
    if (!isArray) {
        SLOGE("devices is not array");
        return napi_invalid_arg;
    }

    uint32_t arrLen = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, devices, &arrLen), napi_invalid_arg);
    if (arrLen == 0) {
        SLOGE("devices len is invalid");
        return napi_invalid_arg;
    }

    for (uint32_t i = 0; i < arrLen; i++) {
        napi_value item = nullptr;
        NAPI_CALL_BASE(env, napi_get_element(env, devices, i, &item), napi_invalid_arg);
        DeviceInfo deviceInfo;
        napi_status status = GetValue(env, item, deviceInfo);
        CHECK_RETURN(status == napi_ok, "not is device info", status);
        out.deviceInfos_.push_back(deviceInfo);
    }
    return napi_ok;
}

/* napi_value -> MediaInfoHolder */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, MediaInfoHolder& out)
{
    return NapiMediaInfoHolder::GetValue(env, in, out);
}

/* napi_value <-> MediaInfoHolder */
napi_status NapiUtils::SetValue(napi_env env, const MediaInfoHolder& in, napi_value& out)
{
    return NapiMediaInfoHolder::SetValue(env, in, out);
}

/* napi_value -> MediaInfo */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, MediaInfo& out)
{
    napi_value value {};
    auto status = napi_get_named_property(env, in, "mediaId", &value);
    CHECK_RETURN(status == napi_ok, "get mediaId failed", status);
    status = GetValue(env, value, out.mediaId_);
    CHECK_RETURN(status == napi_ok, "get mediaId value failed", status);

    status = napi_get_named_property(env, in, "mediaUrl", &value);
    CHECK_RETURN(status == napi_ok, "get mediaUrl failed", status);
    status = GetValue(env, value, out.mediaUrl_);
    CHECK_RETURN(status == napi_ok, "get mediaUrl value failed", status);

    bool hasStartPosition = false;
    napi_has_named_property(env, in, "startPosition", &hasStartPosition);
    if (hasStartPosition) {
        status = napi_get_named_property(env, in, "startPosition", &value);
        CHECK_RETURN(status == napi_ok, "get MediaInfo startPosition failed", status);
        status = GetValue(env, value, out.startPosition_);
        CHECK_RETURN(status == napi_ok, "get MediaInfo startPosition value failed", status);
    } else {
        out.startPosition_ = -1;
    }
    return napi_ok;
}

/* napi_value <- MediaInfo */
napi_status NapiUtils::SetValue(napi_env env, const MediaInfo& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    napi_value property = nullptr;
    status = SetValue(env, in.mediaId_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "mediaId", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    status = SetValue(env, in.mediaUrl_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "mediaUrl", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    if (in.startPosition_ != -1) {
        status = SetValue(env, in.startPosition_, property);
        CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
        status = napi_set_named_property(env, out, "mediaInfo", property);
        CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);
    }

    return napi_ok;
}

/* napi_value -> AVFileDescriptor */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVFileDescriptor& out)
{
    napi_value value {};
    auto status = napi_ok;
    bool hasFd = false;
    napi_has_named_property(env, in, "fd", &hasFd);
    if (hasFd) {
        status = napi_get_named_property(env, in, "fd", &value);
        CHECK_RETURN(status == napi_ok, "get fd failed", status);
        status = GetValue(env, value, out.fd_);
        CHECK_RETURN(status == napi_ok, "get fd value failed", status);
    } else {
        out.fd_ = 0;
    }

    bool hasOffset = false;
    napi_has_named_property(env, in, "offset", &hasOffset);
    if (hasOffset) {
        status = napi_get_named_property(env, in, "offset", &value);
        CHECK_RETURN(status == napi_ok, "get offset failed", status);
        status = GetValue(env, value, out.offset_);
        CHECK_RETURN(status == napi_ok, "get offset value failed", status);
    } else {
        out.offset_ = 0;
    }

    bool hasLength = false;
    napi_has_named_property(env, in, "length", &hasLength);
    if (hasLength) {
        status = napi_get_named_property(env, in, "length", &value);
        CHECK_RETURN(status == napi_ok, "get length failed", status);
        status = GetValue(env, value, out.length_);
        CHECK_RETURN(status == napi_ok, "get length value failed", status);
    } else {
        out.length_ = -1;
    }
    return napi_ok;
}

/* napi_value <- AVFileDescriptor */
napi_status NapiUtils::SetValue(napi_env env, const AVFileDescriptor& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    napi_value property = nullptr;
    status = SetValue(env, in.fd_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "fd", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);

    if (in.offset_ != 0) {
        status = SetValue(env, in.offset_, property);
        CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
        status = napi_set_named_property(env, out, "offset", property);
        CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);
    }

    if (in.length_ != -1) {
        status = SetValue(env, in.length_, property);
        CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
        status = napi_set_named_property(env, out, "length", property);
        CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);
    }
    return napi_ok;
}

napi_status NapiUtils::GetValue(napi_env env, napi_value in, DistributedSessionType& out)
{
    napi_value value {};
    auto status = napi_ok;
    bool hasSessionType = false;
    int32_t type = -1;
    napi_has_named_property(env, in, "distributedSessionType", &hasSessionType);
    if (hasSessionType) {
        status = napi_get_named_property(env, in, "distributedSessionType", &value);
        CHECK_RETURN(status == napi_ok, "get sessionType failed", status);
        status = GetValue(env, value, type);
        CHECK_RETURN(status == napi_ok, "get sessionType value failed", status);
    }
    out = DistributedSessionType(type);
    return napi_ok;
}
napi_status NapiUtils::SetValue(
    napi_env env, const std::vector<std::shared_ptr<AVSessionController>>& in, napi_value& out)
{
    SLOGD("napi_value <- std::vector<std::shared_ptr<AVSessionController>>  %{public}d", static_cast<int>(in.size()));
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN((status == napi_ok), "create_array failed!", status);
    int index = 0;
    for (const auto& item : in) {
        napi_value entry = nullptr;
        NapiAVSessionController::NewInstance(env, item, entry);
        napi_set_element(env, out, index++, entry);
    }
    return status;
}

/* napi_value -> AVDataSrcDescriptor */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AVDataSrcDescriptor& out)
{
    napi_value value {};
    auto status = napi_ok;
    bool hasFileSize = false;
    status = napi_has_named_property(env, in, "fileSize", &hasFileSize);
    CHECK_RETURN(status == napi_ok && hasFileSize, "get fileSize failed!", status);
    status = napi_get_named_property(env, in, "fileSize", &value);
    CHECK_RETURN(status == napi_ok, "get fileSize failed", status);
    status = GetValue(env, value, out.fileSize);
    CHECK_RETURN(status == napi_ok, "get fileSize value failed", status);

    bool hasCallback = false;
    status = napi_has_named_property(env, in, "callback", &hasCallback);
    CHECK_RETURN(status == napi_ok && hasCallback, "get callback failed!", status);
    out.hasCallback = hasCallback;

    return napi_ok;
}

/* napi_value <- AVDataSrcDescriptor */
napi_status NapiUtils::SetValue(napi_env env, const AVDataSrcDescriptor& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    napi_value property = nullptr;
    status = SetValue(env, in.fileSize, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create object failed", status);
    status = napi_set_named_property(env, out, "fileSize", property);
    CHECK_RETURN(status == napi_ok, "napi_set_named_property failed", status);
    return napi_ok;
}

/* napi_value -> AudioCapabilities */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AudioCapabilities& out)
{
    napi_value value {};
    auto status = napi_ok;
    bool hasKey = false;
    status = napi_has_named_property(env, in, "streamInfos", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "streamInfos", &value);
        CHECK_RETURN(status == napi_ok, "get streamInfos failed", status);
        status = GetValue(env, value, out.streamInfos_);
        CHECK_RETURN(status == napi_ok, "get value streamInfos failed", status);
    }
    return napi_ok;
}

/* napi_value <- AudioCapabilities */
napi_status NapiUtils::SetValue(napi_env env, const AudioCapabilities& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    napi_value property = nullptr;
    status = SetValue(env, in.streamInfos_, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "set streamInfos failed", status);
    status = napi_set_named_property(env, out, "streamInfos", property);
    CHECK_RETURN(status == napi_ok, "set streamInfos property failed", status);
    return napi_ok;
}

/* napi_value -> std::vector<AudioStreamInfo> */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::vector<AudioStreamInfo>& out)
{
    uint32_t length {};
    auto status = napi_get_array_length(env, in, &length);
    CHECK_RETURN(status == napi_ok, "get streamInfos array length failed", status);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element {};
        status = napi_get_element(env, in, i, &element);
        CHECK_RETURN((status == napi_ok) && (element != nullptr), "get element failed", status);
        AudioStreamInfo streamInfo;
        status = GetValue(env, element, streamInfo);
        out.push_back(streamInfo);
    }
    return status;
}

/* napi_value <- std::vector<AudioStreamInfo> */
napi_status NapiUtils::SetValue(napi_env env, const std::vector<AudioStreamInfo>& in, napi_value& out)
{
    napi_status status = napi_create_array_with_length(env, in.size(), &out);
    CHECK_RETURN((status == napi_ok), "create streamInfos array failed!", status);
    int index = 0;
    for (auto& item : in) {
        napi_value element = nullptr;
        SetValue(env, item, element);
        status = napi_set_element(env, out, index++, element);
        CHECK_RETURN((status == napi_ok), "napi_set_element failed!", status);
    }
    return status;
}

/* napi_value -> AudioStreamInfo */
napi_status NapiUtils::GetValue(napi_env env, napi_value in, AudioStreamInfo& out)
{
    napi_value value {};
    auto status = napi_ok;
    bool hasKey = false;
    int audioValue = 0;
    status = napi_has_named_property(env, in, "samplingRate", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "samplingRate", &value);
        CHECK_RETURN(status == napi_ok, "get samplingRate failed", status);
        status = GetValue(env, value, audioValue);
        CHECK_RETURN(status == napi_ok, "get value samplingRate failed", status);
        out.samplingRate = static_cast<AudioSamplingRate>(audioValue);
    }
    status = napi_has_named_property(env, in, "encodingType", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "encodingType", &value);
        CHECK_RETURN(status == napi_ok, "get encodingType failed", status);
        status = GetValue(env, value, audioValue);
        CHECK_RETURN(status == napi_ok, "get value encoding failed", status);
        out.encoding = static_cast<AudioEncodingType>(audioValue);
    }
    status = napi_has_named_property(env, in, "sampleFormat", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "sampleFormat", &value);
        CHECK_RETURN(status == napi_ok, "get sampleFormat failed", status);
        status = GetValue(env, value, audioValue);
        CHECK_RETURN(status == napi_ok, "get value format failed", status);
        out.format = static_cast<AudioSampleFormat>(audioValue);
    }
    status = napi_has_named_property(env, in, "channels", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "channels", &value);
        CHECK_RETURN(status == napi_ok, "get channels failed", status);
        status = GetValue(env, value, audioValue);
        CHECK_RETURN(status == napi_ok, "get value channels failed", status);
        out.channels = static_cast<AudioChannel>(audioValue);
    }
    status = napi_has_named_property(env, in, "channelLayout", &hasKey);
    if (hasKey) {
        status = napi_get_named_property(env, in, "channelLayout", &value);
        CHECK_RETURN(status == napi_ok, "get channelLayout failed", status);
        status = GetValue(env, value, audioValue);
        CHECK_RETURN(status == napi_ok, "get value channelLayout failed", status);
        out.channelLayout = static_cast<AudioChannelLayout>(audioValue);
    }
    return napi_ok;
}

/* napi_value <- AudioStreamInfo */
napi_status NapiUtils::SetValue(napi_env env, const AudioStreamInfo& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    napi_value property = nullptr;
    status = SetValue(env, static_cast<int>(in.samplingRate), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "set samplingRate failed", status);
    status = napi_set_named_property(env, out, "samplingRate", property);
    CHECK_RETURN(status == napi_ok, "set samplingRate property failed", status);

    status = SetValue(env, static_cast<int>(in.encoding), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "set encoding failed", status);
    status = napi_set_named_property(env, out, "encodingType", property);
    CHECK_RETURN(status == napi_ok, "set encodingType property failed", status);

    status = SetValue(env, static_cast<int>(in.format), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "set format failed", status);
    status = napi_set_named_property(env, out, "sampleFormat", property);
    CHECK_RETURN(status == napi_ok, "set sampleFormat property failed", status);

    status = SetValue(env, static_cast<int>(in.channels), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "set channels failed", status);
    status = napi_set_named_property(env, out, "channels", property);
    CHECK_RETURN(status == napi_ok, "set channels property failed", status);

    status = SetValue(env, static_cast<int>(in.channelLayout), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "set channelLayout failed", status);
    status = napi_set_named_property(env, out, "channelLayout", property);
    CHECK_RETURN(status == napi_ok, "set channelLayout property failed", status);
    return napi_ok;
}

napi_status NapiUtils::ThrowError(napi_env env, const char* napiMessage, int32_t napiCode)
{
    napi_value message = nullptr;
    napi_value code = nullptr;
    napi_value result = nullptr;
    napi_create_string_utf8(env, napiMessage, NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &result);
    napi_create_int32(env, napiCode, &code);
    napi_set_named_property(env, result, "code", code);
    napi_throw(env, result);
    return napi_ok;
}
}
