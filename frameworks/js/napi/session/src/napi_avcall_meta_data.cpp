/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "napi_avcall_meta_data.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "napi_utils.h"
#include "pixel_map_napi.h"

namespace OHOS::AVSession {
std::map<std::string, NapiAVCallMetaData::GetterType> NapiAVCallMetaData::getterMap_ = {
    {"name", GetName},
    {"phoneNumber", GetPhoneNumber},
    {"avatar", GetMediaImage}
};

std::map<int32_t, NapiAVCallMetaData::SetterType> NapiAVCallMetaData::setterMap_ = {
    {AVCallMetaData::AVCALL_META_KEY_NAME, SetName},
    {AVCallMetaData::AVCALL_META_KEY_PHONE_NUMBER, SetPhoneNumber},
    {AVCallMetaData::AVCALL_META_KEY_MEDIA_IMAGE, SetMediaImage},
    {AVCallMetaData::AVCALL_META_KEY_MEDIA_IMAGE_URI, SetMediaImageUri}
};

std::pair<std::string, int32_t> NapiAVCallMetaData::filterMap_[] = {
    {"name", AVCallMetaData::AVCALL_META_KEY_NAME},
    {"phoneNumber", AVCallMetaData::AVCALL_META_KEY_PHONE_NUMBER},
    {"avatar", AVCallMetaData::AVCALL_META_KEY_MEDIA_IMAGE},
    {"avatar", AVCallMetaData::AVCALL_META_KEY_MEDIA_IMAGE_URI},
};

napi_status NapiAVCallMetaData::ConvertFilter(napi_env env, napi_value filter, AVCallMetaData::AVCallMetaMaskType& mask)
{
    napi_valuetype type = napi_undefined;
    auto status = napi_typeof(env, filter, &type);
    CHECK_RETURN(status == napi_ok, "napi_typeof failed", status);

    if (type == napi_string) {
        std::string stringFilter;
        status = NapiUtils::GetValue(env, filter, stringFilter);
        CHECK_RETURN(status == napi_ok, "get string filter failed", status);
        if (stringFilter != "all") {
            SLOGE("string filter only support all") ;
            return napi_invalid_arg;
        }
        mask.set();
        return napi_ok;
    }

    uint32_t count = 0;
    status = napi_get_array_length(env, filter, &count);
    CHECK_RETURN(status == napi_ok, "get array length failed", status);
    for (uint32_t i = 0; i < count; i++) {
        napi_value value {};
        status = napi_get_element(env, filter, i, &value);
        CHECK_RETURN(status == napi_ok, "get element failed", status);
        std::string metaKey;
        status = NapiUtils::GetValue(env, value, metaKey);
        CHECK_RETURN(status == napi_ok, "get string value failed", status);
        for (const auto& pair : filterMap_) {
            if (pair.first == metaKey) {
                mask.set(pair.second);
            }
        }
    }

    return napi_ok;
}

napi_status NapiAVCallMetaData::GetValue(napi_env env, napi_value in, AVCallMetaData& out)
{
    std::vector<std::string> propertyNames;
    auto status = NapiUtils::GetPropertyNames(env, in, propertyNames);
    CHECK_RETURN(status == napi_ok, "get property name failed", status);

    for (const auto& name : propertyNames) {
        auto it = getterMap_.find(name);
        if (it == getterMap_.end()) {
            SLOGE("property %{public}s is not of metadata", name.c_str());
            return napi_invalid_arg;
        }
        auto getter = it->second;
        if (getter(env, in, out) != napi_ok) {
            SLOGE("get property %{public}s failed", name.c_str());
            return napi_generic_failure;
        }
    }

    return napi_ok;
}

napi_status NapiAVCallMetaData::SetValue(napi_env env, const AVCallMetaData& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    auto mask = in.GetAVCallMetaMask();
    if (mask.none()) {
        SLOGI("undefined meta");
        return SetUndefinedMeta(env, out);
    }

    for (int i = 0; i < AVCallMetaData::AVCALL_META_KEY_MAX; ++i) {
        if (!mask.test(i)) {
            continue;
        }
        auto setter = setterMap_[i];
        if (setter(env, in, out) != napi_ok) {
            SLOGE("set property %{public}d failed", i);
            return napi_generic_failure;
        }
    }

    return napi_ok;
}

napi_status NapiAVCallMetaData::SetUndefinedMeta(napi_env env, napi_value& meta)
{
    auto status = napi_set_named_property(env, meta, "name", NapiUtils::GetUndefinedValue(env));
    CHECK_RETURN(status == napi_ok, "set name to undefined failed", status);
    return napi_ok;
}

napi_status NapiAVCallMetaData::GetName(napi_env env, napi_value in, AVCallMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "name", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetName(property);
    return status;
}

napi_status NapiAVCallMetaData::SetName(napi_env env, const AVCallMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "name", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiAVCallMetaData::GetPhoneNumber(napi_env env, napi_value in, AVCallMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "phoneNumber", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetPhoneNumber(property);
    return status;
}

napi_status NapiAVCallMetaData::SetPhoneNumber(napi_env env, const AVCallMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetPhoneNumber(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "phoneNumber", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiAVCallMetaData::GetMediaImage(napi_env env, napi_value in, AVCallMetaData& out)
{
    napi_value property {};
    auto status = napi_get_named_property(env, in, "avatar", &property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "get property failed", status);
    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, property, &type);
    CHECK_RETURN(status == napi_ok, "get napi_value type failed", status);
    if (type == napi_string) {
        std::string uri;
        status = NapiUtils::GetValue(env, property, uri);
        CHECK_RETURN(status == napi_ok, "get property failed", status);
        out.SetMediaImageUri(uri);
    } else if (type == napi_object) {
        auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, property);
        if (pixelMap == nullptr) {
            SLOGE("unwrap failed");
            return napi_invalid_arg;
        }
        out.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    } else {
        SLOGE("avatar property value type invalid");
        return napi_invalid_arg;
    }

    return status;
}

napi_status NapiAVCallMetaData::SetMediaImage(napi_env env, const AVCallMetaData& in, napi_value& out)
{
    auto pixelMap = in.GetMediaImage();
    if (pixelMap == nullptr) {
        SLOGI("media image is none");
        return napi_ok;
    }

    napi_value property = Media::PixelMapNapi::CreatePixelMap(env,
        AVSessionPixelMapAdapter::ConvertFromInner(pixelMap));
    auto status = napi_set_named_property(env, out, "avatar", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiAVCallMetaData::SetMediaImageUri(napi_env env, const AVCallMetaData& in, napi_value& out)
{
    auto uri = in.GetMediaImageUri();
    if (uri.empty()) {
        SLOGI("media image uri empty");
        return napi_ok;
    }

    napi_value property {};
    auto status = NapiUtils::SetValue(env, uri, property);
    CHECK_RETURN(status == napi_ok, "create property failed", status);
    status = napi_set_named_property(env, out, "avtar", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}
