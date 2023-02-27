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

#include "napi_media_description.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "napi_utils.h"
#include "pixel_map_napi.h"

namespace OHOS::AVSession {
std::map<std::string, NapiMediaDescription::GetterType> NapiMediaDescription::getterMap_ = {
    { "mediaId", GetMediaId },
    { "title", GetTitle },
    { "subtitle", GetSubtitle },
    { "description", GetDescription },
    { "icon",  GetIcon },
    { "iconUri", GetIconUri },
    { "extras", GetExtras },
    { "mediaUri", GetMediaUri },
};

std::map<int32_t, NapiMediaDescription::SetterType> NapiMediaDescription::setterMap_ = {
    { AVMediaDescription::MEDAI_DESCRIPTION_KEY_MEDIA_ID, SetMediaId },
    { AVMediaDescription::MEDAI_DESCRIPTION_KEY_TITLE, SetTitle },
    { AVMediaDescription::MEDAI_DESCRIPTION_KEY_SUBTITLE, SetSubtitle },
    { AVMediaDescription::MEDAI_DESCRIPTION_KEY_DESCRIPTION, SetDescription },
    { AVMediaDescription::MEDAI_DESCRIPTION_KEY_ICON,  SetIcon },
    { AVMediaDescription::MEDAI_DESCRIPTION_KEY_ICON_URI, SetIconUri },
    { AVMediaDescription::MEDAI_DESCRIPTION_KEY_EXTRAS, SetExtras },
    { AVMediaDescription::MEDAI_DESCRIPTION_KEY_MEDIA_URI, SetMediaUri },
};

napi_status NapiMediaDescription::GetValue(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::vector<std::string> propertyNames;
    auto status = NapiUtils::GetPropertyNames(env, in, propertyNames);
    CHECK_RETURN(status == napi_ok, "get property name failed", status);

    for (const auto& name : propertyNames) {
        auto it = getterMap_.find(name);
        if (it == getterMap_.end()) {
            SLOGE("property %{public}s is not of mediadescription", name.c_str());
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

napi_status NapiMediaDescription::SetValue(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    for (int i = 0; i < AVMediaDescription::MEDAI_DESCRIPTION_KEY_MAX; ++i) {
        auto setter = setterMap_[i];
        if (setter(env, in, out) != napi_ok) {
            SLOGE("set property %{public}d failed", i);
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

napi_status NapiMediaDescription::GetMediaId(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaId", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetMediaId(property);
    return status;
}

napi_status NapiMediaDescription::SetMediaId(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetMediaId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaId", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetTitle(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "title", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetTitle(property);
    return status;
}

napi_status NapiMediaDescription::SetTitle(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetTitle(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "title", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetSubtitle(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "subtitle", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetSubtitle(property);
    return status;
}

napi_status NapiMediaDescription::SetSubtitle(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetSubtitle(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "subtitle", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetDescription(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "description", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetDescription(property);
    return status;
}

napi_status NapiMediaDescription::SetDescription(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetDescription(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "description", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetIcon(napi_env env, napi_value in, AVMediaDescription& out)
{
    napi_value property {};
    auto status = napi_get_named_property(env, in, "icon", &property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "get property failed", status);
    auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, property);
    if (pixelMap == nullptr) {
        SLOGE("unwrap failed");
        return napi_invalid_arg;
    }
    out.SetIcon(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    return status;
}

napi_status NapiMediaDescription::SetIcon(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    auto pixelMap = in.GetIcon();
    if (pixelMap == nullptr) {
        SLOGI("media image is null");
        return napi_ok;
    }
    napi_value property = Media::PixelMapNapi::CreatePixelMap(env,
        AVSessionPixelMapAdapter::ConvertFromInner(pixelMap));
    auto status = napi_set_named_property(env, out, "icon", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetIconUri(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "iconUri", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetIconUri(property);
    return status;
}

napi_status NapiMediaDescription::SetIconUri(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetIconUri(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "iconUri", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetExtras(napi_env env, napi_value in, AVMediaDescription& out)
{
    AAFwk::WantParams property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "extras", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetExtras(std::make_shared<AAFwk::WantParams>(property));
    return status;
}

napi_status NapiMediaDescription::SetExtras(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto extras = in.GetExtras();
    if (extras == nullptr) {
        SLOGD("extras is null");
        return napi_ok;
    }
    AAFwk::WantParams params = *extras;
    auto status = NapiUtils::SetValue(env, params, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "extras", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetMediaUri(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaUri", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetMediaUri(property);
    return status;
}

napi_status NapiMediaDescription::SetMediaUri(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetMediaUri(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaUri", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}
