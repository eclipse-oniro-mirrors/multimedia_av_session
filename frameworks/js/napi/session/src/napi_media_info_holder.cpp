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

#include "napi_media_info_holder.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "napi_utils.h"
#include "pixel_map_napi.h"

namespace OHOS::AVSession {
std::map<std::string, NapiMediaInfoHolder::GetterType> NapiMediaInfoHolder::getterMap_ = {
    { "currentIndex", GetCurrentIndex },
    { "playInfos", GetPlayInfos },
};

std::map<int32_t, NapiMediaInfoHolder::SetterType> NapiMediaInfoHolder::setterMap_ = {
    { MediaInfoHolder::MEDIA_INFO_HOLDER_KEY_CURRENT_INDEX, SetCurrentIndex },
    { MediaInfoHolder::MEDIA_INFO_HOLDER_KEY_PLAY_INFOS, SetPlayInfos },
};

napi_status NapiMediaInfoHolder::GetValue(napi_env env, napi_value in, MediaInfoHolder& out)
{
    bool hasCurrentIndex = false;
    napi_has_named_property(env, in, "currentIndex", &hasCurrentIndex);
    if (!hasCurrentIndex) {
        SLOGE("currentIndex is not exit in MediaInfoHolder");
        return napi_invalid_arg;
    }

    bool hasProperty = false;
    napi_has_named_property(env, in, "playInfos", &hasProperty);
    if (!hasProperty) {
        SLOGE("playInfos is not exit in MediaInfoHolder");
        return napi_invalid_arg;
    }

    std::vector<std::string> propertyNames;
    auto status = NapiUtils::GetPropertyNames(env, in, propertyNames);
    CHECK_RETURN(status == napi_ok, "get property name failed", status);

    for (const auto& name : propertyNames) {
        auto it = getterMap_.find(name);
        if (it == getterMap_.end()) {
            SLOGE("property %{public}s is not of queueitem", name.c_str());
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

napi_status NapiMediaInfoHolder::SetValue(napi_env env, const MediaInfoHolder& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    for (int i = 0; i < MediaInfoHolder::MEDIA_INFO_HOLDER_KEY_MAX; ++i) {
        auto setter = setterMap_[i];
        if (setter(env, in, out) != napi_ok) {
            SLOGE("set property %{public}d failed", i);
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

napi_status NapiMediaInfoHolder::GetCurrentIndex(napi_env env, napi_value in, MediaInfoHolder& out)
{
    int32_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "currentIndex", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetCurrentIndex(property);
    return status;
}

napi_status NapiMediaInfoHolder::SetCurrentIndex(napi_env env, const MediaInfoHolder& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetCurrentIndex(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "currentIndex", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaInfoHolder::GetPlayInfos(napi_env env, napi_value in, MediaInfoHolder& out)
{
    std::vector<AVQueueItem> property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "playInfos", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetPlayInfos(property);
    return status;
}

napi_status NapiMediaInfoHolder::SetPlayInfos(napi_env env, const MediaInfoHolder& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetPlayInfos(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "playInfos", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}
