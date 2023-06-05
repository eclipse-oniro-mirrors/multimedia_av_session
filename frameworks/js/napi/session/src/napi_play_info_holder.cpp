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

#include "napi_play_info_holder.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "napi_utils.h"
#include "pixel_map_napi.h"

namespace OHOS::AVSession {
std::map<std::string, NapiPlayInfoHolder::GetterType> NapiPlayInfoHolder::getterMap_ = {
    { "currentIndex", GetCurrentIndex },
    { "playInfos", GetPlayInfos },
};

std::map<int32_t, NapiPlayInfoHolder::SetterType> NapiPlayInfoHolder::setterMap_ = {
    { PlayInfoHolder::PLAY_INFO_HOLDER_KEY_CURRENT_INDEX, SetCurrentIndex },
    { PlayInfoHolder::PLAY_INFO_HOLDER_KEY_PLAY_INFOS, SetPlayInfos },
};

napi_status NapiPlayInfoHolder::GetValue(napi_env env, napi_value in, PlayInfoHolder& out)
{
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

napi_status NapiPlayInfoHolder::SetValue(napi_env env, const PlayInfoHolder& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    for (int i = 0; i < PlayInfoHolder::PLAY_INFO_HOLDER_KEY_MAX; ++i) {
        auto setter = setterMap_[i];
        if (setter(env, in, out) != napi_ok) {
            SLOGE("set property %{public}d failed", i);
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

napi_status NapiPlayInfoHolder::GetCurrentIndex(napi_env env, napi_value in, PlayInfoHolder& out)
{
    int32_t property;
    auto status = NapiUtils::GetNamedProperty(env, in, "currentIndex", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetCurrentIndex(property);
    return status;
}

napi_status NapiPlayInfoHolder::SetCurrentIndex(napi_env env, const PlayInfoHolder& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetCurrentIndex(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "currentIndex", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfoHolder::GetPlayInfos(napi_env env, napi_value in, PlayInfoHolder& out)
{
    std::vector<std::shared_ptr<PlayInfo>> property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "playInfos", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetPlayInfos(property);
    return status;
}

napi_status NapiPlayInfoHolder::SetPlayInfos(napi_env env, const PlayInfoHolder& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetPlayInfos(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "playInfos", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}
