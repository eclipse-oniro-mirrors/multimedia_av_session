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

#include "napi_avcall_state.h"
#include "napi_utils.h"

namespace OHOS::AVSession {
std::map<std::string, NapiAVCallState::GetterType> NapiAVCallState::getterMap_ = {
    { "state", GetAVCallState },
    { "muted", IsAVCallMuted },
};

std::map<int32_t, NapiAVCallState::SetterType> NapiAVCallState::setterMap_ = {
    { AVCallState::AVCALL_STATE_KEY_STATE, SetAVCallState },
    { AVCallState::AVCALL_STATE_KEY_IS_MUTED, SetAVCallMuted },
};

std::map<std::string, int32_t> NapiAVCallState::filterMap_ = {
    { "state", AVCallState::AVCALL_STATE_KEY_STATE },
    { "muted", AVCallState::AVCALL_STATE_KEY_IS_MUTED },
};

napi_status NapiAVCallState::ConvertFilter(napi_env env, napi_value filter,
    AVCallState::AVCallStateMaskType& mask)
{
    napi_valuetype type = napi_undefined;
    auto status = napi_typeof(env, filter, &type);
    CHECK_RETURN(status == napi_ok, "napi_typeof failed", status);

    if (type == napi_string) {
        std::string stringFilter;
        status = NapiUtils::GetValue(env, filter, stringFilter);
        CHECK_RETURN(status == napi_ok, "get string filter failed", status);
        CHECK_RETURN(stringFilter == "all", "string filter only support all", napi_invalid_arg);

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

napi_status NapiAVCallState::GetValue(napi_env env, napi_value in, AVCallState& out)
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

napi_status NapiAVCallState::SetValue(napi_env env, const AVCallState& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    auto mask = in.GetMask();
    for (int i = 0; i < AVCallState::AVCALL_STATE_KEY_MAX; ++i) {
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

napi_status NapiAVCallState::GetAVCallState(napi_env env, napi_value in, AVCallState& out)
{
    int32_t property;
    auto status = NapiUtils::GetNamedProperty(env, in, "state", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetAVCallState(property);
    return status;
}

napi_status NapiAVCallState::SetAVCallState(napi_env env, const AVCallState& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAVCallState(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "avCallState", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiAVCallState::IsAVCallMuted(napi_env env, napi_value in, AVCallState& out)
{
    bool property;
    auto status = NapiUtils::GetNamedProperty(env, in, "muted", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetAVCallMuted(property);
    return status;
}

napi_status NapiAVCallState::SetAVCallMuted(napi_env env, const AVCallState& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.IsAVCallMuted(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "isAVCallMuted", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}
