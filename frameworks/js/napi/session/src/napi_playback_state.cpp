/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "napi_playback_state.h"
#include "napi_utils.h"

namespace OHOS::AVSession {
std::map<std::string, NapiPlaybackState::GetterType> NapiPlaybackState::getterMap_ = {
    { "state", GetState },
    { "speed", GetSpeed },
    { "position", GetPosition },
    { "bufferedTime", GetBufferedTime },
    { "loopMode", GetLoopMode },
    { "isFavorite", GetIsFavorite },
    { "activeItemId", GetActiveItemId },
};

std::map<int32_t, NapiPlaybackState::SetterType> NapiPlaybackState::setterMap_ = {
    { AVPlaybackState::PLAYBACK_KEY_STATE, SetState },
    { AVPlaybackState::PLAYBACK_KEY_SPEED, SetSpeed },
    { AVPlaybackState::PLAYBACK_KEY_POSITION, SetPosition },
    { AVPlaybackState::PLAYBACK_KEY_BUFFERED_TIME, SetBufferedTime },
    { AVPlaybackState::PLAYBACK_KEY_LOOP_MODE, SetLoopMode },
    { AVPlaybackState::PLAYBACK_KEY_IS_FAVORITE, SetIsFavorite },
    { AVPlaybackState::PLAYBACK_KEY_ACTIVE_ITEM_ID, SetActiveItemId },
};

std::map<std::string, int32_t> NapiPlaybackState::filterMap_ = {
    { "state", AVPlaybackState::PLAYBACK_KEY_STATE },
    { "speed", AVPlaybackState::PLAYBACK_KEY_SPEED },
    { "position", AVPlaybackState::PLAYBACK_KEY_POSITION },
    { "bufferedTime", AVPlaybackState::PLAYBACK_KEY_BUFFERED_TIME },
    { "loopMode", AVPlaybackState::PLAYBACK_KEY_LOOP_MODE },
    { "isFavorite", AVPlaybackState::PLAYBACK_KEY_IS_FAVORITE },
    { "activeItemId", AVPlaybackState::PLAYBACK_KEY_ACTIVE_ITEM_ID },
};

napi_status NapiPlaybackState::ConvertFilter(napi_env env, napi_value filter,
                                             AVPlaybackState::PlaybackStateMaskType& mask)
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

napi_status NapiPlaybackState::GetValue(napi_env env, napi_value in, AVPlaybackState& out)
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

napi_status NapiPlaybackState::SetValue(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    auto mask = in.GetMask();
    for (int i = 0; i < AVPlaybackState::PLAYBACK_KEY_MAX; ++i) {
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

napi_status NapiPlaybackState::GetState(napi_env env, napi_value in, AVPlaybackState& out)
{
    int32_t property;
    auto status = NapiUtils::GetNamedProperty(env, in, "state", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetState(property);
    return status;
}

napi_status NapiPlaybackState::SetState(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetState(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "state", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlaybackState::GetSpeed(napi_env env, napi_value in, AVPlaybackState& out)
{
    double property;
    auto status = NapiUtils::GetNamedProperty(env, in, "speed", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetSpeed(property);
    return status;
}

napi_status NapiPlaybackState::SetSpeed(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetSpeed(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "speed", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlaybackState::GetPosition(napi_env env, napi_value in, AVPlaybackState& out)
{
    napi_value result {};
    auto status = napi_get_named_property(env, in, "position", &result);
    CHECK_RETURN((status == napi_ok) && (result != nullptr), "get property failed", status);
    int64_t updateTime {};
    status = NapiUtils::GetNamedProperty(env, result, "updateTime", updateTime);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    int64_t elapsedTime {};
    status = NapiUtils::GetNamedProperty(env, result, "elapsedTime", elapsedTime);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetPosition({elapsedTime, updateTime});
    return status;
}

napi_status NapiPlaybackState::SetPosition(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    napi_value positionProperty {};
    napi_status status = napi_create_object(env, &positionProperty);
    CHECK_RETURN((status == napi_ok) && (positionProperty != nullptr), "create object failed", status);

    auto position = in.GetPosition();
    napi_value elapsedProperty {};
    status = NapiUtils::SetValue(env, position.elapsedTime_, elapsedProperty);
    CHECK_RETURN((status == napi_ok) && (elapsedProperty != nullptr), "create property failed", status);
    status = napi_set_named_property(env, positionProperty, "elapsedTime", elapsedProperty);
    CHECK_RETURN(status == napi_ok, "set property failed", status);

    napi_value updateProperty {};
    status = NapiUtils::SetValue(env, position.updateTime_, updateProperty);
    CHECK_RETURN((status == napi_ok) && (elapsedProperty != nullptr), "create property failed", status);
    status = napi_set_named_property(env, positionProperty, "updateTime", updateProperty);
    CHECK_RETURN(status == napi_ok, "set property failed", status);

    status = napi_set_named_property(env, out, "position", positionProperty);
    CHECK_RETURN(status == napi_ok, "set property failed", status);

    return status;
}

napi_status NapiPlaybackState::GetBufferedTime(napi_env env, napi_value in, AVPlaybackState& out)
{
    int64_t property;
    auto status = NapiUtils::GetNamedProperty(env, in, "bufferedTime", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetBufferedTime(property);
    return status;
}

napi_status NapiPlaybackState::SetBufferedTime(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetBufferedTime(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "bufferedTime", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlaybackState::GetLoopMode(napi_env env, napi_value in, AVPlaybackState& out)
{
    int32_t property;
    auto status = NapiUtils::GetNamedProperty(env, in, "loopMode", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetLoopMode(property);
    return status;
}

napi_status NapiPlaybackState::SetLoopMode(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetLoopMode(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "loopMode", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlaybackState::GetIsFavorite(napi_env env, napi_value in, AVPlaybackState& out)
{
    bool property;
    auto status = NapiUtils::GetNamedProperty(env, in, "isFavorite", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetFavorite(property);
    return status;
}

napi_status NapiPlaybackState::SetIsFavorite(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetFavorite(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "isFavorite", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlaybackState::GetActiveItemId(napi_env env, napi_value in, AVPlaybackState& out)
{
    bool property;
    auto status = NapiUtils::GetNamedProperty(env, in, "activeItemId", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetActiveItemId(property);
    return status;
}

napi_status NapiPlaybackState::SetActiveItemId(napi_env env, const AVPlaybackState& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetActiveItemId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "activeItemId", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}