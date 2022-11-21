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

#include <string>

#include "napi/native_common.h"
#include "avcontrol_command.h"
#include "avplayback_state.h"
#include "napi_avsession_enum.h"

namespace OHOS::AVSession {
static napi_status SetNamedProperty(napi_env env, napi_value& obj, const std::string& name, int32_t value)
{
    napi_value property = nullptr;
    napi_status status = napi_create_int32(env, value, &property);
    if (status != napi_ok) {
        return status;
    }
    status = napi_set_named_property(env, obj, name.c_str(), property);
    if (status != napi_ok) {
        return status;
    }
    return status;
}

static napi_value ExportLoopMode(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "LOOP_MODE_SEQUENCE", AVPlaybackState::LOOP_MODE_SEQUENCE);
    (void)SetNamedProperty(env, result, "LOOP_MODE_SINGLE", AVPlaybackState::LOOP_MODE_SINGLE);
    (void)SetNamedProperty(env, result, "LOOP_MODE_LIST", AVPlaybackState::LOOP_MODE_LIST);
    (void)SetNamedProperty(env, result, "LOOP_MODE_SHUFFLE", AVPlaybackState::LOOP_MODE_SHUFFLE);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportPlaybackState(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_INITIAL", AVPlaybackState::PLAYBACK_STATE_INITIAL);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_PREPARE", AVPlaybackState::PLAYBACK_STATE_PREPARING);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_PLAY", AVPlaybackState::PLAYBACK_STATE_PLAYING);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_PAUSE", AVPlaybackState::PLAYBACK_STATE_PAUSED);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_FAST_FORWARD", AVPlaybackState::PLAYBACK_STATE_FAST_FORWARD);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_REWIND", AVPlaybackState::PLAYBACK_STATE_REWIND);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_STOP", AVPlaybackState::PLAYBACK_STATE_STOP);

    napi_object_freeze(env, result);
    return result;
}

napi_status InitEnums(napi_env env, napi_value exports)
{
    const napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("LoopMode", ExportLoopMode(env)),
        DECLARE_NAPI_PROPERTY("PlaybackState", ExportPlaybackState(env)),
    };

    size_t count = sizeof(properties) / sizeof(napi_property_descriptor);
    return napi_define_properties(env, exports, count, properties);
}
}