/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "avmeta_data.h"
#include "avsession_info.h"
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

static napi_value ExportSkipIntervals(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "SECONDS_10", AVMetaData::SECONDS_10);
    (void)SetNamedProperty(env, result, "SECONDS_15", AVMetaData::SECONDS_15);
    (void)SetNamedProperty(env, result, "SECONDS_30", AVMetaData::SECONDS_30);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportAVCastCategory(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "CATEGORY_LOCAL", AVCastCategory::CATEGORY_LOCAL);
    (void)SetNamedProperty(env, result, "CATEGORY_REMOTE", AVCastCategory::CATEGORY_REMOTE);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportProtocolType(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "TYPE_LOCAL", ProtocolType::TYPE_LOCAL);
    (void)SetNamedProperty(env, result, "TYPE_CAST_PLUS_MIRROR", ProtocolType::TYPE_CAST_PLUS_MIRROR);
    (void)SetNamedProperty(env, result, "TYPE_CAST_PLUS_STREAM", ProtocolType::TYPE_CAST_PLUS_STREAM);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportConnectionState(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "STATE_CONNECTING", ConnectionState::STATE_CONNECTING);
    (void)SetNamedProperty(env, result, "STATE_CONNECTED", ConnectionState::STATE_CONNECTED);
    (void)SetNamedProperty(env, result, "STATE_DISCONNECTED", ConnectionState::STATE_DISCONNECTED);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportDeviceType(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "DEVICE_TYPE_LOCAL", DeviceType::DEVICE_TYPE_LOCAL);
    (void)SetNamedProperty(env, result, "DEVICE_TYPE_TV", DeviceType::DEVICE_TYPE_TV);
    (void)SetNamedProperty(env, result, "DEVICE_TYPE_SMART_SPEAKER", DeviceType::DEVICE_TYPE_SMART_SPEAKER);
    (void)SetNamedProperty(env, result, "DEVICE_TYPE_BLUETOOTH", DeviceType::DEVICE_TYPE_BLUETOOTH);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportPlaybackState(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_INITIAL", AVPlaybackState::PLAYBACK_STATE_INITIAL);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_PREPARE", AVPlaybackState::PLAYBACK_STATE_PREPARE);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_PLAY", AVPlaybackState::PLAYBACK_STATE_PLAY);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_PAUSE", AVPlaybackState::PLAYBACK_STATE_PAUSE);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_FAST_FORWARD", AVPlaybackState::PLAYBACK_STATE_FAST_FORWARD);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_REWIND", AVPlaybackState::PLAYBACK_STATE_REWIND);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_STOP", AVPlaybackState::PLAYBACK_STATE_STOP);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_COMPLETED", AVPlaybackState::PLAYBACK_STATE_COMPLETED);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_RELEASED", AVPlaybackState::PLAYBACK_STATE_RELEASED);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_ERROR", AVPlaybackState::PLAYBACK_STATE_ERROR);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportAVSessionErrorCode(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "ERR_CODE_SERVICE_EXCEPTION", AVSessionErrorCode::ERR_CODE_SERVICE_EXCEPTION);
    (void)SetNamedProperty(env, result, "ERR_CODE_SESSION_NOT_EXIST", AVSessionErrorCode::ERR_CODE_SESSION_NOT_EXIST);
    (void)SetNamedProperty(env, result, "ERR_CODE_CONTROLLER_NOT_EXIST",
        AVSessionErrorCode::ERR_CODE_CONTROLLER_NOT_EXIST);
    (void)SetNamedProperty(env, result, "ERR_CODE_REMOTE_CONNECTION_ERR",
        AVSessionErrorCode::ERR_CODE_REMOTE_CONNECTION_ERR);
    (void)SetNamedProperty(env, result, "ERR_CODE_COMMAND_INVALID", AVSessionErrorCode::ERR_CODE_COMMAND_INVALID);
    (void)SetNamedProperty(env, result, "ERR_CODE_SESSION_INACTIVE", AVSessionErrorCode::ERR_CODE_SESSION_INACTIVE);
    (void)SetNamedProperty(env, result, "ERR_CODE_MESSAGE_OVERLOAD", AVSessionErrorCode::ERR_CODE_MESSAGE_OVERLOAD);
    (void)SetNamedProperty(env, result, "ERR_CODE_DEVICE_CONNECTION_FAILED",
        AVSessionErrorCode::ERR_CODE_DEVICE_CONNECTION_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_REMOTE_CONNECTION_NOT_EXIST",
        AVSessionErrorCode::ERR_CODE_REMOTE_CONNECTION_NOT_EXIST);

    napi_object_freeze(env, result);
    return result;
}

napi_status InitEnums(napi_env env, napi_value exports)
{
    const napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("AVCastCategory", ExportAVCastCategory(env)),
        DECLARE_NAPI_PROPERTY("ProtocolType", ExportProtocolType(env)),
        DECLARE_NAPI_PROPERTY("ConnectionState", ExportConnectionState(env)),
        DECLARE_NAPI_PROPERTY("DeviceType", ExportDeviceType(env)),
        DECLARE_NAPI_PROPERTY("LoopMode", ExportLoopMode(env)),
        DECLARE_NAPI_PROPERTY("SkipIntervals", ExportSkipIntervals(env)),
        DECLARE_NAPI_PROPERTY("PlaybackState", ExportPlaybackState(env)),
        DECLARE_NAPI_PROPERTY("AVSessionErrorCode", ExportAVSessionErrorCode(env)),
    };

    size_t count = sizeof(properties) / sizeof(napi_property_descriptor);
    return napi_define_properties(env, exports, count, properties);
}
}