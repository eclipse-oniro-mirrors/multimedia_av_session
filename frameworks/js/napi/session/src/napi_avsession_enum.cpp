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
#include "avcall_state.h"
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

static napi_status SetNamedProperty(napi_env env, napi_value& obj, const std::string& name, const std::string& value)
{
    napi_value property = nullptr;
    napi_status status = napi_create_string_utf8(env, value.c_str(), value.size(), &property);
    if (status != napi_ok) {
        return status;
    }
    status = napi_set_named_property(env, obj, name.c_str(), property);
    if (status != napi_ok) {
        return status;
    }
    return status;
}

static napi_value ExportDecoderType(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "OH_AVCODEC_MIMETYPE_VIDEO_AVC",
        static_cast<std::string>(DecoderType::OH_AVCODEC_MIMETYPE_VIDEO_AVC));
    (void)SetNamedProperty(env, result, "OH_AVCODEC_MIMETYPE_VIDEO_HEVC",
        static_cast<std::string>(DecoderType::OH_AVCODEC_MIMETYPE_VIDEO_HEVC));
    (void)SetNamedProperty(env, result, "OH_AVCODEC_MIMETYPE_AUDIO_VIVID",
        static_cast<std::string>(DecoderType::OH_AVCODEC_MIMETYPE_AUDIO_VIVID));

    napi_object_freeze(env, result);
    return result;
}
    
static napi_value ExportCallerType(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "TYPE_CAST", static_cast<std::string>(CallerType::TYPE_CAST));
    (void)SetNamedProperty(env, result, "TYPE_BLUETOOTH", static_cast<std::string>(CallerType::TYPE_BLUETOOTH));
    (void)SetNamedProperty(env, result, "TYPE_APP", static_cast<std::string>(CallerType::TYPE_APP));

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportResolutionLevel(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "RESOLUTION_480P", static_cast<int32_t>(ResolutionLevel::RESOLUTION_480P));
    (void)SetNamedProperty(env, result, "RESOLUTION_720P", static_cast<int32_t>(ResolutionLevel::RESOLUTION_720P));
    (void)SetNamedProperty(env, result, "RESOLUTION_1080P", static_cast<int32_t>(ResolutionLevel::RESOLUTION_1080P));
    (void)SetNamedProperty(env, result, "RESOLUTION_2K", static_cast<int32_t>(ResolutionLevel::RESOLUTION_2K));
    (void)SetNamedProperty(env, result, "RESOLUTION_4K", static_cast<int32_t>(ResolutionLevel::RESOLUTION_4K));

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportLoopMode(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "LOOP_MODE_SEQUENCE", AVPlaybackState::LOOP_MODE_SEQUENCE);
    (void)SetNamedProperty(env, result, "LOOP_MODE_SINGLE", AVPlaybackState::LOOP_MODE_SINGLE);
    (void)SetNamedProperty(env, result, "LOOP_MODE_LIST", AVPlaybackState::LOOP_MODE_LIST);
    (void)SetNamedProperty(env, result, "LOOP_MODE_SHUFFLE", AVPlaybackState::LOOP_MODE_SHUFFLE);
    (void)SetNamedProperty(env, result, "LOOP_MODE_CUSTOM", AVPlaybackState::LOOP_MODE_CUSTOM);

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
    (void)SetNamedProperty(env, result, "TYPE_DLNA", ProtocolType::TYPE_DLNA);
    (void)SetNamedProperty(env, result, "TYPE_CAST_PLUS_AUDIO", ProtocolType::TYPE_CAST_PLUS_AUDIO);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportConnectionState(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "STATE_CONNECTING", static_cast<int32_t>(ConnectionState::STATE_CONNECTING));
    (void)SetNamedProperty(env, result, "STATE_CONNECTED", static_cast<int32_t>(ConnectionState::STATE_CONNECTED));
    (void)SetNamedProperty(env, result, "STATE_DISCONNECTED",
                           static_cast<int32_t>(ConnectionState::STATE_DISCONNECTED));

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportDeviceType(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "DEVICE_TYPE_LOCAL", DeviceType::DEVICE_TYPE_LOCAL);
    (void)SetNamedProperty(env, result, "DEVICE_TYPE_TV", DeviceType::DEVICE_TYPE_TV);
    (void)SetNamedProperty(env, result, "DEVICE_TYPE_SMART_SPEAKER", DeviceType::DEVICE_TYPE_SPEAKER);
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
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_IDLE", AVPlaybackState::PLAYBACK_STATE_IDLE);
    (void)SetNamedProperty(env, result, "PLAYBACK_STATE_BUFFERING", AVPlaybackState::PLAYBACK_STATE_BUFFERING);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportAVCallState(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "CALL_STATE_IDLE", AVCallState::AVCALL_STATE_IDLE);
    (void)SetNamedProperty(env, result, "CALL_STATE_INCOMING", AVCallState::AVCALL_STATE_INCOMING);
    (void)SetNamedProperty(env, result, "CALL_STATE_ACTIVE", AVCallState::AVCALL_STATE_ACTIVE);
    (void)SetNamedProperty(env, result, "CALL_STATE_DIALING", AVCallState::AVCALL_STATE_DIALING);
    (void)SetNamedProperty(env, result, "CALL_STATE_WAITING", AVCallState::AVCALL_STATE_WAITING);
    (void)SetNamedProperty(env, result, "CALL_STATE_HOLDING", AVCallState::AVCALL_STATE_HOLDING);
    (void)SetNamedProperty(env, result, "CALL_STATE_DISCONNECTING", AVCallState::AVCALL_STATE_DISCONNECTING);

    napi_object_freeze(env, result);
    return result;
}

static void AVSessionControlErrorCode(napi_env env, napi_value result)
{
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_UNSPECIFIED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_UNSPECIFIED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_REMOTE_ERROR",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_REMOTE_ERROR);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_BEHIND_LIVE_WINDOW",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_BEHIND_LIVE_WINDOW);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_TIMEOUT",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_TIMEOUT);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_RUNTIME_CHECK_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_RUNTIME_CHECK_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_PLAYER_NOT_WORKING",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_PLAYER_NOT_WORKING);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_SEEK_MODE_UNSUPPORTED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_SEEK_MODE_UNSUPPORTED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_ILLEGAL_SEEK_TARGET",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_ILLEGAL_SEEK_TARGET);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_PLAY_MODE_UNSUPPORTED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_PLAY_MODE_UNSUPPORTED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_PLAY_SPEED_UNSUPPORTED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_PLAY_SPEED_UNSUPPORTED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DEVICE_MISSING",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DEVICE_MISSING);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_INVALID_PARAM",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_INVALID_PARAM);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_NO_MEMORY",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_NO_MEMORY);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_OPERATION_NOT_ALLOWED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_OPERATION_NOT_ALLOWED);
}

static void AVSessionIOErrorCode(napi_env env, napi_value result)
{
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_UNSPECIFIED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_UNSPECIFIED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_NETWORK_CONNECTION_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_NETWORK_CONNECTION_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_NETWORK_CONNECTION_TIMEOUT",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_NETWORK_CONNECTION_TIMEOUT);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_INVALID_HTTP_CONTENT_TYPE",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_INVALID_HTTP_CONTENT_TYPE);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_BAD_HTTP_STATUS",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_BAD_HTTP_STATUS);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_FILE_NOT_FOUND",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_FILE_NOT_FOUND);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_NO_PERMISSION",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_NO_PERMISSION);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_CLEARTEXT_NOT_PERMITTED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_CLEARTEXT_NOT_PERMITTED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_READ_POSITION_OUT_OF_RANGE",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_READ_POSITION_OUT_OF_RANGE);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_NO_CONTENTS",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_NO_CONTENTS);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_READ_ERROR",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_READ_ERROR);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_CONTENT_BUSY",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_CONTENT_BUSY);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_CONTENT_EXPIRED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_CONTENT_EXPIRED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_USE_FORBIDDEN",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_USE_FORBIDDEN);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_NOT_VERIFIED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_NOT_VERIFIED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_EXHAUSTED_ALLOWED_USES",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_EXHAUSTED_ALLOWED_USES);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_IO_NETWORK_PACKET_SENDING_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_IO_NETWORK_PACKET_SENDING_FAILED);
}

static void AVSessionParsingErrorCode(napi_env env, napi_value result)
{
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_PARSING_UNSPECIFIED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_PARSING_UNSPECIFIED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_PARSING_CONTAINER_MALFORMED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_PARSING_CONTAINER_MALFORMED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_PARSING_MANIFEST_MALFORMED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_PARSING_MANIFEST_MALFORMED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_PARSING_CONTAINER_UNSUPPORTED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_PARSING_CONTAINER_UNSUPPORTED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_PARSING_MANIFEST_UNSUPPORTED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_PARSING_MANIFEST_UNSUPPORTED);
}

static void AVSessionDecodingErrorCode(napi_env env, napi_value result)
{
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DECODING_UNSPECIFIED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DECODING_UNSPECIFIED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DECODING_INIT_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DECODING_INIT_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DECODING_QUERY_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DECODING_QUERY_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DECODING_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DECODING_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DECODING_FORMAT_EXCEEDS_CAPABILITIES",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DECODING_FORMAT_EXCEEDS_CAPABILITIES);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DECODING_FORMAT_UNSUPPORTED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DECODING_FORMAT_UNSUPPORTED);
}

static void AVSessionAudioRenderErrorCode(napi_env env, napi_value result)
{
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_UNSPECIFIED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_UNSPECIFIED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_INIT_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_INIT_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_WRITE_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_AUDIO_RENDERER_WRITE_FAILED);
}

static void AVSessionDRMErrorCode(napi_env env, napi_value result)
{
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_UNSPECIFIED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_UNSPECIFIED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_SCHEME_UNSUPPORTED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_SCHEME_UNSUPPORTED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_PROVISIONING_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_PROVISIONING_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_CONTENT_ERROR",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_CONTENT_ERROR);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_LICENSE_ACQUISITION_FAILED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_LICENSE_ACQUISITION_FAILED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_DISALLOWED_OPERATION",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_DISALLOWED_OPERATION);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_SYSTEM_ERROR",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_SYSTEM_ERROR);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_DEVICE_REVOKED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_DEVICE_REVOKED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_LICENSE_EXPIRED",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_LICENSE_EXPIRED);
    (void)SetNamedProperty(env, result, "ERR_CODE_CAST_CONTROL_DRM_PROVIDE_KEY_RESPONSE_ERROR",
        AVSessionErrorCode::ERR_CODE_CAST_CONTROL_DRM_PROVIDE_KEY_RESPONSE_ERROR);
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
    AVSessionControlErrorCode(env, result);
    AVSessionIOErrorCode(env, result);
    AVSessionParsingErrorCode(env, result);
    AVSessionDecodingErrorCode(env, result);
    AVSessionAudioRenderErrorCode(env, result);
    AVSessionDRMErrorCode(env, result);
    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportDisplayTag(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "TAG_AUDIO_VIVID", AVMetaData::DISPLAY_TAG_AUDIO_VIVID);

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportCastDisplayState(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "STATE_OFF", static_cast<int32_t>(CastDisplayState::STATE_OFF));
    (void)SetNamedProperty(env, result, "STATE_ON", static_cast<int32_t>(CastDisplayState::STATE_ON));

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportDeviceLogEventCode(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "DEVICE_LOG_FULL",
        static_cast<int32_t>(DeviceLogEventCode::DEVICE_LOG_FULL));
    (void)SetNamedProperty(env, result, "DEVICE_LOG_EXCEPTION",
        static_cast<int32_t>(DeviceLogEventCode::DEVICE_LOG_EXCEPTION));

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportDistributedSessionType(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    (void)SetNamedProperty(env, result, "TYPE_SESSION_REMOTE",
        static_cast<int32_t>(DistributedSessionType::TYPE_SESSION_REMOTE));
    (void)SetNamedProperty(env, result, "TYPE_SESSION_MIGRATE_IN",
        static_cast<int32_t>(DistributedSessionType::TYPE_SESSION_MIGRATE_IN));
    (void)SetNamedProperty(env, result, "TYPE_SESSION_MIGRATE_OUT",
        static_cast<int32_t>(DistributedSessionType::TYPE_SESSION_MIGRATE_OUT));

    napi_object_freeze(env, result);
    return result;
}

static napi_value ExportSessionCategory(napi_env env)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok) {
        return nullptr;
    }

    (void)SetNamedProperty(env, result, "CATEGORY_ACTIVE", static_cast<int32_t>(SessionCategory::CATEGORY_ACTIVE));
    (void)SetNamedProperty(env, result, "CATEGORY_NOT_ACTIVE",
        static_cast<int32_t>(SessionCategory::CATEGORY_NOT_ACTIVE));
    (void)SetNamedProperty(env, result, "CATEGORY_ALL", static_cast<int32_t>(SessionCategory::CATEGORY_ALL));

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
        DECLARE_NAPI_PROPERTY("CallState", ExportAVCallState(env)),
        DECLARE_NAPI_PROPERTY("AVSessionErrorCode", ExportAVSessionErrorCode(env)),
        DECLARE_NAPI_PROPERTY("DisplayTag", ExportDisplayTag(env)),
        DECLARE_NAPI_PROPERTY("CastDisplayState", ExportCastDisplayState(env)),
        DECLARE_NAPI_PROPERTY("DeviceLogEventCode", ExportDeviceLogEventCode(env)),
        DECLARE_NAPI_PROPERTY("DistributedSessionType", ExportDistributedSessionType(env)),
        DECLARE_NAPI_PROPERTY("DecoderType", ExportDecoderType(env)),
        DECLARE_NAPI_PROPERTY("ResolutionLevel", ExportResolutionLevel(env)),
        DECLARE_NAPI_PROPERTY("CallerType", ExportCallerType(env)),
        DECLARE_NAPI_PROPERTY("SessionCategory", ExportSessionCategory(env))
    };

    size_t count = sizeof(properties) / sizeof(napi_property_descriptor);
    return napi_define_properties(env, exports, count, properties);
}
}