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

#ifndef OHOS_NAPI_AVCAST_CONTROLLER_CALLBACK_H
#define OHOS_NAPI_AVCAST_CONTROLLER_CALLBACK_H

#include <list>
#include "avsession_info.h"
#include "avsession_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_async_callback.h"
#include "errors.h"

namespace OHOS::AVSession {
using MSErrCode = ErrCode;
class NapiAVCastControllerCallback : public AVCastControllerCallback {
public:
    enum {
        EVENT_CAST_PLAYBACK_STATE_CHANGE,
        EVENT_CAST_MEDIA_ITEM_CHANGE,
        EVENT_CAST_PLAY_NEXT,
        EVENT_CAST_PLAY_PREVIOUS,
        EVENT_CAST_SEEK_DONE,
        EVENT_CAST_VIDEO_SIZE_CHANGE,
        EVENT_CAST_ERROR,
        EVENT_CAST_GENERIC_ERR,
        EVENT_CAST_IO_ERR,
        EVENT_CAST_PARSING_ERR,
        EVENT_CAST_DECOD_EERR,
        EVENT_CAST_RENDER_ERR,
        EVENT_CAST_DRM_ERR,
        EVENT_CAST_END_OF_STREAM,
        EVENT_CAST_PLAY_REQUEST,
        EVENT_CAST_KEY_REQUEST,
        EVENT_CAST_VALID_COMMAND_CHANGED,
        EVENT_CAST_TYPE_MAX,
    };

    // bit 28~21 is subsys, bit 20~16 is Module. bit 15~0 is code
    static constexpr MSErrCode MS_MODULE = 0X01000;
    static constexpr MSErrCode MS_ERR_OFFSET = ErrCodeOffset(30, MS_MODULE); // 30 is SUBSYS_MULTIMEDIA
    // media api9 error code
    enum MediaServiceExtErrCodeAPI9 : ErrCode {
        MSERR_EXT_API9_OK = 0,                          // use for determine error
        MSERR_EXT_API9_NO_PERMISSION = 201,             // permission denied (AccessToken).
        MSERR_EXT_API9_PERMISSION_DENIED = 202,         // permission denied (system API).
        MSERR_EXT_API9_INVALID_PARAMETER = 401,         // invalid parameter.
        MSERR_EXT_API9_UNSUPPORT_CAPABILITY = 801,      // unsupport api.
        MSERR_EXT_API9_NO_MEMORY = 5400101,             // no memory.
        MSERR_EXT_API9_OPERATE_NOT_PERMIT = 5400102,    // opertation not be permitted.
        MSERR_EXT_API9_IO = 5400103,                    // IO error.
        MSERR_EXT_API9_TIMEOUT = 5400104,               // opertate timeout.
        MSERR_EXT_API9_SERVICE_DIED = 5400105,          // media service died.
        MSERR_EXT_API9_UNSUPPORT_FORMAT = 5400106,      // unsupport format.
    };

    // cast api12 error code
    enum CastExtErrCodeAPI12 : ErrCode {
        // Generic error
        CAST_GENERICERR_EXT_API13_UNSPECIFIED = 6611000,
        CAST_GENERICERR_EXT_API13_REMOTE_ERRO,
        CAST_GENERICERR_EXT_API13_BEHIND_LIVE_WINDOW,
        CAST_GENERICERR_EXT_API13_TIMEOUT,
        CAST_GENERICERR_EXT_API13_FAILED_RUNTIME_CHECK,
        CAST_GENERICERR_EXT_API13_PLAYER_ERROR = 6611100,
        CAST_GENERICERR_EXT_API13_SEEK_MODE_UNSUPPORTED,
        CAST_GENERICERR_EXT_API13_ILLEGAL_SEEK_TARGET,
        CAST_GENERICERR_EXT_API13_PLAY_MODE_UNSUPPORTED,
        CAST_GENERICERR_EXT_API13_PLAY_SPEED_UNSUPPORTED,
        CAST_GENERICERR_EXT_API13_DEVICE_MISSED,
        CAST_GENERICERR_EXT_API13_INVALID_PARAM,
        CAST_GENERICERR_EXT_API13_CONNECT_FAILED,
        CAST_GENERICERR_EXT_API13_OPERATION_NOT_ALLOWED,
        // Input/Output errors
        CAST_IOERR_EXT_API13_UNSPECIFIED = 6612000,
        CAST_IOERR_EXT_API13_NETWORK_CONNECTION_FAILED,
        CAST_IOERR_EXT_API13_NETWORK_CONNECTION_TIMEOUT,
        CAST_IOERR_EXT_API13_INVALID_HTTP_CONTENT_TYPE,
        CAST_IOERR_EXT_API13_BAD_HTTP_STATUS,
        CAST_IOERR_EXT_API13_FILE_NOT_FOUND,
        CAST_IOERR_EXT_API13_NO_PERMISSION,
        CAST_IOERR_EXT_API13_CLEARTEXT_NOT_PERMITTED,
        CAST_IOERR_EXT_API13_READ_POSITION_OUT_OF_RANGE,
        CAST_IOERR_EXT_API13_NO_CONTENTS,
        CAST_IOERR_EXT_API13_READ_ERROR,
        CAST_IOERR_EXT_API13_CONTENT_BUSY,
        CAST_IOERR_EXT_API13_CONTENT_EXPIRED,
        CAST_IOERR_EXT_API13_CONTENT_NON_ALLOWED_USE,
        CAST_IOERR_EXT_API13_CONTENT_CANNOT_VERIFIED,
        CAST_IOERR_EXT_API13_CONTENT_EXHAUSTED_ALLOWED_USES,
        CAST_IOERR_EXT_API13_NETWORK_PACKET_SENDING_FAILURE,
        // Content parsing errors
        CAST_PARSINGERR_EXT_API13_UNSPECIFIED = 6613000,
        CAST_PARSINGERR_EXT_API13_CONTAINER_MALFORMED,
        CAST_PARSINGERR_EXT_API13_MANIFEST_MALFORMED,
        CAST_PARSINGERR_EXT_API13_CONTAINER_UNSUPPORTED,
        CAST_PARSINGERR_EXT_API13_MANIFEST_UNSUPPORTED,
        // Decoding errors
        CAST_DECODEERR_EXT_API13_UNSPECIFIED = 6614000,
        CAST_DECODEERR_EXT_API13_INIT_FAILED,
        CAST_DECODEERR_EXT_API13_QUERY_FAILED,
        CAST_DECODEERR_EXT_API13_FAILED,
        CAST_DECODEERR_EXT_API13_FORMAT_EXCEEDS_CAPABILITIES,
        CAST_DECODEERR_EXT_API13_FORMAT_UNSUPPORTED,
        // AudioRender errors
        CAST_RENDERERR_EXT_API13_UNSPECIFIED = 6615000,
        CAST_RENDERERR_EXT_API13_INIT_FAILED,
        CAST_RENDERERR_EXT_API13_WRITE_FAILED,
        // DRM errors
        CAST_DRMERR_EXT_API13_UNSPECIFIED = 6616000,
        CAST_DRMERR_EXT_API13_SCHEME_UNSUPPORTED,
        CAST_DRMERR_EXT_API13_PROVISIONING_FAILED,
        CAST_DRMERR_EXT_API13_CONTENT_ERROR,
        CAST_DRMERR_EXT_API13_LICENSE_ACQUISITION_FAILED,
        CAST_DRMERR_EXT_API13_DISALLOWED_OPERATION,
        CAST_DRMERR_EXT_API13_SYSTEM_ERROR,
        CAST_DRMERR_EXT_API13_DEVICE_REVOKED,
        CAST_DRMERR_EXT_API13_LICENSE_EXPIRED,
        CAST_DRMERR_EXT_API13_PROVIDE_KEY_RESPONSE_ERROR = 6616100,
    };

    enum MediaServiceErrCode : ErrCode {
        MSERR_OK                = ERR_OK,
        MSERR_NO_MEMORY         = MS_ERR_OFFSET + ENOMEM, // no memory
        MSERR_INVALID_OPERATION = MS_ERR_OFFSET + ENOSYS, // opertation not be permitted
        MSERR_INVALID_VAL       = MS_ERR_OFFSET + EINVAL, // invalid argument
        MSERR_UNKNOWN           = MS_ERR_OFFSET + 0x200,  // unkown error.
        MSERR_SERVICE_DIED,                               // media service died
        MSERR_CREATE_REC_ENGINE_FAILED,                   // create recorder engine failed.
        MSERR_CREATE_PLAYER_ENGINE_FAILED,                // create player engine failed.
        MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED,      // create avmetadatahelper engine failed.
        MSERR_CREATE_AVCODEC_ENGINE_FAILED,               // create avcodec engine failed.
        MSERR_INVALID_STATE,                              // the state is not support this operation.
        MSERR_UNSUPPORT,                                  // unsupport interface.
        MSERR_UNSUPPORT_AUD_SRC_TYPE,                     // unsupport audio source type.
        MSERR_UNSUPPORT_AUD_SAMPLE_RATE,                  // unsupport audio sample rate.
        MSERR_UNSUPPORT_AUD_CHANNEL_NUM,                  // unsupport audio channel.
        MSERR_UNSUPPORT_AUD_ENC_TYPE,                     // unsupport audio encoder type.
        MSERR_UNSUPPORT_AUD_PARAMS,                       // unsupport audio params(other params).
        MSERR_UNSUPPORT_VID_SRC_TYPE,                     // unsupport video source type.
        MSERR_UNSUPPORT_VID_ENC_TYPE,                     // unsupport video encoder type.
        MSERR_UNSUPPORT_VID_PARAMS,                       // unsupport video params(other params).
        MSERR_UNSUPPORT_CONTAINER_TYPE,                   // unsupport container format type.
        MSERR_UNSUPPORT_PROTOCOL_TYPE,                    // unsupport protocol type.
        MSERR_UNSUPPORT_VID_DEC_TYPE,                     // unsupport video decoder type.
        MSERR_UNSUPPORT_AUD_DEC_TYPE,                     // unsupport audio decoder type.
        MSERR_UNSUPPORT_STREAM,                           // internal data stream error.
        MSERR_UNSUPPORT_FILE,                             // this appears to be a text file.
        MSERR_UNSUPPORT_SOURCE,                           // unsupport source type.
        MSERR_AUD_RENDER_FAILED,                          // audio render failed.
        MSERR_AUD_ENC_FAILED,                             // audio encode failed.
        MSERR_VID_ENC_FAILED,                             // video encode failed.
        MSERR_AUD_DEC_FAILED,                             // audio decode failed.
        MSERR_VID_DEC_FAILED,                             // video decode failed.
        MSERR_MUXER_FAILED,                               // stream avmuxer failed.
        MSERR_DEMUXER_FAILED,                             // stream demuxer or parser failed.
        MSERR_OPEN_FILE_FAILED,                           // open file failed.
        MSERR_FILE_ACCESS_FAILED,                         // read or write file failed.
        MSERR_START_FAILED,                               // audio/video start failed.
        MSERR_PAUSE_FAILED,                               // audio/video pause failed.
        MSERR_STOP_FAILED,                                // audio/video stop failed.
        MSERR_SEEK_FAILED,                                // audio/video seek failed.
        MSERR_NETWORK_TIMEOUT,                            // network timeout.
        MSERR_NOT_FIND_CONTAINER,                         // not find a demuxer.
        MSERR_DATA_SOURCE_IO_ERROR,                       // media data source IO failed.
        MSERR_DATA_SOURCE_OBTAIN_MEM_ERROR,               // media data source get mem failed.
        MSERR_DATA_SOURCE_ERROR_UNKNOWN,                  // media data source error unknow.
        MSERR_EXTEND_START      = MS_ERR_OFFSET + 0xF000, // extend err start.
    };

    enum CastErrCode : ErrCode {
        // Generic error
        ERROR_CODE_GENERIC_START = 1000,
        ERROR_CODE_UNSPECIFIED = ERROR_CODE_GENERIC_START,
        ERROR_CODE_REMOTE_ERROR,
        ERROR_CODE_BEHIND_LIVE_WINDOW,
        ERROR_CODE_TIMEOUT,
        ERROR_CODE_FAILED_RUNTIME_CHECK,
        ERROR_CODE_PLAYER_ERROR = 1100,
        ERROR_CODE_SEEK_MODE_UNSUPPORTED,
        ERROR_CODE_ILLEGAL_SEEK_TARGET,
        ERROR_CODE_PLAY_MODE_UNSUPPORTED,
        ERROR_CODE_PLAY_SPEED_UNSUPPORTED,
        ERROR_CODE_DEVICE_MISSED,
        ERROR_CODE_INVALID_PARAM,
        ERROR_CODE_NO_MEMORY,
        ERROR_OPERATION_NOT_ALLOWED,
        ERROR_CODE_GENERIC_END = ERROR_OPERATION_NOT_ALLOWED,
        // Input/Output errors
        ERROR_CODE_IO_START = 2000,
        ERROR_CODE_IO_UNSPECIFIED = ERROR_CODE_IO_START,
        ERROR_CODE_IO_NETWORK_CONNECTION_FAILED,
        ERROR_CODE_IO_NETWORK_CONNECTION_TIMEOUT,
        ERROR_CODE_IO_INVALID_HTTP_CONTENT_TYPE,
        ERROR_CODE_IO_BAD_HTTP_STATUS,
        ERROR_CODE_IO_FILE_NOT_FOUND,
        ERROR_CODE_IO_NO_PERMISSION,
        ERROR_CODE_IO_CLEARTEXT_NOT_PERMITTED,
        ERROR_CODE_IO_READ_POSITION_OUT_OF_RANGE,
        ERROR_CODE_IO_NO_CONTENTS,
        ERROR_CODE_IO_READ_ERROR,
        ERROR_CODE_IO_CONTENT_BUSY,
        ERROR_CODE_IO_CONTENT_EXPIRED,
        ERROR_CODE_IO_CONTENT_NON_ALLOWED_USE,
        ERROR_CODE_IO_CONTENT_CANNOT_VERIFIED,
        ERROR_CODE_IO_CONTENT_EXHAUSTED_ALLOWED_USES,
        ERROR_CODE_IO_NETWORK_PACKET_SENDING_FAILURE,
        ERROR_CODE_IO_END = ERROR_CODE_IO_NETWORK_PACKET_SENDING_FAILURE,
        // Content parsing errors
        ERROR_CODE_PARSING_START = 3000,
        ERROR_CODE_PARSING_UNSPECIFIED = ERROR_CODE_PARSING_START,
        ERROR_CODE_PARSING_CONTAINER_MALFORMED,
        ERROR_CODE_PARSING_MANIFEST_MALFORMED,
        ERROR_CODE_PARSING_CONTAINER_UNSUPPORTED,
        ERROR_CODE_PARSING_MANIFEST_UNSUPPORTED,
        ERROR_CODE_PARSING_END = ERROR_CODE_PARSING_MANIFEST_UNSUPPORTED,
        // Decoding errors
        ERROR_CODE_DECODE_START = 4000,
        ERROR_CODE_DECODE_UNSPECIFIED = ERROR_CODE_DECODE_START,
        ERROR_CODE_DECODER_INIT_FAILED,
        ERROR_CODE_DECODER_QUERY_FAILED,
        ERROR_CODE_DECODING_FAILED,
        ERROR_CODE_DECODING_FORMAT_EXCEEDS_CAPABILITIES,
        ERROR_CODE_DECODING_FORMAT_UNSUPPORTED,
        ERROR_CODE_DECODE_END = ERROR_CODE_DECODING_FORMAT_UNSUPPORTED,
        // AudioRender errors
        ERROR_CODE_AUDIO_RENDERS_START = 5000,
        ERROR_CODE_AUDIO_RENDERS_UNSPECIFIED = ERROR_CODE_AUDIO_RENDERS_START,
        ERROR_CODE_AUDIO_RENDERS_INIT_FAILED,
        ERROR_CODE_AUDIO_RENDERS_WRITE_FAILED,
        ERROR_CODE_AUDIO_RENDERS_END = ERROR_CODE_AUDIO_RENDERS_WRITE_FAILED,
        // DRM errors
        ERROR_CODE_DRM_START = 6000,
        ERROR_CODE_DRM_UNSPECIFIED = ERROR_CODE_DRM_START,
        ERROR_CODE_DRM_SCHEME_UNSUPPORTED,
        ERROR_CODE_DRM_PROVISIONING_FAILED,
        ERROR_CODE_DRM_CONTENT_ERROR,
        ERROR_CODE_DRM_LICENSE_ACQUISITION_FAILED,
        ERROR_CODE_DRM_DISALLOWED_OPERATION,
        ERROR_CODE_DRM_SYSTEM_ERROR,
        ERROR_CODE_DRM_DEVICE_REVOKED,
        ERROR_CODE_DRM_LICENSE_EXPIRED,
        ERROR_CODE_DRM_PROVIDE_KEY_RESPONSE_ERROR,
        ERROR_CODE_DRM_END = ERROR_CODE_DRM_PROVIDE_KEY_PESPONSE_ERROR,
    };

    const std::map<MediaServiceErrCode, std::string> MSERRCODE_INFOS = {
        {MSERR_OK, "success"},
        {MSERR_NO_MEMORY, "no memory"},
        {MSERR_INVALID_OPERATION, "operation not be permitted"},
        {MSERR_INVALID_VAL, "invalid argument"},
        {MSERR_UNKNOWN, "unkown error"},
        {MSERR_SERVICE_DIED, "media service died"},
        {MSERR_CREATE_REC_ENGINE_FAILED, "create recorder engine failed"},
        {MSERR_CREATE_PLAYER_ENGINE_FAILED, "create player engine failed"},
        {MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED, "create avmetadatahelper engine failed"},
        {MSERR_INVALID_STATE, "the state is not support this operation"},
        {MSERR_UNSUPPORT, "unsupport interface"},
        {MSERR_UNSUPPORT_AUD_SRC_TYPE, "unsupport audio source type"},
        {MSERR_UNSUPPORT_AUD_SAMPLE_RATE, "unsupport audio sample rate"},
        {MSERR_UNSUPPORT_AUD_CHANNEL_NUM, "unsupport audio channel"},
        {MSERR_UNSUPPORT_AUD_ENC_TYPE, "unsupport audio encoder type"},
        {MSERR_UNSUPPORT_AUD_PARAMS, "unsupport audio params(other params)"},
        {MSERR_UNSUPPORT_VID_SRC_TYPE, "unsupport video source type"},
        {MSERR_UNSUPPORT_VID_ENC_TYPE, "unsupport video encoder type"},
        {MSERR_UNSUPPORT_VID_PARAMS, "unsupport video params(other params)"},
        {MSERR_UNSUPPORT_CONTAINER_TYPE, "unsupport container format type"},
        {MSERR_UNSUPPORT_PROTOCOL_TYPE, "unsupport protocol type"},
        {MSERR_UNSUPPORT_VID_DEC_TYPE, "unsupport video decoder type"},
        {MSERR_UNSUPPORT_AUD_DEC_TYPE, "unsupport audio decoder type"},
        {MSERR_UNSUPPORT_STREAM, "internal data stream error"},
        {MSERR_UNSUPPORT_FILE, "this appears to be a text file"},
        {MSERR_UNSUPPORT_SOURCE, "unsupport source type"},
        {MSERR_AUD_ENC_FAILED, "audio encode failed"},
        {MSERR_AUD_RENDER_FAILED, "audio render failed"},
        {MSERR_VID_ENC_FAILED, "video encode failed"},
        {MSERR_AUD_DEC_FAILED, "audio decode failed"},
        {MSERR_VID_DEC_FAILED, "video decode failed"},
        {MSERR_MUXER_FAILED, "stream avmuxer failed"},
        {MSERR_DEMUXER_FAILED, "stream demuxer or parser failed"},
        {MSERR_OPEN_FILE_FAILED, "open file failed"},
        {MSERR_FILE_ACCESS_FAILED, "read or write file failed"},
        {MSERR_START_FAILED, "audio or video start failed"},
        {MSERR_PAUSE_FAILED, "audio or video pause failed"},
        {MSERR_STOP_FAILED, "audio or video stop failed"},
        {MSERR_SEEK_FAILED, "audio or video seek failed"},
        {MSERR_NETWORK_TIMEOUT, "network timeout"},
        {MSERR_NOT_FIND_CONTAINER, "not find a demuxer"},
        {MSERR_EXTEND_START, "extend start error code"},
    };

    // Generic error
    const std::map<CastErrCode, std::string> CAST_GENERIC_ERRCODE_INFOS = {
        {ERROR_CODE_UNSPECIFIED, "The error code for cast control is unspecified"},
        {ERROR_CODE_REMOTE_ERROR, "An unspecified error occurs in the remote player"},
        {ERROR_CODE_BEHIND_LIVE_WINDOW, "The playback position falls behind the live window"},
        {ERROR_CODE_TIMEOUT, "The process of cast contorl times out"},
        {ERROR_CODE_FAILED_RUNTIME_CHECK, "The runtime check failed"},
        {ERROR_CODE_PLAYER_ERROR, "Cross-device data transmission is locked"},
        {ERROR_CODE_SEEK_MODE_UNSUPPORTED, "The specified seek mode is not supported"},
        {ERROR_CODE_ILLEGAL_SEEK_TARGET, "The position to seek to is out of the range of the media\
            asset or the specified seek mode is not supported"},
        {ERROR_CODE_PLAY_MODE_UNSUPPORTED, "The specified playback mode is not supported"},
        {ERROR_CODE_PLAY_SPEED_UNSUPPORTED, "The specified playback speed is not supported"},
        {ERROR_CODE_DEVICE_MISSED, "The action failed because either the media source devce or the\
            media sink device has been revoked"},
        {ERROR_CODE_INVALID_PARAM, "The parameter is invalid, for example, the url is illegal to play"},
        {ERROR_CODE_NO_MEMORY, "Allocation of memory failed"},
        {ERROR_OPERATION_NOT_ALLOWED, ""},
    };
    // Input/Output errors
    const std::map<CastErrCode, std::string> CAST_IO_ERRCODE_INFOS = {
        {ERROR_CODE_IO_UNSPECIFIED, "An unspecified input/output error occurs"},
        {ERROR_CODE_IO_NETWORK_CONNECTION_FAILED, "Network connection failure"},
        {ERROR_CODE_IO_NETWORK_CONNECTION_TIMEOUT, "Network timeout"},
        {ERROR_CODE_IO_INVALID_HTTP_CONTENT_TYPE, "Invalid \"Content-Type\" HTTP header"},
        {ERROR_CODE_IO_BAD_HTTP_STATUS, "The HTTP server returns an unexpected HTTP response status code"},
        {ERROR_CODE_IO_FILE_NOT_FOUND, "The file does not exist"},
        {ERROR_CODE_IO_NO_PERMISSION, "No permission is granted to perform the IO operation"},
        {ERROR_CODE_IO_CLEARTEXT_NOT_PERMITTED, "Access to cleartext HTTP traffic is not allowed by the\
            app's network security configuration"},
        {ERROR_CODE_IO_READ_POSITION_OUT_OF_RANGE, "Reading data out of the data bound"},
        {ERROR_CODE_IO_NO_CONTENTS, "The media does not contain any contents that can be played"},
        {ERROR_CODE_IO_READ_ERROR, "The media cannot be read, for example, because of dust or scratches"},
        {ERROR_CODE_IO_CONTENT_BUSY, "This resource is already in use"},
        {ERROR_CODE_IO_CONTENT_EXPIRED, "The content using the validity interval has expired"},
        {ERROR_CODE_IO_CONTENT_NON_ALLOWED_USE, "Using the requested content to play is not allowed"},
        {ERROR_CODE_IO_CONTENT_CANNOT_VERIFIED, "The use of the allowed content cannot be verified"},
        {ERROR_CODE_IO_CONTENT_EXHAUSTED_ALLOWED_USES, "The number of times this content has been used as\
            requested has reached the maximum allowed number of uses"},
        {ERROR_CODE_IO_NETWORK_PACKET_SENDING_FAILURE, "An error occurs when sending packet from source\
            device to sink device"},
    };
    // Content parsing errors
    const std::map<CastErrCode, std::string> CAST_PARSING_ERRCODE_INFOS = {
        {ERROR_CODE_PARSING_UNSPECIFIED, "Unspecified error related to content parsing"},
        {ERROR_CODE_PARSING_CONTAINER_MALFORMED, "Parsing error associated with media container format bit\
            streams"},
        {ERROR_CODE_PARSING_MANIFEST_MALFORMED, "Parsing error associated with the media manifest"},
        {ERROR_CODE_PARSING_CONTAINER_UNSUPPORTED, "An error occurs when attempting to extract a file with\
            an unsupported media container format"},
        {ERROR_CODE_PARSING_MANIFEST_UNSUPPORTED, "Unsupported feature in the media manifest"},
    };
    // Decoding errors
    const std::map<CastErrCode, std::string> CAST_DECODE_ERRCODE_INFOS = {
        {ERROR_CODE_DECODE_UNSPECIFIED, "Unspecified decoding error"},
        {ERROR_CODE_DECODER_INIT_FAILED, "Decoder initialization failed"},
        {ERROR_CODE_DECODER_QUERY_FAILED, "Decoder query failed"},
        {ERROR_CODE_DECODING_FAILED, "Decoding the media samples failed"},
        {ERROR_CODE_DECODING_FORMAT_EXCEEDS_CAPABILITIES, "The format of the content to decode exceeds the\
            capabilities of the device"},
        {ERROR_CODE_DECODING_FORMAT_UNSUPPORTED, "The format of the content to decode is not supported"},
    };
    // AudioRender errors
    const std::map<CastErrCode, std::string> CAST_RENDER_ERRCODE_INFOS = {
        {ERROR_CODE_AUDIO_RENDERS_UNSPECIFIED, "Unspecified errors related to the audio renderer"},
        {ERROR_CODE_AUDIO_RENDERS_INIT_FAILED, "Initializing the audio renderer failed"},
        {ERROR_CODE_AUDIO_RENDERS_WRITE_FAILED, "The audio renderer fails to write data"},
    };
    // DRM errors
    const std::map<CastErrCode, std::string> CAST_DRM_ERRCODE_INFOS = {
        {ERROR_CODE_DRM_UNSPECIFIED, "Unspecified error related to DRM"},
        {ERROR_CODE_DRM_SCHEME_UNSUPPORTED, "The chosen DRM protection scheme is not supported by the device"},
        {ERROR_CODE_DRM_PROVISIONING_FAILED, "Device provisioning failed"},
        {ERROR_CODE_DRM_CONTENT_ERROR, "The DRM-protected content to play is incompatible"},
        {ERROR_CODE_DRM_LICENSE_ACQUISITION_FAILED, "Failed to obtain a license"},
        {ERROR_CODE_DRM_DISALLOWED_OPERATION, "The operation is disallowed by the license policy"},
        {ERROR_CODE_DRM_SYSTEM_ERROR, "An error occurs in the DRM system"},
        {ERROR_CODE_DRM_DEVICE_REVOKED, "The device has revoked DRM privileges"},
        {ERROR_CODE_DRM_LICENSE_EXPIRED, "The DRM license being loaded into the open DRM session has expire"},
        {ERROR_CODE_DRM_PROVIDE_KEY_RESPONSE_ERROR, "An error occurs when the DRM processes the key response"},
    };

    const std::map<MediaServiceErrCode, MediaServiceExtErrCodeAPI9> MSERRCODE_TO_EXTERRORCODEAPI9 = {
        {MSERR_OK,                                  MSERR_EXT_API9_OK},
        {MSERR_NO_MEMORY,                           MSERR_EXT_API9_NO_MEMORY},
        {MSERR_INVALID_OPERATION,                   MSERR_EXT_API9_OPERATE_NOT_PERMIT},
        {MSERR_INVALID_VAL,                         MSERR_EXT_API9_INVALID_PARAMETER},
        {MSERR_SERVICE_DIED,                        MSERR_EXT_API9_SERVICE_DIED},
        {MSERR_CREATE_REC_ENGINE_FAILED,            MSERR_EXT_API9_NO_MEMORY},
        {MSERR_CREATE_PLAYER_ENGINE_FAILED,         MSERR_EXT_API9_NO_MEMORY},
        {MSERR_INVALID_STATE,                       MSERR_EXT_API9_OPERATE_NOT_PERMIT},
        {MSERR_UNSUPPORT,                           MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_AUD_SRC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_AUD_SAMPLE_RATE,           MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_AUD_CHANNEL_NUM,           MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_AUD_ENC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_AUD_PARAMS,                MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_VID_SRC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_VID_ENC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_VID_PARAMS,                MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_CONTAINER_TYPE,            MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_PROTOCOL_TYPE,             MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_VID_DEC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_AUD_DEC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_STREAM,                    MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_FILE,                      MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_UNSUPPORT_SOURCE,                    MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_AUD_RENDER_FAILED,                   MSERR_EXT_API9_IO},
        {MSERR_AUD_ENC_FAILED,                      MSERR_EXT_API9_IO},
        {MSERR_VID_ENC_FAILED,                      MSERR_EXT_API9_IO},
        {MSERR_AUD_DEC_FAILED,                      MSERR_EXT_API9_IO},
        {MSERR_VID_DEC_FAILED,                      MSERR_EXT_API9_IO},
        {MSERR_MUXER_FAILED,                        MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_DEMUXER_FAILED,                      MSERR_EXT_API9_UNSUPPORT_FORMAT},
        {MSERR_OPEN_FILE_FAILED,                    MSERR_EXT_API9_IO},
        {MSERR_FILE_ACCESS_FAILED,                  MSERR_EXT_API9_IO},
        {MSERR_START_FAILED,                        MSERR_EXT_API9_OPERATE_NOT_PERMIT},
        {MSERR_PAUSE_FAILED,                        MSERR_EXT_API9_OPERATE_NOT_PERMIT},
        {MSERR_STOP_FAILED,                         MSERR_EXT_API9_OPERATE_NOT_PERMIT},
        {MSERR_SEEK_FAILED,                         MSERR_EXT_API9_OPERATE_NOT_PERMIT},
        {MSERR_NETWORK_TIMEOUT,                     MSERR_EXT_API9_TIMEOUT},
        {MSERR_NOT_FIND_CONTAINER,                  MSERR_EXT_API9_INVALID_PARAMETER},
        {MSERR_UNKNOWN,                             MSERR_EXT_API9_IO},
    };

    const std::map<CastErrCode, CastExtErrCodeAPI12> CASTERRCODE_TO_EXTERRORCODEAPI12 = {
        // Generic error
        {ERROR_CODE_UNSPECIFIED,                        CAST_GENERICERR_EXT_API13_UNSPECIFIED},
        {ERROR_CODE_REMOTE_ERRO,                        CAST_GENERICERR_EXT_API13_REMOTE_ERRO},
        {ERROR_CODE_BEHIND_LIVE_WINDOW,                 CAST_GENERICERR_EXT_API13_BEHIND_LIVE_WINDOW},
        {ERROR_CODE_TIMEOUT,                            CAST_GENERICERR_EXT_API13_TIMEOUT},
        {ERROR_CODE_FAILED_RUNTIME_CHECK,               CAST_GENERICERR_EXT_API13_FAILED_RUNTIME_CHECK},
        {ERROR_CODE_PLAYER_ERROR,                       CAST_GENERICERR_EXT_API13_PLAYER_ERROR},
        {ERROR_CODE_SEEK_MODE_UNSUPPORTED,              CAST_GENERICERR_EXT_API13_SEEK_MODE_UNSUPPORTED},
        {ERROR_CODE_ILLEGAL_SEEK_TARGET,                CAST_GENERICERR_EXT_API13_ILLEGAL_SEEK_TARGET},
        {ERROR_CODE_PLAY_MODE_UNSUPPORTED,              CAST_GENERICERR_EXT_API13_PLAY_MODE_UNSUPPORTED},
        {ERROR_CODE_PLAY_SPEED_UNSUPPORTED,             CAST_GENERICERR_EXT_API13_PLAY_SPEED_UNSUPPORTED},
        {ERROR_CODE_DEVICE_MISSED,                      CAST_GENERICERR_EXT_API13_DEVICE_MISSED},
        {ERROR_CODE_INVALID_PARAM,                      CAST_GENERICERR_EXT_API13_INVALID_PARAM},
        {ERROR_CONNECT_FAILED,                          CAST_GENERICERR_EXT_API13_CONNECT_FAILED},
        {ERROR_OPERATION_NOT_ALLOWED,                   CAST_GENERICERR_EXT_API13_OPERATION_NOT_ALLOWED},
        // Input/Output errors
        {ERROR_CODE_IO_UNSPECIFIED,                     CAST_IOERR_EXT_API13_UNSPECIFIED},
        {ERROR_CODE_IO_NETWORK_CONNECTION_FAILED,       CAST_IOERR_EXT_API13_NETWORK_CONNECTION_FAILED},
        {ERROR_CODE_IO_NETWORK_CONNECTION_TIMEOUT,      CAST_IOERR_EXT_API13_NETWORK_CONNECTION_TIMEOUT},
        {ERROR_CODE_IO_INUALID_HTTP_CONTENT_TYPE,       CAST_IOERR_EXT_API13_INUALID_HTTP_CONTENT_TYPE},
        {ERROR_CODE_IO_BAD_HTTP_STATUS,                 CAST_IOERR_EXT_API13_BAD_HTTP_STATUS},
        {ERROR_CODE_IO_FILE_NOT_FOUND,                  CAST_IOERR_EXT_API13_FILE_NOT_FOUND},
        {ERROR_CODE_IO_NO_PERMISSION,                   CAST_IOERR_EXT_API13_NO_PERMISSION},
        {ERROR_CODE_IO_CLEARTEXT_NOT_PERMIIED,          CAST_IOERR_EXT_API13_CLEARTEXT_NOT_PERMIIED},
        {ERROR_CODE_IO_READ_POSITION_OUT_OF_RANGE,      CAST_IOERR_EXT_API13_READ_POSITION_OUT_OF_RANGE},
        {ERROR_CODE_IO_NO_CONTENTS,                     CAST_IOERR_EXT_API13_NO_CONTENTS},
        {ERROR_CODE_IO_READ_ERRORS,                     CAST_IOERR_EXT_API13_READ_ERRORS},
        {ERROR_CODE_IO_CONTENT_BUSY,                    CAST_IOERR_EXT_API13_CONTENT_BUSY},
        {ERROR_CODE_IO_CONTENT_EXPIRED,                 CAST_IOERR_EXT_API13_CONTENT_EXPIRED},
        {ERROR_CODE_IO_CONTENT_CANNOT_VERIFIED,         CAST_IOERR_EXT_API13_CONTENT_CANNOT_VERIFIED},
        {ERROR_CODE_IO_CONTENT_EXHAUSTED_ALLOWED_USES,  CAST_IOERR_EXT_API13_CONTENT_EXHAUSTED_ALLOWED_USES},
        {ERROR_CODE_IO_NETWORK_PACKET_SENDING_FAILURE,  CAST_IOERR_EXT_API13_NETWORK_PACKET_SENDING_FAILURE},
        // Content parsing errors
        {ERROR_CODE_PARSING_UNSPECIFIED,                CAST_PARSINGERR_EXT_API13_UNSPECIFIED},
        {ERROR_CODE_PARSING_CONTAINER_MALFORMED,        CAST_PARSINGERR_EXT_API13_CONTAINER_MALFORMED},
        {ERROR_CODE_PARSING_MANIFEST_MALFORMED,         CAST_PARSINGERR_EXT_API13_MANIFEST_MALFORMED},
        {ERROR_CODE_PARSING_CONTAINER_UNSUPPORTED,      CAST_PARSINGERR_EXT_API13_CONTAINER_UNSUPPORTED},
        {ERROR_CODE_PARSING_MANIFEST_UNSUPPORTED,       CAST_PARSINGERR_EXT_API13_MANIFEST_UNSUPPORTED},
        // Decoding errors
        {ERROR_CODE_DECODE_UNSPECIFIED,                 CAST_DECODEERR_EXT_API13_UNSPECIFIED},
        {ERROR_CODE_DECODER_INIT_FAILED,                CAST_DECODEERR_EXT_API13_INIT_FAILED},
        {ERROR_CODE_DECODER_QUERY_FAILED,               CAST_DECODEERR_EXT_API13_QUERY_FAILED},
        {ERROR_CODE_DECODING_FAILED,                    CAST_DECODEERR_EXT_API13_FAILED},
        {ERROR_CODE_DECODING_FORMAT_EXCEEDS_CAPABILITIES, CAST_DECODEERR_EXT_API13_FORMAT_EXCEEDS_CAPABILITIES},
        {ERROR_CODE_DECODING_FORMAT_UNSUPPORTED,        CAST_DECODEERR_EXT_API13_FORMAT_UNSUPPORTED},
        // AudioRender errors
        {ERROR_CODE_AUDIO_RENDERS_UNSPECIFIED,          CAST_RENDERERR_EXT_API13_UNSPECIFIED},
        {ERROR_CODE_AUDIO_RENDERS_INIT_FAILED,          CAST_RENDERERR_EXT_API13_INIT_FAILED},
        {ERROR_CODE_AUDIO_RENDERS_WRITE_FAILED,         CAST_RENDERERR_EXT_API13_WRITE_FAILED},
        // DRM errors
        {ERROR_CODE_DRM_UNSPECIFIED,                    CAST_DRMERR_EXT_API13_UNSPECIFIED},
        {ERROR_CODE_DRM_SCHEME_UNSUPPORTED,             CAST_DRMERR_EXT_API13_SCHEME_UNSUPPORTED},
        {ERROR_CODE_DRM_PROVISIONING_FAILED,            CAST_DRMERR_EXT_API13_PROVISIONING_FAILED},
        {ERROR_CODE_DRM_CONTENT_ERROR,                  CAST_DRMERR_EXT_API13_CONTENT_ERROR},
        {ERROR_CODE_DRM_LICENSE_ACQUISITION_FAILED,     CAST_DRMERR_EXT_API13_LICENSE_ACQUISITION_FAILED},
        {ERROR_CODE_DRM_DISALLOWED_OPERATION,           CAST_DRMERR_EXT_API13_DISALLOWED_OPERATION},
        {ERROR_CODE_DRM_SYSTEM_ERROR,                   CAST_DRMERR_EXT_API13_SYSTEM_ERROR},
        {ERROR_CODE_DRM_DEVICE_REVOKED,                 CAST_DRMERR_EXT_API13_DEVICE_REVOKED},
        {ERROR_CODE_DRM_LICENSE_EXPIRED,                CAST_DRMERR_EXT_API13_LICENSE_EXPIRED},
        {ERROR_CODE_DRM_PROVIDE_KEY_PESPONSE_ERROR,     CAST_DRMERR_EXT_API13_PROVIDE_KEY_PESPONSE_ERROR},
    };

    NapiAVCastControllerCallback();
    ~NapiAVCastControllerCallback() override;

    void OnCastPlaybackStateChange(const AVPlaybackState& state) override;
    void OnMediaItemChange(const AVQueueItem& avQueueItem) override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnSeekDone(const int32_t seekNumber) override;
    void OnVideoSizeChange(const int32_t width, const int32_t height) override;
    void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) override;
    void OnEndOfStream(const int32_t isLooping) override;
    void OnPlayRequest(const AVQueueItem& avQueueItem) override;
    void OnKeyRequest(const std::string &assetId, const std::vector<uint8_t> &keyRequestData) override;
    void OnCastValidCommandChanged(const std::vector<int32_t>& cmds) override;

    bool IsCallbacksEmpty(int32_t event);

    napi_status AddCallback(napi_env env, int32_t event, napi_value callback);
    napi_status RemoveCallback(napi_env env, int32_t event, napi_value callback);

private:
    void HandleEvent(int32_t event);
    void HandlePlayerErrorAPI13(const int32_t errorCode, const std::string& errorMsg);

    template<typename T>
    void HandleEvent(int32_t event, const T& param);

    template<typename T>
    void HandleEvent(int32_t event, const std::string& firstParam, const T& secondParam);

    template<typename T>
    void HandleEvent(int32_t event, const int32_t firstParam, const T& secondParam);

    void HandleEvent(int32_t event, const int32_t firstParam, const int32_t secondParam, const int32_t thirdParam);

    void HandleErrorEvent(int32_t event, const int32_t errorCode, const std::string& errorMsg);

    std::mutex lock_;
    std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    std::list<napi_ref> callbacks_[EVENT_CAST_TYPE_MAX] {};
    std::shared_ptr<bool> isValid_;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVCAST_CONTROLLER_CALLBACK_H
