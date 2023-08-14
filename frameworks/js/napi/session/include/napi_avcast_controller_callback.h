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
#include "errors.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_async_callback.h"
#include "avsession_info.h"
#include "avsession_log.h"

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
        EVENT_CAST_END_OF_STREAM,
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

    napi_status AddCallback(napi_env env, int32_t event, napi_value callback);
    napi_status RemoveCallback(napi_env env, int32_t event, napi_value callback);

private:
    void HandleEvent(int32_t event);

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
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVCAST_CONTROLLER_CALLBACK_H
