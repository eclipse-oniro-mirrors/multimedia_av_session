/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_OHAVSESSION_H
#define OHOS_OHAVSESSION_H

#include <unordered_map>
#include "native_avsession.h"
#include "native_avsession_errors.h"
#include "native_avcastcontroller.h"
#include "native_deviceinfo.h"
#include "avsession_info.h"
#include "av_session.h"
#include "OHAVSessionCallbackImpl.h"
#include "OHAVCastController.h"
#include "OHAVUtils.h"
#include "avsession_log.h"
#include "avcast_control_command.h"

namespace OHOS::AVSession {
class OHAVSession {
public:
    ~OHAVSession();
    OHAVSession();
    OHAVSession(AVSession_Type sessionType, const char* sessionTag,
        const char* bundleName, const char* abilityName);
    void SetAVSession(const std::shared_ptr<AVSession> &avsession);
    bool IsAVSessionNull();
    AVSession_ErrCode Activate();
    AVSession_ErrCode Deactivate();
    std::string GetSessionType();
    const std::string& GetSessionId();

    AVSession_ErrCode SetAVMetaData(OH_AVMetadata *metadata);
    AVSession_ErrCode SetPlaybackState(AVSession_PlaybackState playbackState);
    AVSession_ErrCode SetPlaybackPosition(AVSession_PlaybackPosition* playbackPosition);
    AVSession_ErrCode SetFavorite(bool favorite);
    AVSession_ErrCode SetLoopMode(AVSession_LoopMode loopMode);
    AVSession_ErrCode SetRemoteCastEnabled(bool enabled);

    AVSession_ErrCode RegisterCommandCallback(AVSession_ControlCommand command,
                                              OH_AVSessionCallback_OnCommand callback, void* userData);
    AVSession_ErrCode UnregisterCommandCallback(AVSession_ControlCommand command,
                                                OH_AVSessionCallback_OnCommand callback);
    AVSession_ErrCode RegisterForwardCallback(OH_AVSessionCallback_OnFastForward callback, void* userData);
    AVSession_ErrCode UnregisterForwardCallback(OH_AVSessionCallback_OnFastForward callback);
    AVSession_ErrCode RegisterRewindCallback(OH_AVSessionCallback_OnRewind callback, void* userData);
    AVSession_ErrCode UnregisterRewindCallback(OH_AVSessionCallback_OnRewind callback);
    AVSession_ErrCode RegisterSeekCallback(OH_AVSessionCallback_OnSeek callback, void* userData);
    AVSession_ErrCode UnregisterSeekCallback(OH_AVSessionCallback_OnSeek callback);
    AVSession_ErrCode RegisterSetLoopModeCallback(OH_AVSessionCallback_OnSetLoopMode callback, void* userData);
    AVSession_ErrCode UnregisterSetLoopModeCallback(OH_AVSessionCallback_OnSetLoopMode callback);
    AVSession_ErrCode RegisterToggleFavoriteCallback(OH_AVSessionCallback_OnToggleFavorite callback, void* userData);
    AVSession_ErrCode UnregisterToggleFavoriteCallback(OH_AVSessionCallback_OnToggleFavorite callback);
    AVSession_ErrCode RegisterOutputDeviceChangeCallback(OH_AVSessionCallback_OutputDeviceChange callback);
    AVSession_ErrCode UnregisterOutputDeviceChangeCallback(OH_AVSessionCallback_OutputDeviceChange callback);

    AVSession_ErrCode GetAVCastController(OHAVCastController **avcastController);
    AVSession_ErrCode StopCasting();
    AVSession_ErrCode GetOutputDevice(AVSession_OutputDeviceInfo **outputDeviceInfo);
    AVSession_ErrCode ReleaseOutputDevice(AVSession_OutputDeviceInfo *outputDeviceInfo);

    void DestroyAVSessionOutputDevice(AVSession_OutputDeviceInfo *array);

    AVSession_ErrCode Destroy();
    AVSession_ErrCode CheckAndRegister();

    AVSession_ErrCode GetEncodeErrcode(int32_t ret);
    std::unordered_map<int32_t, AVSession_ErrCode> errcodes = {
        {0, AV_SESSION_ERR_SUCCESS},
        {6600101, AV_SESSION_ERR_SERVICE_EXCEPTION},
        {6600102, AV_SESSION_ERR_CODE_SESSION_NOT_EXIST},
        {6600105, AV_SESSION_ERR_CODE_COMMAND_INVALID},
        {6600106, AV_SESSION_ERR_CODE_SESSION_INACTIVE},
        {6600107, AV_SESSION_ERR_CODE_MESSAGE_OVERLOAD},
    };
    std::unordered_map<std::string, AVSession_Type> avsessionTypes = {
        {"audio", SESSION_TYPE_AUDIO},
        {"video", SESSION_TYPE_VIDEO},
        {"voice_call", SESSION_TYPE_VOICE_CALL},
        {"video_call", SESSION_TYPE_VIDEO_CALL},
        {"photo", SESSION_TYPE_PHOTO},
    };

private:
    static void DownloadAndSetAVMetaData(std::shared_ptr<AVSession> avSession, AVMetaData data,
        std::shared_ptr<AVSessionDataTracker> dataTracker);

private:
    std::mutex lock_;
    std::shared_ptr<AVSession> avSession_;
    std::shared_ptr<OHAVSessionCallbackImpl> ohAVSessionCallbackImpl_;
    std::string sessionId_;

    std::shared_ptr<AVSessionDataTracker> dataTracker_;
    AVMetaData metaData_;
};
}
#endif // OHOS_OHAVSESSION_H