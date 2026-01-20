/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_OHAVSESSION_CASTCONTROLLER_H
#define OHOS_OHAVSESSION_CASTCONTROLLER_H

#include <unordered_map>
#include "avcast_controller.h"
#include "avsession_log.h"
#include "native_avcastcontroller.h"
#include "native_avqueueitem.h"
#include "native_avsession_base.h"
#include "native_avsession_errors.h"
#include "OHAVCastControllerCallbackImpl.h"
#include "OHAVSessionPlaybackState.h"
#include "OHAVMediaDescription.h"
#include "OHAVUtils.h"
#include "pixel_map.h"

namespace OHOS::AVSession {
class OHAVCastController {
public:
    ~OHAVCastController();
    OHAVCastController();
    void InitSharedPtrMember();

    AVSession_ErrCode Destroy();
    AVSession_ErrCode GetPlaybackState(OH_AVSession_AVPlaybackState** playbackState);
    AVSession_ErrCode RegisterPlaybackStateChangedCallback(int32_t filter,
        OH_AVCastControllerCallback_PlaybackStateChanged callback, void* userData);
    AVSession_ErrCode UnregisterPlaybackStateChangedCallback(OH_AVCastControllerCallback_PlaybackStateChanged callback);
    AVSession_ErrCode RegisterMediaItemChangedCallback(OH_AVCastControllerCallback_MediaItemChange callback,
        void* userData);
    AVSession_ErrCode UnregisterMediaItemChangedCallback(OH_AVCastControllerCallback_MediaItemChange callback);
    AVSession_ErrCode RegisterPlayNextCallback(OH_AVCastControllerCallback_PlayNext callback, void* userData);
    AVSession_ErrCode UnregisterPlayNextCallback(OH_AVCastControllerCallback_PlayNext callback);
    AVSession_ErrCode RegisterPlayPreviousCallback(OH_AVCastControllerCallback_PlayPrevious callback, void* userData);
    AVSession_ErrCode UnregisterPlayPreviousCallback(OH_AVCastControllerCallback_PlayPrevious callback);
    AVSession_ErrCode RegisterSeekDoneCallback(OH_AVCastControllerCallback_SeekDone callback, void* userData);
    AVSession_ErrCode UnregisterSeekDoneCallback(OH_AVCastControllerCallback_SeekDone callback);
    AVSession_ErrCode RegisterEndOfStreamCallback(OH_AVCastControllerCallback_EndOfStream callback, void* userData);
    AVSession_ErrCode UnregisterEndOfStreamCallback(OH_AVCastControllerCallback_EndOfStream callback);
    AVSession_ErrCode RegisterErrorCallback(OH_AVCastControllerCallback_Error callback, void* userData);
    AVSession_ErrCode UnregisterErrorCallback(OH_AVCastControllerCallback_Error callback);

    AVSession_ErrCode SendCommonCommand(AVSession_AVCastControlCommandType *avCastControlCommand);
    AVSession_ErrCode SendSeekCommand(int32_t seekTimeMS);
    AVSession_ErrCode SendFastForwardCommand(int32_t forwardTimeS);
    AVSession_ErrCode SendRewindCommand(int32_t rewindTimeS);
    AVSession_ErrCode SendSetSpeedCommand(AVSession_PlaybackSpeed speed);
    AVSession_ErrCode SendVolumeCommand(int32_t volume);
    
    AVSession_ErrCode Prepare(OH_AVSession_AVQueueItem* avqueueItem);
    AVSession_ErrCode Start(OH_AVSession_AVQueueItem* avqueueItem);

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

    bool SetAVCastController(std::shared_ptr<AVCastController> &castController);

private:
    bool IsSameAVQueueItem(const AVQueueItem &avQueueItem);
    void UpdateAVQueueItem(const AVQueueItem &avQueueItem);
    static void PrepareAsyncExecutor(std::shared_ptr<AVCastController> avCastController, const AVQueueItem& data,
        std::shared_ptr<AVSessionDataTracker> dataTracker);

    std::shared_ptr<AVCastController> avCastController_;
    std::shared_ptr<OHAVSessionPlaybackState> ohAVSessionPlaybackState_;
    std::shared_ptr<OHAVMediaDescription> ohAVMediaDescription_;
    AVQueueItem avQueueItem_;
    std::shared_ptr<AVSessionDataTracker> dataTracker_;
    std::shared_ptr<OHAVCastControllerCallbackImpl> ohAVCastControllerCallbackImpl_;
    static std::mutex downloadPrepareMutex_;
    std::mutex lock_;
};
}

#endif // OHOS_OHAVSESSION_CASTCONTROLLER_H