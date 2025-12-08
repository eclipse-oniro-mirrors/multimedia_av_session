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

#ifndef OHOS_OHAVCASTCONTROLLER_CALLBACKIMPL_H
#define OHOS_OHAVCASTCONTROLLER_CALLBACKIMPL_H

#include "native_avmetadata.h"
#include "native_avcastcontroller.h"
#include "OHAVMediaDescription.h"
#include "avsession_info.h"
#include "avplayback_state.h"
#include "OHAVSessionPlaybackState.h"

namespace OHOS::AVSession {
class OHAVCastControllerCallbackImpl : public AVCastControllerCallback {
public:
    OHAVCastControllerCallbackImpl();
    ~OHAVCastControllerCallbackImpl() override;
    void InitSharedPtrMember();

    void OnCastPlaybackStateChange(const AVPlaybackState& state) override;
    void OnMediaItemChange(const AVQueueItem& avQueueItem) override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnSeekDone(const int32_t seekNumber) override;
    void OnVideoSizeChange(const int32_t width, const int32_t height) override {};
    void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) override;
    void OnEndOfStream(const int32_t isLooping) override;
    void OnPlayRequest(const AVQueueItem& avQueueItem) override {};
    void OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData) override {};
    void OnCastValidCommandChanged(const std::vector<int32_t> &cmds) override {};
    int32_t onDataSrcRead(const std::shared_ptr<AVSharedMemoryBase>& mem, uint32_t length,
        int64_t pos, int32_t& result) override { return AV_SESSION_ERR_SUCCESS; };

    AVSession_ErrCode RegisterPlaybackStateChangedCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_PlaybackStateChanged callback, void* userData);
    AVSession_ErrCode UnregisterPlaybackStateChangedCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_PlaybackStateChanged callback);
    AVSession_ErrCode RegisterMediaItemChangedCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_MediaItemChange callback, void* userData);
    AVSession_ErrCode UnregisterMediaItemChangedCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_MediaItemChange callback);
    AVSession_ErrCode RegisterPlayNextCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_PlayNext callback, void* userData);
    AVSession_ErrCode UnregisterPlayNextCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_PlayNext callback);
    AVSession_ErrCode RegisterPlayPreviousCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_PlayPrevious callback, void* userData);
    AVSession_ErrCode UnregisterPlayPreviousCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_PlayPrevious callback);
    AVSession_ErrCode RegisterSeekDoneCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_SeekDone callback, void* userData);
    AVSession_ErrCode UnregisterSeekDoneCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_SeekDone callback);
    AVSession_ErrCode RegisterEndOfStreamCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_EndOfStream callback, void* userData);
    AVSession_ErrCode UnregisterEndOfStreamCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_EndOfStream callback);
    AVSession_ErrCode RegisterErrorCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_Error callback, void* userData);
    AVSession_ErrCode UnregisterErrorCallback(OH_AVCastController* avcastcontroller,
        OH_AVCastControllerCallback_Error callback);
private:
    OH_AVCastController* avCastController_ = {nullptr};
    std::shared_ptr<OHAVSessionPlaybackState> ohAVSessionPlaybackState_;
    std::shared_ptr<AVMediaDescription> avMediaDescription_;
    std::shared_ptr<OHAVMediaDescription> ohAVMediaDescription_;
    std::shared_ptr<OH_PixelmapNative> ohPixelmapNative_ = nullptr;
    std::shared_ptr<OH_AVSession_AVQueueItem> ohAVSessionAVQueueItem_;

    std::vector<std::pair<OH_AVCastControllerCallback_PlaybackStateChanged, void*>> playbackStateCallbacks_;
    std::vector<std::pair<OH_AVCastControllerCallback_MediaItemChange, void*>> mediaItemChangedCallbacks_;
    std::vector<std::pair<OH_AVCastControllerCallback_PlayNext, void*>> playNextCallbacks_;
    std::vector<std::pair<OH_AVCastControllerCallback_PlayPrevious, void*>> playPreviousCallbacks_;
    std::vector<std::pair<OH_AVCastControllerCallback_SeekDone, void*>> seekDoneCallbacks_;
    std::vector<std::pair<OH_AVCastControllerCallback_EndOfStream, void*>> endOfStreamCallbacks_;
    std::vector<std::pair<OH_AVCastControllerCallback_Error, void*>> errorCallbacks_;

    std::mutex lock_;
};
}

#endif // OHOS_OHAVCASTCONTROLLER_CALLBACKIMPL_H