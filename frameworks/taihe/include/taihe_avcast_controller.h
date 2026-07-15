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

#ifndef TAIHE_AVCAST_CONTROLLER_H
#define TAIHE_AVCAST_CONTROLLER_H

#include "avcast_controller.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "taihe_avcast_controller_callback.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class AVCastControllerImpl {
public:
    AVCastControllerImpl();
    explicit AVCastControllerImpl(std::shared_ptr<OHOS::AVSession::AVCastController> &nativeController);
    ~AVCastControllerImpl();

    static int32_t NewInstance(std::shared_ptr<OHOS::AVSession::AVCastController> &nativeController,
        AVCastController &out);
    static constexpr size_t TIME_OUT_SECOND = 5;

    void SetDisplaySurfaceSync(string_view surfaceId);
    array<DecoderType> GetSupportedDecodersSync();
    ResolutionLevel GetRecommendedResolutionLevelSync(DecoderType decoderType);
    array<uintptr_t> GetSupportedHdrCapabilitiesSync();
    array<double> GetSupportedPlaySpeedsSync();
    void SendControlCommandSync(AVCastControlCommand const &command);
    void SendCustomDataSync(uintptr_t data);
    void StartSync(AVQueueItem const& item);
    void PrepareSync(AVQueueItem const& item);
    AVQueueItem GetCurrentItemSync();
    void ProcessMediaKeyResponseSync(string_view assetId, array_view<uint8_t> response);
    void ReleaseSync();
    AVPlaybackState GetAVPlaybackStateSync();
    array<string> GetValidCommandsSync();

    void OnPlaybackStateChange(array_view<string> filter, callback_view<void(AVPlaybackState const&)> callback);
    void OnPlaybackStateChangeAll(callback_view<void(AVPlaybackState const&)> callback);
    void OnMediaItemChange(callback_view<void(AVQueueItem const&)> callback);
    void OnPlayNext(callback_view<void()> callback);
    void OnPlayPrevious(callback_view<void()> callback);
    void OnRequestPlay(callback_view<void(AVQueueItem const&)> callback);
    void OnEndOfStream(callback_view<void()> callback);
    void OnSeekDone(callback_view<void(int32_t)> callback);
    void OnValidCommandChange(callback_view<void(array_view<string>)> callback);
    void OnVideoSizeChange(callback_view<void(int32_t, int32_t)> callback);
    void OnError(callback_view<void(uintptr_t)> callback);
    void OnCastControlGenericError(callback_view<void(uintptr_t)> callback);
    void OnCastControlIoError(callback_view<void(uintptr_t)> callback);
    void OnCastControlParsingError(callback_view<void(uintptr_t)> callback);
    void OnCastControlDecodingError(callback_view<void(uintptr_t)> callback);
    void OnCastControlAudioRendererError(callback_view<void(uintptr_t)> callback);
    void OnCastControlDrmError(callback_view<void(uintptr_t)> callback);
    void OnKeyRequest(callback_view<void(string_view, array_view<uint8_t>)> callback);
    void OnCustomDataChange(callback_view<void(uintptr_t)> callback);

    void OffPlaybackStateChange(optional_view<callback<void(AVPlaybackState const&)>> callback);
    void OffMediaItemChange(optional_view<callback<void(AVQueueItem const&)>> callback);
    void OffPlayNext(optional_view<callback<void()>> callback);
    void OffPlayPrevious(optional_view<callback<void()>> callback);
    void OffRequestPlay(optional_view<callback<void(AVQueueItem const&)>> callback);
    void OffEndOfStream(optional_view<callback<void()>> callback);
    void OffSeekDone(optional_view<callback<void(int32_t)>> callback);
    void OffValidCommandChange(optional_view<callback<void(array_view<string>)>> callback);
    void OffVideoSizeChange(optional_view<callback<void(int32_t, int32_t)>> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OffCastControlGenericError(optional_view<callback<void(uintptr_t)>> callback);
    void OffCastControlIoError(optional_view<callback<void(uintptr_t)>> callback);
    void OffCastControlParsingError(optional_view<callback<void(uintptr_t)>> callback);
    void OffCastControlDecodingError(optional_view<callback<void(uintptr_t)>> callback);
    void OffCastControlAudioRendererError(optional_view<callback<void(uintptr_t)>> callback);
    void OffCastControlDrmError(optional_view<callback<void(uintptr_t)>> callback);
    void OffKeyRequest(optional_view<callback<void(string_view,
        array_view<uint8_t>)>> callback);
    void OffCustomDataChange(optional_view<callback<void(uintptr_t)>> callback);
private:
    static void ReportStartFailInfo(int32_t error);
    static void ReportSendControlCommandFailInfo(int32_t error);
    static std::string GetSendControlCommandErrMsg(int32_t error);
    static int32_t OnEvent(const std::string &event, AVCastControllerImpl *taiheCastController);
    static int32_t OffEvent(const std::string& event, AVCastControllerImpl *taiheCastController);
    static int32_t RegisterCallback(const std::string& event, AVCastControllerImpl *taiheCastController);

    template<typename T>
    static int32_t SetCastPlaybackStateFilter(AVCastControllerImpl *taiheCastController, T filter);

    std::shared_ptr<OHOS::AVSession::AVCastController> castController_;
    std::shared_ptr<TaiheAVCastControllerCallback> callback_;

    static std::set<std::string> eventHandlers_;
};
} // namespace ANI::AVSession
#endif // TAIHE_AVCAST_CONTROLLER_H