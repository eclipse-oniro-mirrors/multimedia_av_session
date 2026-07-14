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

#ifndef TAIHE_AV_SESSION_CONTROLLER_H
#define TAIHE_AV_SESSION_CONTROLLER_H

#include <mutex>

#include "avsession_controller.h"
#include "avsession_manager.h"
#include "taihe_avcontroller_callback.h"
#include "taihe_meta_data.h"
#include "taihe_playback_state.h"
#include "taihe_avcall_state.h"
#include "taihe_avcall_meta_data.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class AVSessionControllerImpl {
public:
    static int32_t NewInstance(const std::shared_ptr<OHOS::AVSession::AVSessionController> &nativeController,
        AVSessionController &out);
    static int32_t RepeatedInstance(const std::string &controllerId, AVSessionController &out);

    AVSessionControllerImpl();
    explicit AVSessionControllerImpl(std::shared_ptr<AVSessionControllerImpl> &taiheController);
    ~AVSessionControllerImpl();

    string GetSessionId();
    AVPlaybackState GetAVPlaybackStateAsync();
    AVPlaybackState GetAVPlaybackStatePromise();
    AVPlaybackState GetAVPlaybackStateSync();
    AVMetadata GetAVMetadataAsync();
    AVMetadata GetAVMetadataPromise();
    AVMetadata GetAVMetadataSync();
    AVCallState GetAVCallStateAsync();
    AVCallState GetAVCallStatePromise();
    AVCallState GetAVCallStateSync();
    CallMetadata GetCallMetadataAsync();
    CallMetadata GetCallMetadataPromise();
    CallMetadata GetCallMetadataSync();
    string GetAVQueueTitleAsync();
    string GetAVQueueTitlePromise();
    string GetAVQueueTitleSync();
    array<AVQueueItem> GetAVQueueItemsAsync();
    array<AVQueueItem> GetAVQueueItemsPromise();
    array<AVQueueItem> GetAVQueueItemsSync();
    void SkipToQueueItemAsync(int32_t itemId);
    void SkipToQueueItemPromise(int32_t itemId);
    void SkipToQueueItemSync(int32_t itemId);
    OutputDeviceInfo GetOutputDeviceAsync();
    OutputDeviceInfo GetOutputDevicePromise();
    OutputDeviceInfo GetOutputDeviceSync();
    void SendAVKeyEventAsync(keyEvent::KeyEvent const &event);
    void SendAVKeyEventPromise(keyEvent::KeyEvent const &event);
    void SendAVKeyEventSync(keyEvent::KeyEvent const &event);
    uintptr_t GetLaunchAbilityAsync();
    uintptr_t GetLaunchAbilityPromise();
    uintptr_t GetLaunchAbilitySync();
    int64_t GetRealPlaybackPositionAsync();
    int64_t GetRealPlaybackPositionPromise();
    int64_t GetRealPlaybackPositionSync();
    bool IsActiveAsync();
    bool IsActivePromise();
    bool IsActiveSync();
    void DestroyAsync();
    void DestroyPromise();
    void DestroySync();
    array<string> GetValidCommandsAsync();
    array<string> GetValidCommandsPromise();
    array<string> GetValidCommandsSync();
    void SendControlCommandAsync(AVControlCommand const &command);
    void SendControlCommandPromise(AVControlCommand const &command);
    void SendControlCommandSync(AVControlCommand const &command);
    void SendCommonCommandAsync(string_view command, uintptr_t args);
    void SendCommonCommandPromise(string_view command, uintptr_t args);
    void SendCommonCommandSync(string_view command, uintptr_t args);
    void SendCustomDataPromise(uintptr_t data);
    void SendCustomDataSync(uintptr_t data);
    uintptr_t GetExtrasAsync();
    uintptr_t GetExtrasPromise();
    uintptr_t GetExtrasSync();
    uintptr_t GetExtrasWithEventPromise(string_view extraEvent);
    uintptr_t GetExtrasWithEventSync(string_view extraEvent);
    bool IsDesktopLyricEnabledPromise();
    bool IsDesktopLyricEnabledSync();
    void SetDesktopLyricVisiblePromise(bool visible);
    void SetDesktopLyricVisibleSync(bool visible);
    bool IsDesktopLyricVisiblePromise();
    bool IsDesktopLyricVisibleSync();
    void SetDesktopLyricStatePromise(DesktopLyricState const& state);
    void SetDesktopLyricStateSync(DesktopLyricState const& state);
    DesktopLyricState GetDesktopLyricStatePromise();
    DesktopLyricState GetDesktopLyricStateSync();
    array<string> GetMediaCenterControlTypePromise();
    array<string> GetMediaCenterControlTypeSync();
    array<double> GetSupportedPlaySpeedsPromise();
    array<double> GetSupportedPlaySpeedsSync();
    array<int32_t> GetSupportedLoopModesPromise();
    array<int32_t> GetSupportedLoopModesSync();

    void OnMetadataChange(array_view<string> filter, callback_view<void(AVMetadata const&)> callback);
    void OnMetadataChangeAll(callback_view<void(AVMetadata const&)> callback);
    void OnPlaybackStateChange(array_view<string> filter, callback_view<void(AVPlaybackState const&)> callback);
    void OnPlaybackStateChangeAll(callback_view<void(AVPlaybackState const&)> callback);
    void OnCallMetadataChange(array_view<string> filter, callback_view<void(CallMetadata const&)> callback);
    void OnCallMetadataChangeAll(callback_view<void(CallMetadata const&)> callback);
    void OnCallStateChange(array_view<string> filter, callback_view<void(AVCallState const&)> callback);
    void OnCallStateChangeAll(callback_view<void(AVCallState const&)> callback);
    void OnSessionDestroy(callback_view<void()> callback);
    void OnActiveStateChange(callback_view<void(bool)> callback);
    void OnValidCommandChange(callback_view<void(array_view<string>)> callback);
    void OnOutputDeviceChange(callback_view<void(ConnectionState, OutputDeviceInfo const&)> callback);
    void OnSessionEvent(callback_view<void(string_view, uintptr_t)> callback);
    void OnQueueItemsChange(callback_view<void(array_view<AVQueueItem>)> callback);
    void OnQueueTitleChange(callback_view<void(string_view)> callback);
    void OnExtrasChange(callback_view<void(uintptr_t)> callback);
    void OnCustomDataChange(callback_view<void(uintptr_t)> callback);
    void OnDesktopLyricVisibilityChanged(callback_view<void(bool)> callback);
    void OnDesktopLyricStateChanged(callback_view<void(DesktopLyricState const&)> callback);
    void OnDesktopLyricEnabled(callback_view<void(bool)> callback);
    void OnMediaCenterControlTypeChanged(callback_view<void(array_view<string>)> callback);
    void OnSupportedPlaySpeedsChange(callback_view<void(array_view<double>)> callback);
    void OnSupportedLoopModesChange(callback_view<void(array_view<int32_t>)> callback);

    void OffMetadataChange(optional_view<callback<void(AVMetadata const&)>> callback);
    void OffPlaybackStateChange(optional_view<callback<void(AVPlaybackState const&)>> callback);
    void OffCallMetadataChange(optional_view<callback<void(CallMetadata const&)>> callback);
    void OffCallStateChange(optional_view<callback<void(AVCallState const&)>> callback);
    void OffSessionDestroy(optional_view<callback<void()>> callback);
    void OffActiveStateChange(optional_view<callback<void(bool)>> callback);
    void OffValidCommandChange(optional_view<callback<void(array_view<string>)>> callback);
    void OffOutputDeviceChange(optional_view<callback<void(ConnectionState, OutputDeviceInfo const&)>> callback);
    void OffSessionEvent(optional_view<callback<void(string_view, uintptr_t)>> callback);
    void OffQueueItemsChange(optional_view<callback<void(array_view<AVQueueItem>)>> callback);
    void OffQueueTitleChange(optional_view<callback<void(string_view)>> callback);
    void OffExtrasChange(optional_view<callback<void(uintptr_t)>> callback);
    void OffCustomDataChange(optional_view<callback<void(uintptr_t)>> callback);
    void OffDesktopLyricVisibilityChanged(optional_view<callback<void(bool)>> callback);
    void OffDesktopLyricStateChanged(optional_view<callback<void(DesktopLyricState const&)>> callback);
    void OffDesktopLyricEnabled(optional_view<callback<void(bool)>> callback);
    void OffMediaCenterControlTypeChanged(optional_view<callback<void(array_view<string>)>> callback);
    void OffSupportedPlaySpeedsChange(optional_view<callback<void(array_view<double>)>> callback);
    void OffSupportedLoopModesChange(optional_view<callback<void(array_view<int32_t>)>> callback);

private:
    static int32_t DoRegisterCallback(std::shared_ptr<AVSessionControllerImpl> &taiheController);
    static int32_t DoRegisterCallback(AVSessionControllerImpl *taiheController);
    static int32_t OnEvent(const std::string &event, AVSessionControllerImpl *taiheController);
    static int32_t OffEvent(const std::string& event, AVSessionControllerImpl *taiheController);
    static int32_t RegisterCallback(const std::string &event, AVSessionControllerImpl *taiheController);
    static void ErrCodeToMessage(int32_t errCode, const std::string &funcName, std::string &message);

    template<typename T>
    static int32_t SetAVCallMetaFilter(AVSessionControllerImpl *taiheController, T filter);
    template<typename T>
    static int32_t SetAVCallStateFilter(AVSessionControllerImpl *taiheController, T filter);
    template<typename T>
    static int32_t SetPlaybackStateFilter(AVSessionControllerImpl *taiheController, T filter);
    template<typename T>
    static int32_t SetMetaFilter(AVSessionControllerImpl *taiheController, T filter);

    std::string sessionId_;
    std::shared_ptr<OHOS::AVSession::AVSessionController> controller_;
    std::shared_ptr<TaiheAVControllerCallback> callback_;
    static std::mutex uvMutex_;
    static std::mutex controllerListMutex_;

    static std::set<std::string> eventHandlers_;
    static std::map<std::string, std::shared_ptr<AVSessionControllerImpl>> controllerList_;
};
} // namespace ANI::AVSession
#endif // TAIHE_AV_SESSION_CONTROLLER_H