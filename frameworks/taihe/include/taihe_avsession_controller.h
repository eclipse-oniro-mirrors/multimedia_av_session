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
    AVPlaybackState GetAVPlaybackStateSync();
    AVMetadata GetAVMetadataSync();
    AVCallState GetAVCallStateSync();
    CallMetadata GetCallMetadataSync();
    string GetAVQueueTitleSync();
    array<AVQueueItem> GetAVQueueItemsSync();
    void SkipToQueueItemSync(int32_t itemId);
    OutputDeviceInfo GetOutputDeviceSync();
    void SendAVKeyEventSync(keyEvent::KeyEvent const &event);
    uintptr_t GetLaunchAbilitySync();
    int64_t GetRealPlaybackPositionSync();
    bool IsActiveSync();
    void DestroySync();
    array<string> GetValidCommandsSync();
    void SendControlCommandSync(AVControlCommand const &command);
    void SendCommonCommandSync(string_view command, uintptr_t args);
    uintptr_t GetExtrasSync();
    uintptr_t GetExtrasWithEventSync(string_view extraEvent);

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

private:
    static int32_t DoRegisterCallback(std::shared_ptr<AVSessionControllerImpl> &taiheController);
    static int32_t DoRegisterCallback(AVSessionControllerImpl *taiheController);
    static int32_t OnEvent(const std::string &event, AVSessionControllerImpl *taiheController);
    static int32_t OffEvent(const std::string& event, AVSessionControllerImpl *taiheController);
    static int32_t RegisterCallback(const std::string &event, AVSessionControllerImpl *taiheController);

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