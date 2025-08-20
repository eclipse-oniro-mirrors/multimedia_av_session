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

#ifndef TAIHE_AV_SESSION_H
#define TAIHE_AV_SESSION_H

#include <chrono>
#include <mutex>
#include <map>

#include "av_session.h"
#include "avsession_info.h"
#include "avsession_event_handler.h"
#include "avsession_manager.h"
#include "avcontrol_command.h"
#include "pixel_map.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_event_handler.h"
#include "taihe_avsession_callback.h"
#include "taihe_avsession_manager.h"
#include "taihe_utils.h"
#include "want_agent.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class AVSessionImpl {
public:
    static int32_t NewInstance(std::shared_ptr<OHOS::AVSession::AVSession> &nativeSession,
        struct AVSession &out, std::shared_ptr<AVSessionImpl> &taiheSession,
        const std::string &tag, OHOS::AppExecFwk::ElementName &elementName);
    static int32_t ReCreateInstance(std::shared_ptr<OHOS::AVSession::AVSession> nativeSession);

    AVSessionImpl();
    explicit AVSessionImpl(std::shared_ptr<OHOS::AVSession::AVSession> &nativeSession,
        const std::string &tag, OHOS::AppExecFwk::ElementName &elementName);
    explicit AVSessionImpl(std::shared_ptr<AVSessionImpl> &taiheSession);
    ~AVSessionImpl();

    // Taihe read only attributes
    string GetSessionId();
    string GetSessionType();

    void SetAVMetadataSync(AVMetadata const &data);
    void SetCallMetadataSync(CallMetadata const& data);
    void SetAVPlaybackStateSync(AVPlaybackState const &state);
    void SetAVCallStateSync(AVCallState const& state);
    void SetLaunchAbilitySync(uintptr_t ability);
    void DispatchSessionEventSync(string_view event, uintptr_t args);
    void SetAVQueueItemsSync(array_view<AVQueueItem> items);
    void SetAVQueueTitleSync(string_view title);
    void SetExtrasSync(uintptr_t extras);
    AVSessionController GetControllerSync();
    optional<AVCastController> GetAVCastControllerSync();
    OutputDeviceInfo GetOutputDeviceSync();
    array<CastDisplayInfo> GetAllCastDisplaysSync();
    void StopCastingSync();
    void ActivateSync();
    void DeactivateSync();
    void DestroySync();

    void OnPlay(callback_view<void()> callback);
    void OnPause(callback_view<void()> callback);
    void OnStop(callback_view<void()> callback);
    void OnPlayNext(callback_view<void()> callback);
    void OnPlayPrevious(callback_view<void()> callback);
    void OnFastForward(callback_view<void(int64_t)> callback);
    void OnRewind(callback_view<void(int64_t)> callback);
    void OnPlayFromAssetId(callback_view<void(int64_t)> callback);
    void OnSeek(callback_view<void(int64_t)> callback);
    void OnSetSpeed(callback_view<void(double)> callback);
    void OnSetLoopMode(callback_view<void(LoopMode)> callback);
    void OnToggleFavorite(callback_view<void(string_view)> callback);
    void OnHandleKeyEvent(callback_view<void(uintptr_t)> callback);
    void OnOutputDeviceChange(callback_view<void(ConnectionState, OutputDeviceInfo const&)> callback);
    void OnCommonCommand(callback_view<void(string_view, uintptr_t)> callback);
    void OnSkipToQueueItem(callback_view<void(int32_t)> callback);
    void OnAnswer(callback_view<void()> callback);
    void OnHangUp(callback_view<void()> callback);
    void OnToggleCallMute(callback_view<void()> callback);
    void OnCastDisplayChange(callback_view<void(CastDisplayInfo const&)> callback);

    void OffPlay(optional_view<callback<void()>> callback);
    void OffPause(optional_view<callback<void()>> callback);
    void OffStop(optional_view<callback<void()>> callback);
    void OffPlayNext(optional_view<callback<void()>> callback);
    void OffPlayPrevious(optional_view<callback<void()>> callback);
    void OffFastForward(optional_view<callback<void()>> callback);
    void OffRewind(optional_view<callback<void()>> callback);
    void OffPlayFromAssetId(optional_view<callback<void(int64_t)>> callback);
    void OffSeek(optional_view<callback<void(int64_t)>> callback);
    void OffSetSpeed(optional_view<callback<void(double)>> callback);
    void OffSetLoopMode(optional_view<callback<void(LoopMode)>> callback);
    void OffToggleFavorite(optional_view<callback<void(string_view)>> callback);
    void OffHandleKeyEvent(optional_view<callback<void(uintptr_t)>> callback);
    void OffOutputDeviceChange(optional_view<callback<void(ConnectionState, OutputDeviceInfo const&)>> callback);
    void OffCommonCommand(optional_view<callback<void(string_view, uintptr_t)>> callback);
    void OffSkipToQueueItem(optional_view<callback<void(int32_t)>> callback);
    void OffAnswer(optional_view<callback<void()>> callback);
    void OffHangUp(optional_view<callback<void()>> callback);
    void OffToggleCallMute(optional_view<callback<void()>> callback);
    void OffCastDisplayChange(optional_view<callback<void(CastDisplayInfo const&)>> callback);

    std::string GetSessionIdInner();
    void SetSessionIdInner(std::string sessionId);

    std::string GetSessionTypeInner();
    void SetSessionTypeInner(std::string sessionType);

    std::string GetSessionTag();
    void SetSessionTag(std::string sessionTag);

    OHOS::AppExecFwk::ElementName GetSessionElement();
    void SetSessionElement(OHOS::AppExecFwk::ElementName elementName);

private:
    static int32_t OnEvent(const std::string &event, AVSessionImpl *taiheSession);
    static int32_t OffEvent(const std::string &event, AVSessionImpl *taiheSession);
    static std::function<void()> PlaybackStateExecute(const std::shared_ptr<OHOS::AVSession::AVSession> &session,
        const OHOS::AVSession::AVPlaybackState &playBackState);
    static std::function<void()> PlaybackStateComplete();

    static void ErrCodeToMessage(int32_t errCode, std::string& message);

    static int32_t ThrowErrorAndReturn(const std::string& message, int32_t errCode);
    static int32_t ThrowErrorAndReturnByErrCode(const std::string& message, int32_t errCode);

    std::string sessionId_;
    std::string sessionType_;
    std::string sessionTag_;
    OHOS::AppExecFwk::ElementName elementName_;
    std::shared_ptr<OHOS::AVSession::AVSession> session_;
    std::shared_ptr<TaiheAVSessionCallback> callback_;
    std::chrono::system_clock::time_point latestMetadataTs_;
    std::string latestMetadataUri_;
    std::string latestMetadataAssetId_;
    std::string latestDownloadedUri_;
    std::string latestDownloadedAssetId_;
    OHOS::AVSession::AVMetaData metaData_;

    static std::mutex executeMutex_;
    static std::mutex completeMutex_;
    static std::condition_variable executeCond_;
    static std::condition_variable completeCond_;
    static int32_t playBackStateRet_;
    static std::shared_ptr<AVSessionImpl> taiheAVSession_;

    static std::set<std::string> onEventHandlers_;
    static std::set<std::string> offEventHandlers_;
};
} // namespace ANI::AVSession
#endif // TAIHE_AV_SESSION_H