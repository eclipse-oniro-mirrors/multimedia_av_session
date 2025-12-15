
/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_ITEM_H
#define OHOS_AVSESSION_ITEM_H

#include <dlfcn.h>
#include <string>
#include <map>
#include <mutex>
#include <shared_mutex>

#include "avsession_stub.h"
#include "av_session_callback_proxy.h"
#include "avcontrol_command.h"
#include "audio_info.h"
#include "avcast_control_command.h"
#include "system_ability_definition.h"
#include "collaboration_manager_utils.h"
#include "avsession_item_extension.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include <condition_variable>
#include <chrono>

#include "i_avcast_controller_proxy.h"
#include "avcast_controller_item.h"
#include "hw_cast_display_listener.h"
#endif

namespace OHOS::AVSession {
class AVControllerItem;
class RemoteSessionSink;
class RemoteSessionSource;
class AVSessionItem : public AVSessionStub {
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
class CssListener : public IAVRouterListener {
public:
    explicit CssListener(wptr<AVSessionItem> ptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ptr_ = ptr;
    }

    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove)
    {
        std::unique_lock lock(mutex_);
        sptr<AVSessionItem> sharedPtr = ptr_.promote();
        lock.unlock();
        CHECK_AND_RETURN_LOG(sharedPtr != nullptr, "sptr is nullptr in OnCastStateChange");
        sharedPtr->OnCastStateChange(castState, deviceInfo, isNeedRemove);
    }

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
    {
        std::unique_lock lock(mutex_);
        sptr<AVSessionItem> sharedPtr = ptr_.promote();
        lock.unlock();
        CHECK_AND_RETURN_LOG(sharedPtr != nullptr, "sptr is nullptr in OnCastEventRecv");
        sharedPtr->OnCastEventRecv(errorCode, errorMsg);
    }

    std::mutex mutex_;
    wptr<AVSessionItem> ptr_;
};
#endif
public:
    explicit AVSessionItem(const AVSessionDescriptor& descriptor, int32_t userId = DEFAULT_USER_ID,
        AVSessionItemExtension *extension = nullptr);

    ~AVSessionItem() override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    void DealCastState(int32_t castState);

    void DealDisconnect(DeviceInfo deviceInfo, bool isNeedRemove);

    void DealCollaborationPublishState(int32_t castState, DeviceInfo deviceInfo);

    void DealLocalState(int32_t castState);

    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove);

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg);

    void ListenCollaborationOnStop();

    void DestroyCast(bool continuePlay);

    enum class MultiDeviceState {
        DEFAULT,
        CASTING_SWITCH_DEVICE,
        CASTED_AND_CASTING,
        CASTING_AND_CASTED,
    };
#endif

    void InitListener();

    std::string GetSessionId() override;

    std::string GetSessionType() override;

    std::string GetSessionTag();

    int32_t SetAVCallMetaData(const AVCallMetaData& avCallMetaData) override;

    int32_t SetAVCallState(const AVCallState& avCallState) override;

    int32_t GetAVMetaData(AVMetaData& meta) override;

    int32_t SetAVMetaData(const AVMetaData& meta) override;

    int32_t UpdateAVQueueInfo(const AVQueueInfo& info) override;

    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;

    int32_t SetAVQueueItems(const std::vector<AVQueueItem>& items) override;

    int32_t GetAVQueueTitle(std::string& title) override;

    int32_t SetAVQueueTitle(const std::string& title) override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

    int32_t SendCustomData(const AAFwk::WantParams& data) override;

    void SendCustomDataInner(const AAFwk::WantParams& data);

    int32_t SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability) override;

    int32_t GetExtras(AAFwk::WantParams& extras) override;

    int32_t SetExtras(const AAFwk::WantParams& extras) override;

    int32_t Activate() override;

    int32_t Deactivate() override;

    bool IsActive() override;

    int32_t Destroy() override;

    int32_t AddSupportCommand(int32_t cmd) override;

    int32_t DeleteSupportCommand(int32_t cmd) override;

    int32_t DestroyTask(bool continuePlay = false);

    AVSessionDescriptor GetDescriptor();

    AVPlaybackState::PlaybackStateMaskType GetControlItemsPlaybackFilter();

    int32_t SetAVPlaybackState(const AVPlaybackState& state) override;

    void SetDesktopLyricFeatureSupported(bool isSupported);

    int32_t EnableDesktopLyric(bool isEnabled) override;

    int32_t IsDesktopLyricEnabled(bool &isEnabled);

    int32_t SetDesktopLyricVisible(bool isVisible) override;

    int32_t IsDesktopLyricVisible(bool &isVisible) override;

    int32_t SetDesktopLyricState(DesktopLyricState state) override;

    int32_t GetDesktopLyricState(DesktopLyricState &state) override;

    int32_t SetDesktopLyricVisibleInner(bool isVisible, const std::string &handler);

    int32_t SetDesktopLyricStateInner(const DesktopLyricState &state, const std::string &handler);

    AVCallState GetAVCallState();

    AVCallMetaData GetAVCallMetaData();

    AVPlaybackState GetPlaybackState();

    AVMetaData GetMetaDataWithoutImg();

    AVMetaData GetMetaData();

    std::vector<AVQueueItem> GetQueueItems();

    std::string GetQueueTitle();

    AAFwk::WantParams GetExtras();

    void KeyEventExtras(AAFwk::IArray* list);

    void NotificationExtras(AAFwk::IArray* list);
 
    bool IsNotShowNotification();

    std::vector<int32_t> GetSupportCommand();

    AbilityRuntime::WantAgent::WantAgent GetLaunchAbility();

    void HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent, const CommandInfo& cmdInfo = CommandInfo{});

    void HandleOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo);

    void DealOutputDeviceChange(const int32_t castState, const OutputDeviceInfo& outputDeviceInfo);

    void HandleSkipToQueueItem(const int32_t& itemId);

    void ExecuteControllerCommand(const AVControlCommand& cmd);

    void ExecueCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs);

    void ExecuteCustomData(const AAFwk::WantParams& data);

    int32_t AddController(pid_t pid, sptr<AVControllerItem>& controller);

    void SetPid(pid_t pid);

    void SetUid(pid_t uid);

    pid_t GetPid() const;

    pid_t GetUid() const;

    int32_t GetUserId() const;

    std::string GetAbilityName() const;

    std::string GetBundleName() const;

    void UpdateSessionElement(const AppExecFwk::ElementName& elementName);

    void SetPlayingTime(int64_t playingTime);

    int64_t GetPlayingTime() const;

    void SetLyricTitle(const std::string& title);

    std::string GetLyricTitle() const;

    void SetTop(bool top);

    std::shared_ptr<RemoteSessionSource> GetRemoteSource();

    void HandleControllerRelease(pid_t pid);

    void SetServiceCallbackForRelease(const std::function<void(AVSessionItem&)>& callback);

    void SetServiceCallbackForCallStart(const std::function<void(AVSessionItem&)>& callback);

    void SetServiceCallbackForKeyEvent(const std::function<void(std::string)>& callback);

    void SetOutputDevice(const OutputDeviceInfo& info);

    void GetOutputDevice(OutputDeviceInfo& info);

    int32_t CastAudioToRemote(const std::string& sourceDevice, const std::string& sinkDevice,
                              const std::string& sinkCapability);

    int32_t SourceCancelCastAudio(const std::string& sinkDevice);

    int32_t CastAudioFromRemote(const std::string& sourceSessionId, const std::string& sourceDevice,
                                const std::string& sinkDevice, const std::string& sourceCapability);

    int32_t SinkCancelCastAudio();

    int32_t SetSessionEvent(const std::string& event, const AAFwk::WantParams& args) override;

    void SetServiceCallbackForAVQueueInfo(const std::function<void(AVSessionItem&)>& callback);

    void SetServiceCallbackForUpdateSession(const std::function<void(std::string, bool)>& callback);

    void SetServiceCallbackForMediaSession(const std::function<void(std::string, bool, bool)>& callback);
    
    void SetServiceCallbackForNtfCapsule(const std::function<void(std::string, bool)>& callback);

    void SetServiceCallbackForUpdateTop(const std::function<void(std::string)>& callback);

    void SetServiceCallbackForAncoStart(const std::function<void(std::string, std::string, std::string)>& callback);

    bool IsCasting();

    void GetCurrentCastItem(AVQueueItem& item);

    AVPlaybackState GetCastAVPlaybackState();

    void SendControlCommandToCast(AVCastControlCommand cmd);

    void SetServiceCallbackForUpdateExtras(const std::function<void(std::string)>& callback);

    void RegisterAVSessionCallback(std::shared_ptr<AVSessionCallback> callbackOfMigrate);

    void SetSupportCommand(std::vector<int32_t> cmds);

    int32_t GetAppIndex();

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t RegisterListenerStreamToCast(const std::pair<std::string, std::string>& serviceNameStatePair,
        DeviceInfo deviceInfo);

    void InitializeCastCommands();

    void AddSessionCommandToCast(int32_t cmd);

    void RemoveSessionCommandFromCast(int32_t cmd);

    int32_t SessionCommandToCastCommand(int32_t cmd);

    int32_t AddSupportCastCommand(int32_t cmd);

    int32_t DeleteSupportCastCommand(int32_t cmd);

    void HandleCastValidCommandChange(const std::vector<int32_t>& cmds);

    int32_t ReleaseCast(bool continuePlay = false) override;

    int32_t StartCast(const OutputDeviceInfo& outputDeviceInfo);

    int32_t SubStartCast(const OutputDeviceInfo& outputDeviceInfo);

    int32_t CastAddToCollaboration(const OutputDeviceInfo& outputDeviceInfo);

    int32_t AddDevice(const int64_t castHandle, const OutputDeviceInfo& outputDeviceInfo,
        uint32_t spid);

    int32_t StopCast(bool continuePlay = false);

    void dealValidCallback(int32_t cmd, std::vector<int32_t>& supportedCastCmds);

    sptr<IRemoteObject> GetAVCastControllerInner() override;

    void ReleaseAVCastControllerInner();

    void UpdateCastDeviceMap(DeviceInfo deviceInfo);

    void SetCastHandle(int64_t castHandle);

    void RegisterDeviceStateCallback();

    void UnRegisterDeviceStateCallback();

    void StopCastSession();

    int32_t StartCastDisplayListener() override;

    int32_t StopCastDisplayListener() override;

    void GetDisplayListener(sptr<IAVSessionCallback> callback);

    int32_t GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays) override;

    void SetExtrasInner(AAFwk::IArray* list);

    bool IsAppSupportCast();

    void SetSpid(const AAFwk::WantParams& extras);

    uint32_t GetSpid();

    void SetServiceCallbackForStream(const std::function<void(std::string)>& callback);
    
    void SetServiceCallbackForCastNtfCapsule(const std::function<void(std::string, bool, bool)>& callback);

    void SetServiceCallbackForPhotoCast(const std::function<void(std::string, bool)>& callback);

    void SetServiceCallbackForStopSinkCast(const std::function<void()>& callback);

    void SetMultiDeviceState(MultiDeviceState multiDeviceState);

    MultiDeviceState GetMultiDeviceState();
#endif

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    void ReportPlaybackState(const AVPlaybackState& state);
    void ReportMetadataChange(const AVMetaData& metadata);
    void ReportCommandChange();
    void ReportSessionControl(const std::string& bundleName, int32_t cmd);
#endif

    void ReadMetaDataImg(std::shared_ptr<AVSessionPixelMap>& innerPixelMap, bool isCast = false);
    void ReadMetaDataAVQueueImg(std::shared_ptr<AVSessionPixelMap>& avQueuePixelMap);

protected:
    int32_t RegisterCallbackInner(const sptr<IAVSessionCallback>& callback) override;
    sptr<IRemoteObject> GetControllerInner() override;

private:
    bool HasAvQueueInfo();
    void HandleOnAVCallAnswer(const AVControlCommand& cmd);
    void HandleOnAVCallHangUp(const AVControlCommand& cmd);
    void HandleOnAVCallToggleCallMute(const AVControlCommand& cmd);
    void HandleOnPlay(const AVControlCommand& cmd);
    void HandleOnPause(const AVControlCommand& cmd);
    void HandleOnPlayOrPause(const AVControlCommand& cmd);
    void HandleOnStop(const AVControlCommand& cmd);
    void HandleOnPlayNext(const AVControlCommand& cmd);
    void HandleOnPlayPrevious(const AVControlCommand& cmd);
    void HandleOnFastForward(const AVControlCommand& cmd);
    void HandleOnRewind(const AVControlCommand& cmd);
    void HandleOnSeek(const AVControlCommand& cmd);
    void HandleOnSetSpeed(const AVControlCommand& cmd);
    void HandleOnSetLoopMode(const AVControlCommand& cmd);
    void HandleOnSetTargetLoopMode(const AVControlCommand& cmd);
    void HandleOnToggleFavorite(const AVControlCommand& cmd);
    void HandleOnPlayFromAssetId(const AVControlCommand& cmd);
    void HandleOnPlayWithAssetId(const AVControlCommand& cmd);

    void ReportConnectFinish(const std::string func, const DeviceInfo &deviceInfo);
    void ReportStopCastFinish(const std::string func, const DeviceInfo &deviceInfo);
    void SaveLocalDeviceInfo();
    int32_t ProcessFrontSession(const std::string& source);
    void HandleFrontSession();
    int32_t DoContinuousTaskRegister();
    int32_t DoContinuousTaskUnregister();
    void ReportSetAVMetaDataInfo(const AVMetaData& meta);
    std::string GetAnonymousDeviceId(std::string deviceId);
    void ReportAVCastControllerInfo();
    void InitAVCastControllerProxy();
    bool CheckTitleChange(const AVMetaData& meta);
    void CheckUseAVMetaData(const AVMetaData& meta);
    void PublishAVCastHa(int32_t castState, DeviceInfo deviceInfo);
    void DelRecommend();
    void ReadMediaAndAVQueueImg(AVMetaData::MetaMaskType recordFilter, AVMetaData& oldData, AVMetaData newData);
    void UpdateMetaData(const AVMetaData& meta);
    void UpdateRecommendInfo(bool needRecommend);
    bool SearchSpidInCapability(const std::string& deviceId);
    void CheckIfSendCapsule(const AVPlaybackState& state);
    void CheckSupportColdStartExtra(const AAFwk::WantParams& extras);
    int32_t ProcessInputRedistributeEvent(const int32_t keyCode);
    bool IsKeyEventSupported(const std::string &bundleName);
    int32_t UpdateVolume(bool up);
    void GetCurrentAppIndexForSession();
    AbilityRuntime::WantAgent::WantAgent CreateWantAgentWithIndex(const AbilityRuntime::WantAgent::WantAgent& ability,
        int32_t index);
    void HandleDesktopLyricVisibilityChanged(bool isVisible);
    void HandleDesktopLyricStateChanged(const DesktopLyricState &state);

    using HandlerFuncType = std::function<void(const AVControlCommand&)>;
    std::map<uint32_t, HandlerFuncType> cmdHandlers = {
        {AVControlCommand::SESSION_CMD_PLAY,
            [this](const AVControlCommand& cmd) { HandleOnPlay(cmd); }},
        {AVControlCommand::SESSION_CMD_PAUSE,
            [this](const AVControlCommand& cmd) { HandleOnPause(cmd); }},
        {AVControlCommand::SESSION_CMD_STOP,
            [this](const AVControlCommand& cmd) { HandleOnStop(cmd); }},
        {AVControlCommand::SESSION_CMD_PLAY_NEXT,
            [this](const AVControlCommand& cmd) { HandleOnPlayNext(cmd); }},
        {AVControlCommand::SESSION_CMD_PLAY_PREVIOUS,
            [this](const AVControlCommand& cmd) { HandleOnPlayPrevious(cmd); }},
        {AVControlCommand::SESSION_CMD_FAST_FORWARD,
            [this](const AVControlCommand& cmd) { HandleOnFastForward(cmd); }},
        {AVControlCommand::SESSION_CMD_REWIND,
            [this](const AVControlCommand& cmd) { HandleOnRewind(cmd); }},
        {AVControlCommand::SESSION_CMD_SEEK,
            [this](const AVControlCommand& cmd) { HandleOnSeek(cmd); }},
        {AVControlCommand::SESSION_CMD_SET_SPEED,
            [this](const AVControlCommand& cmd) { HandleOnSetSpeed(cmd); }},
        {AVControlCommand::SESSION_CMD_SET_LOOP_MODE,
            [this](const AVControlCommand& cmd) { HandleOnSetLoopMode(cmd); }},
        {AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE,
            [this](const AVControlCommand& cmd) { HandleOnSetTargetLoopMode(cmd); }},
        {AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE,
            [this](const AVControlCommand& cmd) { HandleOnToggleFavorite(cmd); }},
        {AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID,
            [this](const AVControlCommand& cmd) { HandleOnPlayFromAssetId(cmd); }},
        {AVControlCommand::SESSION_CMD_PLAY_WITH_ASSETID,
            [this](const AVControlCommand& cmd) { HandleOnPlayWithAssetId(cmd); }},
        {AVControlCommand::SESSION_CMD_AVCALL_ANSWER,
            [this](const AVControlCommand& cmd) { HandleOnAVCallAnswer(cmd); }},
        {AVControlCommand::SESSION_CMD_AVCALL_HANG_UP,
            [this](const AVControlCommand& cmd) { HandleOnAVCallHangUp(cmd); }},
        {AVControlCommand::SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE,
            [this](const AVControlCommand& cmd) { HandleOnAVCallToggleCallMute(cmd); }}
    };

    std::map<int32_t, HandlerFuncType> keyEventCaller_ = {
        {MMI::KeyEvent::KEYCODE_MEDIA_PLAY, [this](const AVControlCommand& cmd) { HandleOnPlay(cmd); }},
        {MMI::KeyEvent::KEYCODE_MEDIA_PAUSE, [this](const AVControlCommand& cmd) { HandleOnPause(cmd); }},
        {MMI::KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE, [this](const AVControlCommand& cmd) { HandleOnPlayOrPause(cmd); }},
        {MMI::KeyEvent::KEYCODE_MEDIA_STOP, [this](const AVControlCommand& cmd) { HandleOnPause(cmd); }},
        {MMI::KeyEvent::KEYCODE_MEDIA_NEXT, [this](const AVControlCommand& cmd) { HandleOnPlayNext(cmd); }},
        {MMI::KeyEvent::KEYCODE_MEDIA_PREVIOUS, [this](const AVControlCommand& cmd) { HandleOnPlayPrevious(cmd); }},
        {MMI::KeyEvent::KEYCODE_MEDIA_REWIND, [this](const AVControlCommand& cmd) { HandleOnRewind(cmd); }},
        {MMI::KeyEvent::KEYCODE_MEDIA_FAST_FORWARD, [this](const AVControlCommand& cmd) { HandleOnFastForward(cmd); }}
    };

    std::map<pid_t, sptr<AVControllerItem>> controllers_;
    AVCallMetaData avCallMetaData_;
    AVCallState avCallState_;

    AVSessionDescriptor descriptor_;
    int32_t userId_ = 0;
    AVPlaybackState playbackState_;
    AVMetaData metaData_;
    AVMetaData lastMetaData_;
    std::vector<AVQueueItem> queueItems_;
    std::string queueTitle_;
    AbilityRuntime::WantAgent::WantAgent launchAbility_;
    AAFwk::WantParams extras_;
    std::vector<int32_t> supportedCmd_;
    std::vector<int32_t> supportedCastCmds_;
    sptr<IAVSessionCallback> callback_;
    std::shared_ptr<AVSessionCallback> callbackForMigrate_;
    std::function<void(AVSessionItem&)> serviceCallback_;
    std::function<void(AVSessionItem&)> callStartCallback_;
    friend class AVSessionDumper;
    int64_t playingTime_ = 0;
    std::string lyricTitle_ = "";
    int32_t appIndex_ = 0;

    std::shared_ptr<RemoteSessionSource> remoteSource_;
    std::shared_ptr<RemoteSessionSink> remoteSink_;

    std::function<void(AVSessionItem&)> serviceCallbackForAddAVQueueInfo_;
    std::function<void(std::string, bool)> serviceCallbackForUpdateSession_;
    std::function<void(std::string, bool, bool)> serviceCallbackForMediaSession_;
    std::function<void(std::string)> serviceCallbackForKeyEvent_;
    std::function<void(std::string)> updateExtrasCallback_;
    std::function<void(std::string, bool)> serviceCallbackForNtf_;
    std::function<void(std::string)> serviceCallbackForUpdateTop_;
    std::function<void(std::string, std::string, std::string)> serviceCallbackForAncoStart_;
    volatile bool isFirstAddToFront_ = true;
    bool isMediaKeySupport = false;
    bool isNotShowNotification_ = false;
    bool isMediaChange_ = true;
    bool isRecommendMediaChange_ = false;
    bool isRecommend_ = false;
    bool isPlayingState_ = false;
    bool isSetLaunchAbility_ = false;

    int32_t disconnectStateFromCast_ = 5;
    int32_t connectStateFromCast_ = 6;
    int32_t authingStateFromCast_ = 10;
    int32_t castDisconnectStateInAVSession_ = 6;
    int32_t removeCmdStep_ = 1000;

    volatile bool isDestroyed_ = false;

    static const int32_t DEFAULT_USER_ID = 100;
    static constexpr const int32_t audioBrokerUid = 5557;
    static constexpr const char *defaultBundleName = "com.example.himusicdemo";
    static constexpr const char *sessionCastState_ = "CAST_STATE";
    static constexpr const int32_t cancelTimeout = 5000;

    std::atomic_bool isSupportedDesktopLyric_ = false;
    std::atomic_bool isEnabledDesktopLyric_ = false;
    std::mutex desktopLyricVisibleMutex_;
    bool isDesktopLyricVisible_ = false;
    std::mutex desktopLyricStateMutex_;
    DesktopLyricState desktopLyricState_ = {};
    AVSessionItemExtension *extension_ = nullptr;

    // The following locks are used in the defined order of priority
    std::recursive_mutex avsessionItemLock_;

    std::recursive_mutex controllersLock_;

    std::recursive_mutex callbackLock_;

    std::recursive_mutex destroyLock_;

    std::recursive_mutex remoteCallbackLock_;

    std::recursive_mutex remoteSourceLock_;

    std::recursive_mutex remoteSinkLock_;

    std::shared_ptr<bool> isAlivePtr_;

    std::recursive_mutex isAliveLock_;

    std::recursive_mutex callbackForCastCapLock_;

    std::recursive_mutex mediaSessionCallbackLock_;

    std::shared_mutex writeAndReadImgLock_;

    std::recursive_mutex updateTopLock_;

    std::shared_mutex coldStartCallbackLock_;

    std::recursive_mutex launchAbilityLock_;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::recursive_mutex castLock_;
    int64_t castHandle_ = 0;
    std::string castHandleDeviceId_ = "-100";
    const int32_t streamStateConnection = 6;
    const std::string deviceStateConnection = "CONNECT_SUCC";
    int32_t newCastState = -1;
    std::pair<std::string, std::string> castServiceNameStatePair_;

    std::atomic<bool> mirrorToStreamOnceFlag_ = false;
    std::string collaborationNeedDeviceId_;
    std::string collaborationNeedNetworkId_;

    std::recursive_mutex castControllerProxyLock_;
    std::shared_ptr<IAVCastControllerProxy> castControllerProxy_;
    std::recursive_mutex castControllersLock_;
    std::vector<std::shared_ptr<AVCastControllerItem>> castControllers_;
    std::shared_ptr<CssListener> cssListener_;
    sptr<HwCastDisplayListener> displayListener_;
    std::recursive_mutex displayListenerLock_;
    std::shared_ptr<IAVRouterListener> iAVRouterListener_;

    std::map<std::string, DeviceInfo> castDeviceInfoMap_;
    uint32_t spid_ = 0;
    std::mutex spidMutex_;
    std::function<void(std::string)> serviceCallbackForStream_;
    std::atomic<MultiDeviceState> multiDeviceState_ = MultiDeviceState::DEFAULT;
    OutputDeviceInfo newOutputDeviceInfo_;
    bool isFirstCallback_ = true;
    const int32_t SWITCH_WAIT_TIME = 300;
    std::function<void(std::string, bool, bool)> serviceCallbackForCastNtf_;
    std::function<void(std::string, bool)> serviceCallbackForPhotoCast_;
    std::function<void()> serviceCallbackStopSinkCast_;

    const std::string MEDIA_CONTROL_BUNDLENAME = "com.ohos.mediacontroller";
    const std::string SCENE_BOARD_BUNDLENAME = "com.ohos.sceneboard";
    const std::string MEDIA_CAST_DISCONNECT = "usual.event.MEDIA_CAST_DISCONNECT";
    const std::string MEDIA_CAST_ERROR = "usual.event.MEDIA_CAST_ERROR";
#endif
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_ITEM_H
