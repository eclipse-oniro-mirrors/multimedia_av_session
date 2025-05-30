/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "avsession_stub.h"
#include "avsession_callback_proxy.h"
#include "avcontrol_command.h"
#include "audio_info.h"
#include "avcast_control_command.h"
#include "system_ability_definition.h"
#include "collaboration_manager_utils.h"

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
    explicit CssListener(AVSessionItem *ptr)
    {
        ptr_ = ptr;
    }

    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove)
    {
        ptr_->OnCastStateChange(castState, deviceInfo, isNeedRemove);
    }

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
    {
        ptr_->OnCastEventRecv(errorCode, errorMsg);
    }

    AVSessionItem *ptr_;
};
#endif
public:
    explicit AVSessionItem(const AVSessionDescriptor& descriptor, int32_t userId = DEFAULT_USER_ID);

    ~AVSessionItem() override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    void DealCastState(int32_t castState);

    void DealDisconnect(DeviceInfo deviceInfo, bool isNeedRemove);

    void DealCollaborationPublishState(int32_t castState, DeviceInfo deviceInfo);

    void DealLocalState(int32_t castState);

    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove);

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg);

    void ListenCollaborationApplyResult();

    void ListenCollaborationOnStop();
#endif

    std::string GetSessionId() override;

    std::string GetSessionType() override;

    int32_t SetAVCallMetaData(const AVCallMetaData& avCallMetaData) override;

    int32_t SetAVCallState(const AVCallState& avCallState) override;

    int32_t GetAVMetaData(AVMetaData& meta) override;

    int32_t SetAVMetaData(const AVMetaData& meta) override;

    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;

    int32_t SetAVQueueItems(const std::vector<AVQueueItem>& items) override;

    int32_t GetAVQueueTitle(std::string& title) override;

    int32_t SetAVQueueTitle(const std::string& title) override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

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

    int32_t SetAVPlaybackState(const AVPlaybackState& state) override;

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

    void HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent);

    void HandleOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo);

    void HandleSkipToQueueItem(const int32_t& itemId);

    void ExecuteControllerCommand(const AVControlCommand& cmd);

    void ExecueCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs);

    int32_t AddController(pid_t pid, sptr<AVControllerItem>& controller);

    void SetPid(pid_t pid);

    void SetUid(pid_t uid);

    pid_t GetPid() const;

    pid_t GetUid() const;

    int32_t GetUserId() const;

    std::string GetAbilityName() const;

    std::string GetBundleName() const;

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
    
    void SetServiceCallbackForNtfCapsule(const std::function<void(std::string, bool)>& callback);

    bool IsCasting();

    void GetCurrentCastItem(AVQueueItem& item);

    AVPlaybackState GetCastAVPlaybackState();

    void SendControlCommandToCast(AVCastControlCommand cmd);

    void SetServiceCallbackForUpdateExtras(const std::function<void(std::string)>& callback);

    void RegisterAVSessionCallback(std::shared_ptr<AVSessionCallback> callbackOfMigrate);

    void SetSupportCommand(std::vector<int32_t> cmds);

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t RegisterListenerStreamToCast(const std::pair<std::string, std::string>& serviceNameStatePair,
        DeviceInfo deviceInfo);

    void InitializeCastCommands();

    void AddSessionCommandToCast(int32_t cmd);

    void RemoveSessionCommandFromCast(int32_t cmd);

    int32_t SessionCommandToCastCommand(int32_t cmd);

    int32_t AddSupportCastCommand(int32_t cmd);

    int32_t DeleteSupportCastCommand(int32_t cmd);

    void HandleCastValidCommandChange(const std::vector<int32_t> &cmds);

    int32_t ReleaseCast(bool continuePlay = false) override;

    int32_t StartCast(const OutputDeviceInfo& outputDeviceInfo);

    int32_t SubStartCast(const OutputDeviceInfo& outputDeviceInfo);

    int32_t CastAddToCollaboration(const OutputDeviceInfo& outputDeviceInfo);

    int32_t AddDevice(const int64_t castHandle, const OutputDeviceInfo& outputDeviceInfo);

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

    void SetServiceCallbackForStream(const std::function<void(std::string)>& callback);
    
    void SetServiceCallbackForCastNtfCapsule(const std::function<void(std::string, bool, bool)>& callback);
#endif

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
    int32_t userId_;
    AVPlaybackState playbackState_;
    AVMetaData metaData_;
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

    std::shared_ptr<RemoteSessionSource> remoteSource_;
    std::shared_ptr<RemoteSessionSink> remoteSink_;

    std::function<void(AVSessionItem&)> serviceCallbackForAddAVQueueInfo_;
    std::function<void(std::string, bool)> serviceCallbackForUpdateSession_;
    std::function<void(std::string)> serviceCallbackForKeyEvent_;
    std::function<void(std::string)> updateExtrasCallback_;
    std::function<void(std::string, bool)> serviceCallbackForNtf_;
    volatile bool isFirstAddToFront_ = true;
    bool isMediaKeySupport = false;
    bool isNotShowNotification_ = false;
    bool isMediaChange_ = true;

    int32_t disconnectStateFromCast_ = 5;
    int32_t connectStateFromCast_ = 6;
    int32_t authingStateFromCast_ = 10;
    int32_t castDisconnectStateInAVSession_ = 6;
    int32_t removeCmdStep_ = 1000;

    volatile bool isDestroyed_ = false;

    static const int32_t DEFAULT_USER_ID = 100;

    static constexpr const char *defaultBundleName = "com.example.himusicdemo";

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

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::recursive_mutex castLock_;
    int64_t castHandle_ = 0;
    std::string castHandleDeviceId_ = "-100";
    const int32_t streamStateConnection = 6;
    const std::string deviceStateConnection = "CONNECT_SUCC";
    int32_t newCastState = -1;
    std::pair<std::string, std::string> castserviceNameStatePair_;

    bool collaborationRejectFlag_ = false;
    bool applyUserResultFlag_ = false;
    bool applyResultFlag_ = false;
    bool waitUserDecisionFlag_ = false;
    bool mirrorToStreamFlag_ = false;
    std::string collaborationNeedDeviceId_;
    std::string collaborationNeedNetworkId_;
    std::mutex collaborationApplyResultMutex_;
    std::condition_variable connectWaitCallbackCond_;
    const int32_t collaborationCallbackTimeOut_ = 10;
    const int32_t collaborationUserCallbackTimeOut_ = 60;

    std::recursive_mutex castControllerProxyLock_;
    std::shared_ptr<IAVCastControllerProxy> castControllerProxy_;
    std::recursive_mutex castControllersLock_;
    std::vector<std::shared_ptr<AVCastControllerItem>> castControllers_;
    std::shared_ptr<CssListener> cssListener_;
    sptr<HwCastDisplayListener> displayListener_;
    std::recursive_mutex displayListenerLock_;
    std::shared_ptr<IAVRouterListener> iAVRouterListener_;
    std::recursive_mutex mirrorToStreamLock_;

    std::map<std::string, DeviceInfo> castDeviceInfoMap_;
    std::function<void(std::string)> serviceCallbackForStream_;
    bool isSwitchNewDevice_ = false;
    OutputDeviceInfo newOutputDeviceInfo_;
    bool isFirstCallback_ = true;
    const int32_t SWITCH_WAIT_TIME = 300;
    std::function<void(std::string, bool, bool)> serviceCallbackForCastNtf_;
#endif
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_ITEM_H
