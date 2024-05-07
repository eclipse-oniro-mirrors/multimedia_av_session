/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <string>
#include <map>

#include "avsession_stub.h"
#include "avsession_callback_proxy.h"
#include "avcontrol_command.h"
#include "audio_info.h"
#include "avcast_control_command.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "i_avcast_controller_proxy.h"
#include "avcast_controller_item.h"
#endif

namespace OHOS::AVSession {
class AVControllerItem;
class RemoteSessionSink;
class RemoteSessionSource;
class AVSessionItem : public AVSessionStub {
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
class CssListener : public IAVCastSessionStateListener {
public:
    explicit CssListener(AVSessionItem *ptr)
    {
        ptr_ = ptr;
    }

    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo)
    {
        ptr_->OnCastStateChange(castState, deviceInfo);
    }

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
    {
        ptr_->OnCastEventRecv(errorCode, errorMsg);
    }

    AVSessionItem *ptr_;
};
#endif
public:
    explicit AVSessionItem(const AVSessionDescriptor& descriptor);

    ~AVSessionItem() override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    bool IsCastSinkSession(int32_t castState);

    void DealCastState(int32_t castState);

    void DealDisconnect(DeviceInfo deviceInfo);

    void OnCastStateChange(int32_t castState, DeviceInfo deviceInfo);

    void OnCastEventRecv(int32_t errorCode, std::string& errorMsg);
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

    int32_t DestroyTask();

    AVSessionDescriptor GetDescriptor();

    int32_t SetAVPlaybackState(const AVPlaybackState& state) override;

    AVCallState GetAVCallState();

    AVCallMetaData GetAVCallMetaData();

    AVPlaybackState GetPlaybackState();

    AVMetaData GetMetaData();

    std::vector<AVQueueItem> GetQueueItems();

    std::string GetQueueTitle();

    AAFwk::WantParams GetExtras();

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

    std::string GetAbilityName() const;

    std::string GetBundleName() const;

    void SetTop(bool top);

    std::shared_ptr<RemoteSessionSource> GetRemoteSource();

    void HandleControllerRelease(pid_t pid);

    void SetServiceCallbackForRelease(const std::function<void(AVSessionItem&)>& callback);

    void SetServiceCallbackForCallStart(const std::function<void(AVSessionItem&)>& callback);

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

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    void InitializeCastCommands();

    void AddSessionCommandToCast(int32_t cmd);

    void RemoveSessionCommandFromCast(int32_t cmd);

    int32_t SessionCommandToCastCommand(int32_t cmd);

    int32_t RegisterListenerStreamToCast(const std::map<std::string, std::string>& serviceNameMapState);

    int32_t AddSupportCastCommand(int32_t cmd);

    bool IsCastRelevancyCommand(int32_t cmd);

    int32_t DeleteSupportCastCommand(int32_t cmd);

    void HandleCastValidCommandChange(std::vector<int32_t> &cmds);

    int32_t ReleaseCast() override;

    int32_t StartCast(const OutputDeviceInfo& outputDeviceInfo);

    int32_t AddDevice(const int64_t castHandle, const OutputDeviceInfo& outputDeviceInfo);

    int32_t StopCast();

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
    void HandleOnStop(const AVControlCommand& cmd);
    void HandleOnPlayNext(const AVControlCommand& cmd);
    void HandleOnPlayPrevious(const AVControlCommand& cmd);
    void HandleOnFastForward(const AVControlCommand& cmd);
    void HandleOnRewind(const AVControlCommand& cmd);
    void HandleOnSeek(const AVControlCommand& cmd);
    void HandleOnSetSpeed(const AVControlCommand& cmd);
    void HandleOnSetLoopMode(const AVControlCommand& cmd);
    void HandleOnToggleFavorite(const AVControlCommand& cmd);
    void HandleOnPlayFromAssetId(const AVControlCommand& cmd);

    void ReportConnectFinish(const std::string func, const DeviceInfo &deviceInfo);
    void ReportStopCastFinish(const std::string func, const DeviceInfo &deviceInfo);
    void SaveLocalDeviceInfo();

    using HandlerFuncType = void(AVSessionItem::*)(const AVControlCommand&);
    static inline HandlerFuncType cmdHandlers[SESSION_CMD_MAX] = {
        &AVSessionItem::HandleOnPlay,
        &AVSessionItem::HandleOnPause,
        &AVSessionItem::HandleOnStop,
        &AVSessionItem::HandleOnPlayNext,
        &AVSessionItem::HandleOnPlayPrevious,
        &AVSessionItem::HandleOnFastForward,
        &AVSessionItem::HandleOnRewind,
        &AVSessionItem::HandleOnSeek,
        &AVSessionItem::HandleOnSetSpeed,
        &AVSessionItem::HandleOnSetLoopMode,
        &AVSessionItem::HandleOnToggleFavorite,
        &AVSessionItem::HandleOnPlayFromAssetId,
        &AVSessionItem::HandleOnAVCallAnswer,
        &AVSessionItem::HandleOnAVCallHangUp,
        &AVSessionItem::HandleOnAVCallToggleCallMute,
    };

    std::recursive_mutex controllersLock_;
    std::map<pid_t, sptr<AVControllerItem>> controllers_;
    AVCallMetaData avCallMetaData_;
    AVCallState avCallState_;

    AVSessionDescriptor descriptor_;
    AVPlaybackState playbackState_;
    AVMetaData metaData_;
    std::recursive_mutex queueItemsLock_;
    std::vector<AVQueueItem> queueItems_;
    std::string queueTitle_;
    AbilityRuntime::WantAgent::WantAgent launchAbility_;
    AAFwk::WantParams extras_;
    std::vector<int32_t> supportedCmd_;
    std::vector<int32_t> supportedCastCmds_;
    std::recursive_mutex callbackLock_;
    sptr<IAVSessionCallback> callback_;
    std::recursive_mutex remoteCallbackLock_;
    std::shared_ptr<AVSessionCallback> remoteCallback_;
    std::function<void(AVSessionItem&)> serviceCallback_;
    std::function<void(AVSessionItem&)> callStartCallback_;
    friend class AVSessionDumper;

    std::recursive_mutex remoteSourceLock_;
    std::shared_ptr<RemoteSessionSource> remoteSource_;
    std::recursive_mutex remoteSinkLock_;
    std::shared_ptr<RemoteSessionSink> remoteSink_;

    std::function<void(AVSessionItem&)> serviceCallbackForAddAVQueueInfo_;

    int32_t castConnectStateForDisconnect_ = 5;
    int32_t castConnectStateForConnected_ = 6;
    int32_t removeCmdStep_ = 1000;
    
    std::recursive_mutex destroyLock_;
    volatile bool isDestroyed_ = false;

    std::recursive_mutex metaDataLock_;
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::recursive_mutex castHandleLock_;
    int64_t castHandle_ = 0;
    int32_t deviceStateAddCommand_ = 0;
    const int32_t streamStateConnection = 6;
    const int32_t virtualDeviceStateConnection = -6;
    const std::string deviceStateConnection = "CONNECT_SUCC";
    const int32_t firstStep = 1;
    const int32_t secondStep = 2;
    const int32_t playingState = 3;
    int32_t removeTimes = 0;
    int32_t newCastState = -1;
    int32_t counter_ = -1;
    bool isUpdate = false;
    std::map<std::string, std::string> castServiceNameMapState_;

    std::recursive_mutex castControllerProxyLock_;
    std::shared_ptr<IAVCastControllerProxy> castControllerProxy_;
    std::recursive_mutex castControllersLock_;
    std::vector<std::shared_ptr<AVCastControllerItem>> castControllers_;
    std::shared_ptr<CssListener> cssListener_;
    std::shared_ptr<IAVCastSessionStateListener> iAVCastSessionStateListener_;
    sptr<HwCastDisplayListener> displayListener_;
    std::recursive_mutex displayListenerLock_;

    std::map<std::string, DeviceInfo> castDeviceInfoMap_;
#endif
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_ITEM_H
