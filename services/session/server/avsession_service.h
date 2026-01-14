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

#ifndef OHOS_AVSESSION_SERVICE_H
#define OHOS_AVSESSION_SERVICE_H

#include <atomic>
#include <mutex>
#include <map>
#include <thread>

#include "iremote_stub.h"
#include "system_ability.h"
#include "audio_info.h"
#include "avsession_service_stub.h"
#include "avsession_item.h"
#include "avcontroller_item.h"
#include "session_container.h"
#include "iclient_death.h"
#include "isession_listener.h"
#include "ianco_media_session_listener.h"
#include "focus_session_strategy.h"
#include "background_audio_controller.h"
#include "ability_manager_adapter.h"
#ifdef DEVICE_MANAGER_ENABLE
#include "device_manager.h"
#include "dm_device_info.h"
#endif
#include "audio_adapter.h"
#include "remote_session_command_process.h"
#include "i_avsession_service_listener.h"
#include "avqueue_info.h"
#include "migrate/migrate_avsession_server.h"
#include "migrate/migrate_avsession_proxy.h"
#include "account_manager_adapter.h"
#include "app_manager_adapter.h"
#include "avsession_dynamic_loader.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_info.h"
#include "file_ex.h"
#include "iservice_registry.h"
#include "key_event_adapter.h"
#include "cJSON.h"
#include "session_stack.h"
#include "avsession_trace.h"
#include "avsession_dumper.h"
#include "command_send_limit.h"
#include "avsession_sysevent.h"
#include "json_utils.h"
#include "avsession_utils.h"
#include "avcontrol_command.h"
#include "avsession_event_handler.h"
#include "bundle_status_adapter.h"
#include "if_system_ability_manager.h"
#include "avsession_radar.h"
#include "system_ability_load_callback_stub.h"

#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "matching_skills.h"

#include "avsession_users_manager.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "av_router.h"
#include "collaboration_manager.h"
#include "pcm_cast_session.h"
#endif

namespace OHOS::AVSession {
class AVSessionDumper;

class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit ClientDeathRecipient(const std::function<void()>& callback);

    void OnRemoteDied(const wptr<IRemoteObject>& object) override;

private:
    std::function<void()> callback_;
};

#ifdef DEVICE_MANAGER_ENABLE
class AVSessionInitDMCallback : public OHOS::DistributedHardware::DmInitCallback {
public:
    AVSessionInitDMCallback() = default;
    ~AVSessionInitDMCallback() override = default;
    void OnRemoteDied() override {};
};
#endif

class AVSessionSystemAbilityLoadCallback : public SystemAbilityLoadCallbackStub {
public:
    explicit AVSessionSystemAbilityLoadCallback(AVSessionService *ptr);
    virtual ~AVSessionSystemAbilityLoadCallback();

    void OnLoadSACompleteForRemote(const std::string& deviceId,
        int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject);

private:
    AVSessionService *servicePtr_ = nullptr;
};

#ifdef DEVICE_MANAGER_ENABLE
class AVSessionDeviceStateCallback : public OHOS::DistributedHardware::DeviceStateCallback {
public:
    explicit AVSessionDeviceStateCallback(AVSessionService *ptr);
    virtual ~AVSessionDeviceStateCallback();

    void OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;

private:
    AVSessionService *servicePtr_ = nullptr;
};
#endif

class EventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    EventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo, AVSessionService *ptr);
    virtual ~EventSubscriber() = default;
    void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;
private:
    AVSessionService *servicePtr_ = nullptr;
};

class AVSessionService : public SystemAbility, public AVSessionServiceStub, public IAVSessionServiceListener,
    public AVSessionItemExtension {
    DECLARE_SYSTEM_ABILITY(AVSessionService);

public:
    DISALLOW_COPY_AND_MOVE(AVSessionService);

    explicit AVSessionService(int32_t systemAbilityId, bool runOnCreate = true);

    ~AVSessionService() override;

    void OnDump() override;

    void OnStart() override;

    void OnStartProcess();

    void OnStop() override;

    int32_t OnIdle(const SystemAbilityOnDemandReason& idleReason) override;

    void OnActive(const SystemAbilityOnDemandReason& activeReason) override;

    void PullMigrateStub();

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    int32_t GetSessionInner(const AppExecFwk::ElementName& elementName,
        std::string& tag, sptr<IRemoteObject>& session) override;

    sptr<IRemoteObject> CreateSessionInner(const std::string& tag, int32_t type,
                                           const AppExecFwk::ElementName& elementName) override;

    int32_t CreateSessionInner(const std::string& tag, int32_t type, const AppExecFwk::ElementName& elementName,
                               sptr<IRemoteObject>& object) override;

    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) override;

    int32_t GetSessionDescriptors(int32_t category, std::vector<AVSessionDescriptor>& descriptors) override;

    int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId, AVSessionDescriptor& descriptor) override;

    int32_t GetColdStartSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors);

    int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor>& descriptors) override;

    int32_t GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
                                      std::vector<AVQueueInfo>& avQueueInfos) override;

    int32_t StartAVPlayback(const std::string& bundleName, const std::string& assetId,
        const std::string& moduleName) override;

    int32_t StartAVPlayback(const std::string& bundleName, const std::string& assetId,
        const std::string& moduleName, const std::string& deviceId);

    int32_t RegisterAncoMediaSessionListener(const sptr<IAncoMediaSessionListener> &listener) override;

    int32_t HandleKeyEvent(const MMI::KeyEvent& keyEvent, const std::string& deviceId = "");

    int32_t CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) override;

    int32_t CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object, pid_t pid);

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t GetAVCastControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) override;
#endif

    int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) override;

    int32_t RegisterSessionListenerForAllUsers(const sptr<ISessionListener>& listener) override;

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) override;

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent, const AAFwk::Want &wantParam) override;

    int32_t SendSystemControlCommand(const AVControlCommand& command) override;

    int32_t RegisterClientDeathObserver(const sptr<IClientDeath>& observer) override;

    int32_t IsDesktopLyricSupported(bool &isSupported) override;

    void OnClientDied(pid_t pid, pid_t uid);

    void HandleSessionRelease(std::string sessionId, bool continuePlay = false);

    void HandleSessionReleaseInner();

    void HandleCallStartEvent();

    void HandleControllerRelease(AVControllerItem& controller);

    std::int32_t Dump(std::int32_t fd, const std::vector<std::u16string>& args) override;

    int32_t CastAudio(const SessionToken& token,
                      const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors) override;

    int32_t CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors) override;

    void NotifyAudioSessionCheckTrigger(const int32_t uid)
    {
        return NotifyAudioSessionCheck(uid);
    }

    void NotifyBackgroundReportCheck(const int32_t uid, const int32_t pid,
        AudioStandard::StreamUsage streamUsage, AudioStandard::RendererState rendererState);

    void SuperLauncher(std::string deviceId, std::string serviceName,
        std::string extraInfo, const std::string& state);

    void ReleaseSuperLauncher(std::string serviceName);

    void ConnectSuperLauncher(std::string deviceId, std::string serviceName);

    void SucceedSuperLauncher(std::string deviceId, std::string extraInfo);

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    void ReleaseCastSession() override;

    void CreateSessionByCast(const int64_t castHandle) override;

    void NotifyDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override;

    void NotifyDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) override;

    void NotifyDeviceOffline(const std::string& deviceId) override;

    void NotifyDeviceStateChange(const DeviceState& deviceState) override;

    void NotifyMirrorToStreamCast();

    bool IsMirrorToStreamCastAllowed(sptr<AVSessionItem>& session);

    __attribute__((no_sanitize("cfi"))) int32_t MirrorToStreamCast(sptr<AVSessionItem> session);

    void SetIsSupportMirrorToStream(bool isSupportMirrorToStream) override;

    void SplitExtraInfo(std::string info);

    int32_t StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo) override;

    int32_t StopCast(const SessionToken& sessionToken) override;

    int32_t StopSourceCast();

    int32_t checkEnableCast(bool enable) override;

    void setInCast(bool isInCast) override;
#endif

    int32_t Close(void) override;

    void AddAvQueueInfoToFile(AVSessionItem& session);

    std::string GetAVQueueDir(int32_t userId = 0);

    std::string GetAVSortDir(int32_t userId = 0);

    void HandleUserEvent(const std::string &type, const int &userId);

    void HandleRemoveMediaCardEvent(int32_t uid, bool isPhoto);

    void HandleBundleRemoveEvent(const std::string bundleName);

    void HandleMediaCardStateChangeEvent(std::string isAppear);

    void RegisterBundleDeleteEventForHistory(int32_t userId = 0);

    void NotifyMigrateStop(const std::string &deviceId);

    void InitCastEngineService();

#ifdef DEVICE_MANAGER_ENABLE
    bool ProcessTargetMigrate(bool isOnline, const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
#endif

    int32_t GetDistributedSessionControllersInner(const DistributedSessionType& sessionType,
        std::vector<sptr<IRemoteObject>>& sessionControllers) override;

    void NotifyRemoteDistributedSessionControllersChanged(
        const std::vector<sptr<IRemoteObject>>& sessionControllers);

    void NotifyRemoteBundleChange(const std::string bundleName);

    bool CheckIfOtherAudioPlaying();

    int32_t StartDesktopLyricAbility(const std::string &sessionId, const std::string &handler) override;

    int32_t StopDesktopLyricAbility();

    void SetDesktopLyricAbilityState(int32_t userId, int32_t state);

    int32_t GetDesktopLyricAbilityState(int32_t userId);

    int32_t UploadDesktopLyricOperationInfo(const std::string &sessionId,
        const std::string &handler, uint32_t sceneCode) override;

private:
    void NotifyProcessStatus(bool isStart);

    void SetCritical(bool isCritical);

    static SessionContainer& GetContainer();
    static AVSessionUsersManager& GetUsersManager();

    std::string AllocSessionId();

    bool AbilityHasSession(pid_t pid);

    sptr<AVControllerItem> GetPresentController(pid_t pid, const std::string& sessionId);

    void NotifySessionCreate(const AVSessionDescriptor& descriptor);
    void NotifySessionRelease(const AVSessionDescriptor& descriptor);
    void NotifyTopSessionChanged(const AVSessionDescriptor& descriptor);
    void NotifyAudioSessionCheck(const int32_t uid);
    void NotifySystemUI(sptr<AVSessionItem> photoSession, bool addCapsule, bool isCapsuleUpdate);
    void PublishEvent(int32_t mediaPlayState);

    void AddClientDeathObserver(pid_t pid, const sptr<IClientDeath>& observer,
        const sptr<ClientDeathRecipient> recipient);
    void RemoveClientDeathObserver(pid_t pid);

    void AddSessionListener(pid_t pid, const sptr<ISessionListener>& listener);
    void AddSessionListenerForAllUsers(pid_t pid, const sptr<ISessionListener>& listener);
    void RemoveSessionListener(pid_t pid);

    void AddInnerSessionListener(SessionListener* listener);
    void RemoveInnerSessionListener(SessionListener* listener);

    void AddHistoricalRecordListener(HistoricalRecordListener* listener);
    void RemoveHistoricalRecordListener(HistoricalRecordListener* listener);

    sptr<AVSessionItem> SelectSessionByUid(const AudioStandard::AudioRendererChangeInfo& info);

    std::function<bool(int32_t, int32_t)> GetAllowedPlaybackCallbackFunc();

    sptr<AVSessionItem> CreateSessionInner(const std::string& tag, int32_t type, bool thirdPartyApp,
                                           const AppExecFwk::ElementName& elementName);

    int32_t CreateSessionInner(const std::string& tag, int32_t type, bool thirdPartyApp,
                               const AppExecFwk::ElementName& elementName, sptr<AVSessionItem>& sessionItem);

    bool IsElementNameValid(const AppExecFwk::ElementName& elementName);

    bool IsParamInvalid(const std::string& tag, int32_t type, const AppExecFwk::ElementName& elementName);

    void AddExtraFrontSession(int32_t type, sptr<AVSessionItem>& sessionItem);

    void RefreshUserFromAnco(const std::string& tag, const AppExecFwk::ElementName& elementName);

    void ServiceCallback(sptr<AVSessionItem>& sessionItem);

    sptr<AVSessionItem> CreateNewSession(const std::string& tag, int32_t type, bool thirdPartyApp,
                                         const AppExecFwk::ElementName& elementName);

    sptr<AVControllerItem> CreateNewControllerForSession(pid_t pid, sptr<AVSessionItem>& session);

    int32_t CancelCastAudioForClientExit(pid_t pid, const sptr<AVSessionItem>& session);

    void ClearSessionForClientDiedNoLock(pid_t pid, bool continuePlay);

    void ClearControllerForClientDiedNoLock(pid_t pid);

    void InitKeyEvent();

    void InitAudio();

    void InitAMS();

    void InitDM();

    void InitBMS();

    void InitRadarBMS();

    void InitAccountMgr();

    void InitCommonEventService();

    void InitCollaboration();

    bool SelectFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo& info);

    void RefreshFocusSessionSort(sptr<AVSessionItem> &session);

    void UpdateTopSession(const sptr<AVSessionItem>& newTopSession, int32_t userId = 0);

    sptr<AVSessionItem> GetOtherPlayingSession(int32_t userId, std::string bundleName);

    void HandleOtherSessionPlaying(sptr<AVSessionItem>& session);

    void HandleFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo& info, bool isPlaying);

    __attribute__((no_sanitize("cfi"))) std::shared_ptr<RemoteSessionCommandProcess> GetService(
        const std::string& deviceId);

    int32_t CastAudioProcess(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors,
                             const std::string& sourceSessionInfo,
                             sptr<AVSessionItem>& session);

    int32_t CastAudioInner(const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors,
                           const std::string& sourceSessionInfo,
                           const sptr<AVSessionItem>& session);

    int32_t CancelCastAudioInner(const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkDevices,
                                 const std::string& sourceSessionInfo,
                                 const sptr<AVSessionItem>& session);

    int32_t RemoteCastAudioInner(const std::string& sourceSessionInfo, std::string& sinkSessionInfo);

    int32_t RemoteCancelCastAudioInner(const std::string& sessionInfo);

    int32_t ProcessCastAudioCommand(const RemoteServiceCommand command, const std::string& input,
                                    std::string& output) override;

    int32_t CastAudioForNewSession(const sptr<AVSessionItem>& session);

    bool IsLocalDevice(const std::string& networkId);

    int32_t GetLocalNetworkId(std::string& networkId);

    int32_t GetTrustedDeviceName(const std::string& networkId, std::string& deviceName);

    int32_t GetNotActiveSession(std::vector<AVSessionDescriptor>& descriptors);

#ifdef DEVICE_MANAGER_ENABLE
    int32_t GetTrustedDevicesInfo(std::vector<OHOS::DistributedHardware::DmDeviceInfo>& deviceList);
#endif

    int32_t SetBasicInfo(std::string& sessionInfo);

    void SetDeviceInfo(const std::vector<AudioStandard::AudioDeviceDescriptor>& castAudioDescriptors,
                           sptr<AVSessionItem>& session);

    int32_t GetAudioDescriptor(const std::string deviceId,
                               std::vector<AudioStandard::AudioDeviceDescriptor>& audioDeviceDescriptors);

    bool GetAudioDescriptorByDeviceId(
        const std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>>& descriptors,
        const std::string& deviceId,
        AudioStandard::AudioDeviceDescriptor& audioDescriptor);

    void GetDeviceInfo(const sptr<AVSessionItem>& session,
                           const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors,
                           std::vector<AudioStandard::AudioDeviceDescriptor>& castSinkDescriptors,
                           std::vector<AudioStandard::AudioDeviceDescriptor>& cancelSinkDescriptors);

    int32_t SelectOutputDevice(const int32_t uid, const AudioStandard::AudioDeviceDescriptor& descriptor);

    int32_t StartDefaultAbilityByCall(std::string& sessionId);

    int32_t StartAbilityByCall(const std::string& sessionIdNeeded, std::string& sessionId);

    void HandleEventHandlerCallBack();

    AVControlCommand GetSessionProcCommand();

    bool IsHistoricalSession(const std::string& sessionId);

    void DeleteHistoricalRecord(const std::string& bundleName, int32_t userId = 0);
    
    void DeleteAVQueueInfoRecord(const std::string& bundleName, int32_t userId = 0);

    bool SaveAvQueueInfo(std::string& oldContent, const std::string &bundleName, AVSessionItem& session);

    const cJSON* GetSubNode(const cJSON* nodeItem, const std::string& name);

    void SaveSessionInfoInFile(const std::string& tag, const std::string& sessionId,
        const std::string& sessionType, const AppExecFwk::ElementName& elementName);

    bool CheckAndCreateDir(const std::string& filePath);

    bool CheckUserDirValid(int32_t userId = 0);

    bool LoadStringFromFileEx(const std::string& filePath, std::string& content);

    bool SaveStringToFileEx(const std::string& filePath, const std::string& content);

    bool CheckStringAndCleanFile(const std::string& filePath);

    void ClearClientResources(pid_t pid, bool continuePlay);
    
    bool SaveAvQueueInfo(std::string& oldContent, const std::string &bundleName,
        const AVMetaData& meta, const int32_t userId);

    void DeleteAVQueueImage(cJSON* item);

    int32_t GetHistoricalSessionDescriptorsFromFile(std::vector<AVSessionDescriptor>& descriptors);

    int32_t UpdateControlListFromFile();

    void ReportStartCastBegin(std::string func, const OutputDeviceInfo& outputDeviceInfo, int32_t uid);

    void ReportStartCastEnd(std::string func, const OutputDeviceInfo &outputDeviceInfo, int32_t uid, int ret);
    
    void HandleAppStateChange(int uid, int state);

    void UpdateFrontSession(sptr<AVSessionItem>& sessionItem, bool isAdd);

    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> CreateWantAgent(sptr<AVSessionItem> photoSession);
    
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> CreateNftRemoveWant(int32_t uid, bool isPhoto);

    void DoMetadataImgClean(AVMetaData& data);

    void HandleSystemKeyColdStart(const AVControlCommand &command, const std::string deviceId = "");

    bool SubscribeCommonEvent();

    bool UnSubscribeCommonEvent();

    void ReportSessionInfo(const sptr <AVSessionItem>& session, int res);

    bool CheckAncoAudio();

    int32_t ConvertKeyCodeToCommand(int keyCode);

    void RemoveExpired(std::list<std::chrono::system_clock::time_point> &list,
        const std::chrono::system_clock::time_point &now, int32_t time = 1);

    void LowQualityCheck(int32_t uid, int32_t pid, AudioStandard::StreamUsage streamUsage,
        AudioStandard::RendererState rendererState);

    void PlayStateCheck(int32_t uid, AudioStandard::StreamUsage streamUsage,
        AudioStandard::RendererState rState);

    std::shared_ptr<std::list<sptr<AVSessionItem>>> GetCurSessionListForFront(int32_t userId = 0);

    std::shared_ptr<std::list<sptr<AVSessionItem>>> GetCurKeyEventSessionList(int32_t userId = 0);

    void AddCapsuleServiceCallback(sptr<AVSessionItem>& sessionItem);

    void AddKeyEventServiceCallback(sptr<AVSessionItem>& sessionItem);

    void AddUpdateTopServiceCallback(sptr<AVSessionItem>& sessionItem);

    void AddCastCapsuleServiceCallback(sptr<AVSessionItem>& sessionItem);

    void AddAncoColdStartServiceCallback(sptr<AVSessionItem>& session);

    void AddCastServiceCallback(sptr<AVSessionItem>& sessionItem);

    bool VerifyNotification();

    void HandleChangeTopSession(int32_t infoUid, int32_t infoPid, int32_t userId);

    bool UpdateOrder(sptr<AVSessionItem>& sessionItem);

    bool IsTopSessionPlaying();

    bool IsLocalSessionPlaying(const sptr<AVSessionItem>& session);

    bool NotifyFlowControl();

    bool IsCapsuleNeeded();

    int32_t GetLocalDeviceType();

    void DoTargetDevListenWithDM();

    void DoRemoteAVSessionLoad(std::string remoteDeviceId);

#ifdef DEVICE_MANAGER_ENABLE
    void DoConnectProcessWithMigrate(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);

    void DoConnectProcessWithMigrateServer(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);

    void DoConnectProcessWithMigrateProxy(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);

    void DoDisconnectProcessWithMigrate(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);

    void DoDisconnectProcessWithMigrateServer(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);

    void DoDisconnectProcessWithMigrateProxy(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
#endif

    int32_t DoHisMigrateServerTransform(std::string networkId);

    void UpdateLocalFrontSession(std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront);

    void NotifyLocalFrontSessionChangeForMigrate(std::string localFrontSessionIdUpdate);

#ifdef DEVICE_MANAGER_ENABLE
    bool CheckWhetherTargetDevIsNext(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
#endif

    void NotifyHistoricalRecordChange(const std::string& bundleName, int32_t userId);

    void NotifySessionChange(std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront,
        int32_t userId = 0);

    void NotifyActiveSessionChange(const std::vector<AVSessionDescriptor> &descriptors);

    std::string GetLocalTitle();

    void DealFlowControl(int32_t uid, bool isBroker);

    bool InsertSessionItemToCJSON(sptr<AVSessionItem> &session, cJSON* valuesArray);

    bool InsertSessionItemToCJSONAndPrint(const std::string& tag, const std::string& sessionId,
        const std::string& sessionType, const AppExecFwk::ElementName& elementName, cJSON* valuesArray);

    void ProcessDescriptorsFromCJSON(std::vector<AVSessionDescriptor>& descriptors, cJSON* valueItem);

    void ProcessAvQueueInfosFromCJSON(std::vector<AVQueueInfo>& avQueueInfos, cJSON* valueItem);

    bool InsertAvQueueInfoToCJSONAndPrint(const std::string &bundleName,
        const AVMetaData& meta, const int32_t userId, cJSON* valuesArray);

    bool GetDefaultAbilityElementNameFromCJSON(std::string& sortContent,
        std::string& bundleName, std::string& abilityName);

    bool GetElementNameBySessionIdFromCJSON(std::string& sortContent, const std::string& sessionIdNeeded,
        std::string& bundleName, std::string& abilityName);

    void DeleteAVQueueInfoRecordFromCJSON(std::string& sortContent, const std::string& bundleName, int32_t userId);

    bool FillFileWithEmptyContentEx(ofstream& fileWrite);

    void CheckAndUpdateAncoMediaSession(const AppExecFwk::ElementName& elementName);

    void UpdateSessionTimestamp(sptr<AVSessionItem> session);

    bool CheckSessionHandleKeyEvent(bool procCmd, AVControlCommand cmd, const MMI::KeyEvent& keyEvent,
        sptr<AVSessionItem> session, const std::string& deviceId = "");

    bool IsAncoValid();

    std::string DoCJSONArrayTransformToString(cJSON* valueItem);

    void HandleTopSessionRelease(int32_t userId, sptr<AVSessionItem>& sessionItem);

    bool ProcTopSessionPlaying(sptr<AVSessionItem> session, bool isPlaying, bool isMediaChange);

    bool CheckStartAncoMediaPlay(const std::string& bundleName, int32_t *result);

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    void ReportSessionState(const sptr<AVSessionItem>& session, SessionState state);
    void ReportSessionControl(const std::string& bundleName, int32_t cmd);
#endif

    void SubscribeBundleStatusIfNeeded(const std::string& oldSortContent, const std::string& bundleName);

    std::atomic<uint32_t> sessionSeqNum_ {};
    std::atomic<bool> isMediaCardOpen_ = false;
    std::atomic<bool> hasRemoveEvent_ = false;
    std::atomic<bool> hasMediaCapsule_ = false;
    std::atomic<bool> hasCardStateChangeStopTask_ = false;

    sptr<AVSessionItem> topSession_;
    sptr<AVSessionItem> ancoSession_;
    std::map<pid_t, std::list<sptr<AVControllerItem>>> controllers_;
    std::map<pid_t, sptr<IClientDeath>> clientDeathObservers_;
    std::map<pid_t, sptr<ClientDeathRecipient>> clientDeathRecipients_;
    std::list<SessionListener*> innerSessionListeners_;
    std::list<HistoricalRecordListener*> historicalRecordListeners_;
    std::map<std::string, std::shared_ptr<AbilityManagerAdapter>> abilityManager_;
    FocusSessionStrategy focusSessionStrategy_;
    BackgroundAudioController backgroundAudioController_;
    std::map<std::string, std::string> castAudioSessionMap_;
    bool isAllSessionCast_ {};
    std::string outputDeviceId_;
    std::unique_ptr<AVSessionDumper> dumpHelper_ {};
    friend class AVSessionDumper;
    std::shared_ptr<MigrateAVSessionServer> migrateAVSession_;
    std::shared_ptr<EventSubscriber> subscriber_;
    bool isScreenOn_ = false;
    bool isScreenLocked_ = true;
    std::list<std::chrono::system_clock::time_point> flowControlPublishTimestampList_;
    std::function<bool(int32_t, int32_t)> queryAllowedPlaybackCallbackFunc_;
    sptr<IAncoMediaSessionListener> ancoMediaSessionListener_;
    std::set<std::string> controlBundleNameSet_;
    void SetCriticalWhenCreate(sptr<AVSessionItem> sessionItem);
    void SetCriticalWhenRelease(sptr<AVSessionItem> sessionItem);

    // The following locks are used in the defined order of priority
    std::recursive_mutex sessionServiceLock_;

    std::recursive_mutex sessionFrontLock_;

    std::recursive_mutex sessionListenersLock_;

    std::recursive_mutex migrateListenersLock_;

    std::recursive_mutex sessionFileLock_;

    std::recursive_mutex avQueueFileLock_;

    std::recursive_mutex abilityManagerLock_;

    std::recursive_mutex screenStateLock_;

    std::recursive_mutex clientDeathLock_;

    std::recursive_mutex notifyLock_;

    std::recursive_mutex audioBrokerLock_;

    // DMSDP related locks
    std::recursive_mutex isAllSessionCastLock_;

    std::recursive_mutex outputDeviceIdLock_;

    std::recursive_mutex castAudioSessionMapLock_;

    std::recursive_mutex keyEventListLock_;

    std::recursive_mutex historicalRecordListenersLock_;

    std::recursive_mutex controlListLock_;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::pair<std::string, std::string> castServiceNameStatePair_;
    const std::string deviceStateConnection = "CONNECT_SUCC";
    const std::string deviceStateDisconnection = "IDLE";
    const std::string seperator = ",";
    int appState = -1;
    std::atomic<bool> isSupportMirrorToStream_ = false;
    std::atomic<bool> appCastExit_ = false;
    std::string castDeviceId_ = "0";
    std::string castDeviceName_ = " ";
    int32_t castDeviceType_ = 0;
    std::mutex checkEnableCastMutex_;
    std::recursive_mutex checkEnableCastLock_;
    std::unordered_set<pid_t> cacheEnableCastPids_;
    bool cancelCastRelease_ = false;
    std::condition_variable enableCastCond_;
    const int32_t castReleaseTimeOut_ = 120;
    shared_ptr<PcmCastSession> pcmCastSession_ = nullptr;
#endif

    static constexpr const char *SORT_FILE_NAME = "sortinfo";
    static constexpr const char *DEFAULT_SESSION_ID = "default";
    static constexpr const char *DEFAULT_BUNDLE_NAME = "com.example.himusicdemo";
    static constexpr const char *DEFAULT_ABILITY_NAME = "MainAbility";
    static constexpr const char *AVQUEUE_FILE_NAME = "avqueueinfo";
    static constexpr const char *sessionCastState_ = "CAST_STATE";
    static constexpr const char *controlListFile = "/data/service/el2/public/av_session/controlList";

    const std::string MEDIA_CONTROL_BUNDLENAME = "com.ohos.mediacontroller";
    const std::string MEDIA_CONTROL_ABILITYNAME = "com.ohos.mediacontroller.avplayer.mainability";
    const std::string MEDIA_CONTROL_STATE = "usual.event.MEDIA_CONTROL_STATE";
    const std::string MEDIA_PLAY_STATE = "MediaPlaybackState";

    int32_t pressCount_ {};
    int32_t maxHistoryNums_ = 10;
    bool isFirstPress_ = true;
    bool isInCast_ = false;
    bool isCastableDevice_ = false;
    bool isAudioBrokerStart_ = false;
    bool isAncoMediaSessionChange_ = false;

    void *migrateStubFuncHandle_ = nullptr;

#ifdef DEVICE_MANAGER_ENABLE
    std::shared_ptr<AVSessionDeviceStateCallback> deviceStateCallback_ = nullptr;
    int32_t localDeviceType_ = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    int32_t targetDeviceType_ = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
#endif
    const std::string serviceName = "av_session";
    std::string deviceIdForMigrate_ = "";
    std::string localFrontSessionId_ = "";
    bool isMigrateTargetFound_ = false;
    std::map<std::string, std::shared_ptr<MigrateAVSessionServer>> migrateAVSessionServerMap_;
    std::map<std::string, std::shared_ptr<SoftbusSession>> migrateAVSessionProxyMap_;
    std::recursive_mutex migrateProxyMapLock_;
    std::set<std::string> controlListForNtf_ = {"com.ohos.mediacontroller"};

    std::map<int32_t, int32_t> desktopLyricAbilityStateMap_;
    std::mutex desktopLyricAbilityStateMutex_;

    const int32_t ONE_CLICK = 1;
    const int32_t DOUBLE_CLICK = 2;
    const int32_t THREE_CLICK = 3;
    const int32_t unSetHistoryNum = 3;
    const int32_t CLICK_TIMEOUT = 500;
    const int32_t lowQualityTimeout = 1000;
    const int32_t errorStateTimeout = 3 * 1000;
    const int32_t defMaxHistoryNum = 10;
    const int32_t maxFileLength = 32 * 1024 * 1024;
    const int32_t maxAVQueueInfoLen = 99;
    const int32_t allocSpace = 2;
    const int32_t avSessionUid = 6700;
    const int32_t ancoUid = 1041;
    const int32_t audioBrokerUid = 5557;
    const int32_t saType = 1;
    const int32_t remoteMediaNone = 4;
    const int32_t remoteMediaAlive = 3;
    const int32_t mediaPlayStateTrue = 1;
    const int32_t mediaPlayStateFalse = 0;
    const uint32_t MAX_NOTIFICATION_NUM = 3;
    const int32_t NOTIFICATION_CONTROL_TIME = 1000;
    const int32_t cancelTimeout = 5000;
    const uint8_t doRemoteLoadRetryTime = 5;
    const int32_t defaultUserId = 100;
    const int32_t mediaControlAncoParam = 52225;
    const int32_t otherPlayingSessionMinLen = 2;
    const int32_t systemuiLiveviewTypeCodeMediacontroller = 2;
    const int32_t systemuiLiveviewTypeCodePhoto = 27;
    const int32_t mediacontrollerNotifyId = 0;
    const int32_t photoNotifyId = 1;

    const std::string sessionTypePhoto = "photo";
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVICE_H
