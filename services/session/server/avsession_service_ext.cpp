/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "audio_device_manager.h"
#include "avsession_service.h"
#include "migrate_avsession_manager.h"
#include "cast_engine_common.h"

namespace OHOS::AVSession {
void AVSessionService::SuperLauncher(std::string deviceId, std::string serviceName,
    std::string extraInfo, const std::string& state)
{
    SLOGI("SuperLauncher serviceName: %{public}s, state: %{public}s", serviceName.c_str(), state.c_str());

    if (serviceName == "SuperLauncher-Dual") {
        if (state == "IDLE") {
            ReleaseSuperLauncher(serviceName);
        } else if (state == "CONNECTING") {
            ConnectSuperLauncher(deviceId, serviceName);
        } else if (state == "CONNECT_SUCC") {
            SucceedSuperLauncher(deviceId, extraInfo);
        }
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if ((serviceName == "HuaweiCast" || serviceName == "HuaweiCast-Dual") &&
        (state == "IDLE" || state == "CONNECT_SUCC")) {
        castServiceNameStatePair_ = std::make_pair(serviceName, state);
        isSupportMirrorToStream_ = false;
        appCastExit_ = false;
        castDeviceId_ = "0";
        castDeviceName_ = " ";
        castDeviceType_ = 0;
        SplitExtraInfo(extraInfo);
        NotifyMirrorToStreamCast();
        if (state == "IDLE") {
            SLOGI("call disable cast for cast idle");
            checkEnableCast(false);
        }
    }
#endif
}

void AVSessionService::ReleaseSuperLauncher(std::string serviceName)
{
    AudioDeviceManager::GetInstance().UnInitAudioStateCallback();
    MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(serviceName);
    if (migrateAVSession_ != nullptr) {
        RemoveInnerSessionListener(migrateAVSession_.get());
        RemoveHistoricalRecordListener(migrateAVSession_.get());
    }
}

void AVSessionService::ConnectSuperLauncher(std::string deviceId, std::string serviceName)
{
    if (migrateAVSession_ == nullptr) {
        migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
    }
    migrateAVSession_->Init(this);
    MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(serviceName, migrateAVSession_);
    AddInnerSessionListener(migrateAVSession_.get());
    AddHistoricalRecordListener(migrateAVSession_.get());
    AudioDeviceManager::GetInstance().InitAudioStateCallback(migrateAVSession_, deviceId);
}

void AVSessionService::SucceedSuperLauncher(std::string deviceId, std::string extraInfo)
{
    if (migrateAVSession_ == nullptr) {
        migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
    }
    migrateAVSession_->ResetSupportCrossMediaPlay(extraInfo);
    migrateAVSession_->SendRemoteHistorySessionList(deviceId);
}

void AVSessionService::NotifyMigrateStop(const std::string &deviceId)
{
    if (migrateAVSession_ == nullptr) {
        SLOGI("NotifyMigrateStop without migrate, create new");
        migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
    }
    std::lock_guard lockGuard(sessionServiceLock_);
    migrateAVSession_->StopObserveControllerChanged(deviceId);
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
void AVSessionService::SplitExtraInfo(std::string info)
{
    cJSON* extraInfo = cJSON_Parse(info.c_str());
    bool extraInfoFlag = (extraInfo == nullptr) || cJSON_IsInvalid(extraInfo) || cJSON_IsNull(extraInfo);
    if (extraInfoFlag) {
        SLOGE("extraInfo parse is not valid json");
        cJSON_Delete(extraInfo);
        return;
    }

    cJSON* supportMirrorToStreamItem = cJSON_GetObjectItem(extraInfo, "SUPPORT_MIRROR_TO_STREAM");
    CHECK_AND_PRINT_LOG(supportMirrorToStreamItem != nullptr, "supportMirrorToStreamItem is nullptr");
    bool supportMirrorToStreamItemFlag = (supportMirrorToStreamItem != nullptr) &&
        !cJSON_IsInvalid(supportMirrorToStreamItem) && !cJSON_IsNull(supportMirrorToStreamItem) &&
        cJSON_IsBool(supportMirrorToStreamItem) && cJSON_IsTrue(supportMirrorToStreamItem);
    isSupportMirrorToStream_ = supportMirrorToStreamItemFlag ? cJSON_IsTrue(supportMirrorToStreamItem) : false;

    cJSON* appCastExitItem = cJSON_GetObjectItem(extraInfo, "appCastExit");
    CHECK_AND_PRINT_LOG(appCastExitItem != nullptr, "appCastExitItem is nullptr");
    bool appCastExitItemFlag = (appCastExitItem != nullptr) && !cJSON_IsInvalid(appCastExitItem) &&
        !cJSON_IsNull(appCastExitItem) && cJSON_IsBool(appCastExitItem) && cJSON_IsTrue(appCastExitItem);
    appCastExit_ = appCastExitItemFlag ? cJSON_IsTrue(appCastExitItem) : false;

    cJSON* deviceIdItem = cJSON_GetObjectItem(extraInfo, "deviceId");
    CHECK_AND_PRINT_LOG(deviceIdItem != nullptr, "deviceIdItem is nullptr");
    bool deviceIdItemFlag = (deviceIdItem != nullptr) && !cJSON_IsInvalid(deviceIdItem) &&
        !cJSON_IsNull(deviceIdItem) && cJSON_IsString(deviceIdItem) && deviceIdItem->valuestring != nullptr;
    castDeviceId_ = deviceIdItemFlag ? std::string(deviceIdItem->valuestring) : "0";

    cJSON* deviceNameItem = cJSON_GetObjectItem(extraInfo, "deviceName");
    CHECK_AND_PRINT_LOG(deviceNameItem != nullptr, "deviceNameItem is nullptr");
    bool deviceNameItemFlag = (deviceNameItem != nullptr) && !cJSON_IsInvalid(deviceNameItem) &&
        !cJSON_IsNull(deviceNameItem) && cJSON_IsString(deviceNameItem) && deviceNameItem->valuestring != nullptr;
    castDeviceName_ = deviceNameItemFlag ? std::string(deviceNameItem->valuestring) : " ";

    cJSON* deviceTypeItem = cJSON_GetObjectItem(extraInfo, "deviceType");
    CHECK_AND_PRINT_LOG(deviceTypeItem != nullptr, "deviceTypeItem is nullptr");
    bool deviceTypeItemFlag = (deviceTypeItem != nullptr) && !cJSON_IsInvalid(deviceTypeItem) &&
        !cJSON_IsNull(deviceTypeItem) && cJSON_IsNumber(deviceTypeItem);
    castDeviceType_ = deviceTypeItemFlag ? deviceTypeItem->valueint : 0;
    cJSON_Delete(extraInfo);
}
#endif

void AVSessionService::AddInnerSessionListener(SessionListener *listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    innerSessionListeners_.push_back(listener);
}

void AVSessionService::RemoveInnerSessionListener(SessionListener *listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (auto it = innerSessionListeners_.begin(); it != innerSessionListeners_.end();) {
        if (*it == listener) {
            SLOGI("RemoveInnerSessionListener");
            it = innerSessionListeners_.erase(it);
        } else {
            it++;
        }
    }
}

void AVSessionService::AddHistoricalRecordListener(HistoricalRecordListener *listener)
{
    std::lock_guard lockGuard(historicalRecordListenersLock_);
    historicalRecordListeners_.push_back(listener);
}

void AVSessionService::RemoveHistoricalRecordListener(HistoricalRecordListener *listener)
{
    std::lock_guard lockGuard(historicalRecordListenersLock_);
    for (auto it = historicalRecordListeners_.begin(); it != historicalRecordListeners_.end();) {
        if (*it == listener) {
            SLOGI("RemoveHistoricalRecordListener");
            it = historicalRecordListeners_.erase(it);
        } else {
            it++;
        }
    }
}

void AVSessionService::NotifyHistoricalRecordChange(const std::string& bundleName, int32_t userId)
{
    std::lock_guard lockGuard(historicalRecordListenersLock_);
    for (const auto& listener : historicalRecordListeners_) {
        if (listener != nullptr) {
            listener->OnHistoricalRecordChange();
        }
    }
}

// LCOV_EXCL_START
void AVSessionService::HandleAppStateChange(int uid, int state)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGD("uid = %{public}d, state = %{public}d", uid, state);
    if (topSession_ != nullptr && topSession_->GetUid() == uid) {
        if (state == appState) {
            return;
        }
        if (state == static_cast<int>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND)) {
            SLOGI("enter notifyMirrorToStreamCast by background to foreground state change, and counts = 2");
            MirrorToStreamCast(topSession_);
        }
        appState = state;
    }
#endif //CASTPLUS_CAST_ENGINE_ENABLE
}
// LCOV_EXCL_STOP

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionService::GetAVCastControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object)
{
    SLOGI("Start get cast controller with pid %{public}d", static_cast<int>(GetCallingPid()));
    auto session = GetContainer().GetSessionById(sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "StopCast: session is not exist");
    auto result = session->GetAVCastControllerInner();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, AVSESSION_ERROR, "GetAVCastControllerInner failed");
    object = result;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::checkEnableCast(bool enable)
{
    std::lock_guard lockGuard(checkEnableCastLock_);
    SLOGI("checkEnableCast enable:%{public}d, isInCast:%{public}d, calling pid:%{public}d",
        enable, isInCast_, GetCallingPid());
    enable ? (void)cacheEnableCastPids_.insert(GetCallingPid()) : (void)cacheEnableCastPids_.erase(GetCallingPid());
    GetCallingUid() == avSessionUid ? (void)cacheEnableCastPids_.erase(GetCallingPid()) : (void)0;
    if (enable && !cancelCastRelease_) {
        cancelCastRelease_ = true;
        enableCastCond_.notify_all();
    }
    
    if (enable == true && isInCast_ == false) {
        isInCast_ = AVRouter::GetInstance().Init(this) == AVSESSION_SUCCESS ? true : false;
    } else if (enable == false && isInCast_ == true) {
        cancelCastRelease_ = false;
        std::thread([this]() {
            std::unique_lock<std::mutex> lock(checkEnableCastMutex_);
            CHECK_AND_RETURN_LOG(!enableCastCond_.wait_for(lock, std::chrono::seconds(castReleaseTimeOut_),
                [this]() { return cancelCastRelease_; }), "cancel cast release");
            std::lock_guard threadLockGuard(checkEnableCastLock_);
            CHECK_AND_RETURN_LOG(!AVRouter::GetInstance().IsRemoteCasting(),
                "can not release cast with session casting");
            CHECK_AND_RETURN_LOG(castServiceNameStatePair_.second != deviceStateConnection,
                "can not release cast with casting");
            CHECK_AND_RETURN_LOG(cacheEnableCastPids_.empty(),
                "can not release cast with pid still calling");
            isInCast_ = AVRouter::GetInstance().Release();
        }).detach();
    } else {
        SLOGD("AVRouter Init in nothing change");
    }
    return AVSESSION_SUCCESS;
}

void AVSessionService::setInCast(bool isInCast)
{
    SLOGI("setInCast, isInCast:%{public}d", isInCast);
    isInCast_ = isInCast;
}

// LCOV_EXCL_START
void AVSessionService::ReleaseCastSession()
{
    std::lock_guard lockGuard(sessionServiceLock_);
    SLOGI("Start release cast session");
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session != nullptr && session->GetDescriptor().sessionTag_ == "RemoteCast") {
            std::string sessionId = session->GetDescriptor().sessionId_;
            SLOGI("Already has a cast session %{public}s", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
            session->UnRegisterDeviceStateCallback();
            session->StopCastSession();
            session->ReleaseAVCastControllerInner();
            HandleSessionRelease(sessionId);
        }
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void AVSessionService::CreateSessionByCast(const int64_t castHandle)
{
    SLOGI("AVSessionService CreateSessionByCast in");
    AVSessionRadarInfo info("AVSessionService::CreateSessionByCast");
    AVSessionRadar::GetInstance().StartConnect(info);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("castBundleName");
    elementName.SetAbilityName("castAbilityName");
    sptr<AVSessionItem> sinkSession;
    auto res = CreateSessionInner("RemoteCast", AVSession::SESSION_TYPE_AUDIO, false, elementName, sinkSession);
    CHECK_AND_RETURN_LOG(res == AVSESSION_SUCCESS, "CreateSession at sink failed");
    SLOGI("Create Cast sink sessionId %{public}s",
        AVSessionUtils::GetAnonySessionId(sinkSession->GetSessionId()).c_str());
    sinkSession->SetCastHandle(castHandle);
    sinkSession->RegisterDeviceStateCallback();
    
    {
        std::lock_guard frontLockGuard(sessionFrontLock_);
        std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront =
            GetUsersManager().GetCurSessionListForFront(0);
        CHECK_AND_RETURN_LOG(sessionListForFront != nullptr, "sessionListForFront ptr nullptr!");
        auto it = std::find(sessionListForFront->begin(), sessionListForFront->end(), sinkSession);
        if (it == sessionListForFront->end()) {
            SLOGI(" front session add cast session");
            sessionListForFront->push_front(sinkSession);
        }
    }

    HISYSEVENT_BEHAVIOR("SESSION_CAST",
        "BUNDLE_NAME", "castBundleName",
        "ABILITY_NAME", "castAbilityName",
        "SESSION_PID", sinkSession->GetDescriptor().pid_,
        "SESSION_UID", sinkSession->GetDescriptor().uid_,
        "SESSION_ID", sinkSession->GetDescriptor().sessionId_,
        "SESSION_TAG", sinkSession->GetDescriptor().sessionTag_,
        "SESSION_TYPE", sinkSession->GetDescriptor().sessionType_,
        "DETAILED_MSG", "session create from cast+ callback");
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void AVSessionService::NotifyDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo)
{
    AVSessionRadarInfo info("AVSessionService::NotifyDeviceAvailable");
    AVSessionRadar::GetInstance().CastDeviceAvailable(castOutputDeviceInfo, info);

    for (DeviceInfo deviceInfo : castOutputDeviceInfo.deviceInfos_) {
        for (const auto& session : GetContainer().GetAllSessions()) {
            session->UpdateCastDeviceMap(deviceInfo);
        }
    }
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        listener->OnDeviceAvailable(castOutputDeviceInfo);
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMap = GetUsersManager().GetSessionListener();
    for (const auto& [pid, listener] : listenerMap) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceAvailable");
        listener->OnDeviceAvailable(castOutputDeviceInfo);
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMapForAll = GetUsersManager().GetSessionListenerForAllUsers();
    for (const auto& [pid, listener] : listenerMapForAll) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceAvailable");
        listener->OnDeviceAvailable(castOutputDeviceInfo);
    }
}
// LCOV_EXCL_STOP

void AVSessionService::NotifyDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    std::map<pid_t, sptr<ISessionListener>> listenerMap = GetUsersManager().GetSessionListener();
    for (const auto& [pid, listener] : listenerMap) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceLogEvent");
        listener->OnDeviceLogEvent(eventId, param);
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMapForAll = GetUsersManager().GetSessionListenerForAllUsers();
    for (const auto& [pid, listener] : listenerMapForAll) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceLogEvent");
        listener->OnDeviceLogEvent(eventId, param);
    }
}

// LCOV_EXCL_START
void AVSessionService::NotifyDeviceOffline(const std::string& deviceId)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        listener->OnDeviceOffline(deviceId);
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMap = GetUsersManager().GetSessionListener();
    for (const auto& [pid, listener] : listenerMap) {
        SLOGI("notify device offline with pid %{public}d", static_cast<int>(pid));
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceOffline");
        listener->OnDeviceOffline(deviceId);
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMapForAll = GetUsersManager().GetSessionListenerForAllUsers();
    for (const auto& [pid, listener] : listenerMapForAll) {
        SLOGI("notify device offline with pid %{public}d across users", static_cast<int>(pid));
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceOffline");
        listener->OnDeviceOffline(deviceId);
    }
}
// LCOV_EXCL_STOP

void AVSessionService::NotifyDeviceStateChange(const DeviceState& deviceState)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    std::map<pid_t, sptr<ISessionListener>> listenerMap = GetUsersManager().GetSessionListener();
    for (const auto& [pid, listener] : listenerMap) {
        SLOGI("notify device state change with pid %{public}d", static_cast<int>(pid));
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceStateChange");
        if (listener != nullptr) {
            listener->OnDeviceStateChange(deviceState);
        }
    }
}

int32_t AVSessionService::StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("SessionId is %{public}s", AVSessionUtils::GetAnonySessionId(sessionToken.sessionId).c_str());
    CHECK_AND_RETURN_RET_LOG(outputDeviceInfo.deviceInfos_.size() > 0, ERR_INVALID_PARAM, "empty device info");

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    bool isPcm = (outputDeviceInfo.deviceInfos_[0].supportedProtocols_ & ProtocolType::TYPE_CAST_PLUS_AUDIO) != 0;
    if (isPcm) {
        pcmCastSession_ = std::make_shared<PcmCastSession>();
        return pcmCastSession_->StartCast(outputDeviceInfo, castServiceNameStatePair_);
    }
#endif //CASTPLUS_CAST_ENGINE_ENABLE

    sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionToken.sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, ERR_SESSION_NOT_EXIST, "session %{public}s not exist",
        AVSessionUtils::GetAnonySessionId(sessionToken.sessionId).c_str());
    ReportStartCastBegin("AVSessionService::StartCast", outputDeviceInfo, session->GetDescriptor().uid_);
    int32_t ret = session->StartCast(outputDeviceInfo);
    ReportStartCastEnd("AVSessionService::StartCast", outputDeviceInfo, session->GetDescriptor().uid_, ret);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "StartCast failed");
    SLOGD("StartCast set isSourceInCast");

    SLOGI("no set continuous task in service");
    HISYSEVENT_BEHAVIOR("SESSION_CAST",
        "BUNDLE_NAME", session->GetDescriptor().elementName_.GetBundleName(),
        "MODULE_NAME", session->GetDescriptor().elementName_.GetModuleName(),
        "ABILITY_NAME", session->GetDescriptor().elementName_.GetAbilityName(),
        "SESSION_PID", session->GetDescriptor().pid_, "SESSION_UID", session->GetDescriptor().uid_,
        "SESSION_ID", session->GetDescriptor().sessionId_, "SESSION_TAG", session->GetDescriptor().sessionTag_,
        "SESSION_TYPE", session->GetDescriptor().sessionType_, "DETAILED_MSG", "start cast session");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::StopCast(const SessionToken& sessionToken)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (pcmCastSession_ != nullptr) {
        pcmCastSession_->StopCast();
        pcmCastSession_ = nullptr;
    }
#endif //CASTPLUS_CAST_ENGINE_ENABLE

    sptr<AVSessionItem> session = GetUsersManager().GetContainerFromAll().GetSessionById(sessionToken.sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_SUCCESS, "StopCast: session is not exist");
    CHECK_AND_RETURN_RET_LOG(session->StopCast() == AVSESSION_SUCCESS, AVSESSION_ERROR, "StopCast failed");
    if (session->GetDescriptor().sessionTag_ == "RemoteCast") {
        SLOGI("Stop cast at sink, start destroy sink avsession task");
        HandleSessionRelease(sessionToken.sessionId);
        return AVSESSION_SUCCESS;
    }

    SLOGI("no set continuous task in service");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::StopSourceCast()
{
    for (const auto& session : GetContainer().GetAllSessions()) {
        CHECK_AND_RETURN_RET(session != nullptr, AVSESSION_SUCCESS);
        CHECK_AND_RETURN_RET(session->IsCasting(), AVSESSION_SUCCESS);
        session->SetMultiDeviceState(AVSessionItem::MultiDeviceState::CASTING_AND_CASTED);
        CHECK_AND_RETURN_RET(session->StopCast() == AVSESSION_SUCCESS, AVSESSION_ERROR);
    }

    return AVSESSION_SUCCESS;
}

void AVSessionService::NotifyMirrorToStreamCast()
{
    for (auto& session : GetContainer().GetAllSessions()) {
        if (session && topSession_ && (session.GetRefPtr() == topSession_.GetRefPtr())) {
            MirrorToStreamCast(session);
        }
    }
    if (castServiceNameStatePair_.second == deviceStateDisconnection) {
        DeviceInfo localDeviceInfo;
        AVRouter::GetInstance().SetServiceAllConnectState(-1, localDeviceInfo);
    }
}

bool AVSessionService::IsMirrorToStreamCastAllowed(sptr<AVSessionItem>& session)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, false, "session is nullptr");
    bool deviceCond = isSupportMirrorToStream_ && !appCastExit_;
    
    CHECK_AND_RETURN_RET_LOG(deviceCond, false, "deviceCond is false");
    bool connectCond = castServiceNameStatePair_.second == deviceStateConnection;

    CHECK_AND_RETURN_RET_LOG(deviceCond && connectCond, false, "connectCond is false");
    std::string bundleName = session->GetBundleName();
    bool isWhiteApp = std::find(CastEngine::MIRROR_TO_STREAM_APP_LIST.begin(),
        CastEngine::MIRROR_TO_STREAM_APP_LIST.end(), bundleName) != CastEngine::MIRROR_TO_STREAM_APP_LIST.end();
    bool appCond = session->IsAppSupportCast() && isWhiteApp &&
                   session->GetDescriptor().sessionType_ == AVSession::SESSION_TYPE_VIDEO &&
                   !AppManagerAdapter::GetInstance().IsAppBackground(session->GetUid(), session->GetPid());

    return deviceCond && connectCond && appCond;
}

__attribute__((no_sanitize("cfi"))) int32_t AVSessionService::MirrorToStreamCast(sptr<AVSessionItem> session)
{
    SLOGI("enter MirrorToStreamCast");
    if (!IsMirrorToStreamCastAllowed(session)) {
        appCastExit_ = false;
        return AVSESSION_SUCCESS;
    }
    checkEnableCast(true);
    {
        std::lock_guard lockGuard(checkEnableCastLock_);
        cacheEnableCastPids_.erase(GetCallingPid());
    }
    DeviceInfo deviceInfo;
    deviceInfo.deviceId_ = castDeviceId_;
    deviceInfo.deviceName_ = castDeviceName_;
    deviceInfo.deviceType_ = castDeviceType_;
    deviceInfo.castCategory_ = AVCastCategory::CATEGORY_REMOTE;
    deviceInfo.supportedProtocols_ = ProtocolType::TYPE_CAST_PLUS_STREAM;
    deviceInfo.providerId_ = 1;
    return session->RegisterListenerStreamToCast(castServiceNameStatePair_, deviceInfo);
}

void AVSessionService::SetIsSupportMirrorToStream(bool isSupportMirrorToStream)
{
    isSupportMirrorToStream_ = isSupportMirrorToStream;
}

void AVSessionService::ReportStartCastBegin(std::string func, const OutputDeviceInfo& outputDeviceInfo, int32_t uid)
{
    AVSessionRadarInfo info(func);
    info.bundleName_ = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    AVSessionRadar::GetInstance().StartCastBegin(outputDeviceInfo, info);
}

void AVSessionService::ReportStartCastEnd(std::string func, const OutputDeviceInfo& outputDeviceInfo,
    int32_t uid, int ret)
{
    AVSessionRadarInfo info(func);
    info.bundleName_ = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    if (ret == AVSESSION_SUCCESS) {
        AVSessionRadar::GetInstance().StartCastEnd(outputDeviceInfo, info);
    } else {
        info.errorCode_ = AVSessionRadar::GetRadarErrorCode(ret);
        AVSessionRadar::GetInstance().FailToStartCast(outputDeviceInfo, info);
    }
}
#endif

AVSessionSystemAbilityLoadCallback::AVSessionSystemAbilityLoadCallback(AVSessionService *ptr)
{
    SLOGI("AVSessionSystemAbilityLoadCallback construct");
    servicePtr_ = ptr;
}

AVSessionSystemAbilityLoadCallback::~AVSessionSystemAbilityLoadCallback()
{
    SLOGI("AVSessionSystemAbilityLoadCallback destruct");
}

void AVSessionSystemAbilityLoadCallback::OnLoadSACompleteForRemote(const std::string& deviceId,
    int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject)
{
    SLOGI("OnLoadSACompleteForRemote systemAbilityId:%{public}d, loaded with object:%{public}d",
        systemAbilityId, static_cast<int>(remoteObject != nullptr));
}

#ifdef DEVICE_MANAGER_ENABLE
AVSessionDeviceStateCallback::AVSessionDeviceStateCallback(AVSessionService *ptr)
{
    SLOGI("AVSessionDeviceStateCallback construct");
    servicePtr_ = ptr;
}
AVSessionDeviceStateCallback::~AVSessionDeviceStateCallback()
{
    SLOGI("AVSessionDeviceStateCallback destruct");
}

void AVSessionDeviceStateCallback::OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    SLOGI("AVSessionDeviceStateCallback OnDeviceOnline %{public}d", static_cast<int>(deviceInfo.deviceTypeId));
}

void AVSessionDeviceStateCallback::OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    SLOGI("AVSessionDeviceStateCallback OnDeviceReady %{public}d", static_cast<int>(deviceInfo.deviceTypeId));
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "OnDeviceReady get servicePtr_ nullptr");
    if (servicePtr_->ProcessTargetMigrate(true, deviceInfo)) {
        SLOGI("OnDeviceReady ProcessTargetMigrate pass");
    }
}

void AVSessionDeviceStateCallback::OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    SLOGI("AVSessionDeviceStateCallback OnDeviceOffline %{public}d", static_cast<int>(deviceInfo.deviceTypeId));
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "OnDeviceOffline get servicePtr_ nullptr");
    if (servicePtr_->ProcessTargetMigrate(false, deviceInfo)) {
        SLOGI("OnDeviceOffline ProcessTargetMigrate pass");
    }
}

void AVSessionDeviceStateCallback::OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    SLOGD("AVSessionDeviceStateCallback OnDeviceChanged %{public}d", static_cast<int>(deviceInfo.deviceTypeId));
}
#endif

int32_t AVSessionService::GetLocalDeviceType()
{
    int32_t deviceType = -1;
#ifdef DEVICE_MANAGER_ENABLE
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceType(serviceName, deviceType);
    CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "get local device type failed with ret:%{public}d", ret);
#endif
    return deviceType;
}

void AVSessionService::DoTargetDevListenWithDM()
{
#ifdef DEVICE_MANAGER_ENABLE
    localDeviceType_ = GetLocalDeviceType();
    isCastableDevice_ = (localDeviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1 ||
               localDeviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_TV);
    targetDeviceType_ = (localDeviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) ?
        DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE : DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    SLOGI("get localDeviceType:%{public}d", localDeviceType_);

    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    int32_t ret = GetTrustedDevicesInfo(deviceList);
    CHECK_AND_PRINT_LOG(ret == AVSESSION_SUCCESS, "get trusted devcie list fail with ret:%{public}d", ret);
    for (DistributedHardware::DmDeviceInfo& deviceInfo : deviceList) {
        if (ProcessTargetMigrate(true, deviceInfo)) {
            SLOGI("GetTrustedDevicesInfo find target");
        }
    }

    deviceStateCallback_ = std::make_shared<AVSessionDeviceStateCallback>(this);
    ret = DistributedHardware::DeviceManager::GetInstance().
        RegisterDevStateCallback(serviceName, "extra", deviceStateCallback_);
    SLOGE("RegisterDevStateCallback with ret:%{public}d", ret);
#endif
}

#ifdef DEVICE_MANAGER_ENABLE
bool AVSessionService::ProcessTargetMigrate(bool isOnline, const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    if (deviceInfo.deviceTypeId != targetDeviceType_ || !CheckWhetherTargetDevIsNext(deviceInfo)) {
        SLOGE("ProcessTargetMigrate wtih deviceType:%{public}d or version not fit", deviceInfo.deviceTypeId);
        return false;
    }
    if (!isOnline) {
        isMigrateTargetFound_ = false;
        DoDisconnectProcessWithMigrate(deviceInfo);
        deviceIdForMigrate_ = "";
    } else {
        isMigrateTargetFound_ = true;
        deviceIdForMigrate_ = std::string(deviceInfo.deviceId);
        DoConnectProcessWithMigrate(deviceInfo);
        if (localDeviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
            DoRemoteAVSessionLoad(deviceIdForMigrate_);
        }
    }
    return true;
}
#endif

void AVSessionService::DoRemoteAVSessionLoad(std::string remoteDeviceId)
{
    SLOGI("DoRemoteAVSessionLoad async with deviceId:%{public}s.",
        AVSessionUtils::GetAnonySessionId(remoteDeviceId).c_str());
    std::thread([this, remoteDeviceId]() {
        auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (mgr == nullptr) {
            SLOGE("DoRemoteAVSessionLoad get SystemAbilityManager fail");
            return;
        }
        sptr<IRemoteObject> remoteObject = nullptr;
        uint8_t outOfTime = doRemoteLoadRetryTime;
        while (remoteObject == nullptr && outOfTime > 0) {
            outOfTime--;
            std::this_thread::sleep_for(std::chrono::milliseconds(CLICK_TIMEOUT));
            remoteObject = mgr->CheckSystemAbility(AVSESSION_SERVICE_ID, remoteDeviceId);
            if (remoteObject != nullptr) {
                SLOGI("DoRemoteAVSessionLoad done with remoteObject get");
                return;
            } else {
                SLOGI("DoRemoteAVSessionLoad get null, retryLeftTime:%{public}u", outOfTime);
            }
        }
    }).detach();
}

#ifdef DEVICE_MANAGER_ENABLE
void AVSessionService::DoConnectProcessWithMigrate(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    if (localDeviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        DoConnectProcessWithMigrateServer(deviceInfo);
    } else {
        DoConnectProcessWithMigrateProxy(deviceInfo);
    }
}

void AVSessionService::DoConnectProcessWithMigrateServer(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::string networkId = std::string(deviceInfo.networkId);
    SLOGI("DoConnectProcessWithMigrateServer with deviceType:%{public}d|deviceId:%{public}s.",
        deviceInfo.deviceTypeId,
        AVSessionUtils::GetAnonySessionId(networkId).c_str());
    if (migrateAVSessionServerMap_.find(networkId) == migrateAVSessionServerMap_.end()) {
        CHECK_AND_RETURN_LOG(DoHisMigrateServerTransform(networkId) == ERR_SESSION_NOT_EXIST,
            "hisMigrate transform done");
        std::shared_ptr<MigrateAVSessionServer> migrateAVSessionServer =
            std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, networkId);
        migrateAVSessionServer->Init(this);
        migrateAVSessionServer->LocalFrontSessionArrive(localFrontSessionId_);
        MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(
            MigrateAVSessionManager::migrateSceneNext,
            migrateAVSessionServer);
        migrateAVSessionServerMap_.insert({networkId, migrateAVSessionServer});
        SLOGI("new MigrateServer success:%{public}d", static_cast<int>(migrateAVSessionServerMap_.size()));
    } else {
        SLOGE("server already alive:%{public}d", static_cast<int>(migrateAVSessionServerMap_.size()));
    }
}

void AVSessionService::DoConnectProcessWithMigrateProxy(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::string networkId = std::string(deviceInfo.networkId);
    SLOGI("DoConnectProcessWithMigrateProxy with deviceType:%{public}d|deviceId:%{public}s.",
        deviceInfo.deviceTypeId,
        AVSessionUtils::GetAnonySessionId(networkId).c_str());
    std::lock_guard lockGuard(migrateProxyMapLock_);
    if (migrateAVSessionProxyMap_.find(networkId) == migrateAVSessionProxyMap_.end()) {
        std::string localDevId;
        GetLocalNetworkId(localDevId);
        std::shared_ptr<MigrateAVSessionProxy> migrateAVSessionProxy =
            std::make_shared<MigrateAVSessionProxy>(this, MigrateAVSessionManager::MSG_HEAD_MODE_FOR_NEXT, localDevId);
        MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId,
            MigrateAVSessionManager::migrateSceneNext, migrateAVSessionProxy);
        migrateAVSessionProxyMap_.insert({networkId, std::static_pointer_cast<SoftbusSession>(migrateAVSessionProxy)});
        SLOGI("new proxy success:%{public}d", static_cast<int>(migrateAVSessionProxyMap_.size()));
    } else {
        SLOGE("proxy already alive:%{public}d", static_cast<int>(migrateAVSessionProxyMap_.size()));
    }
}

void AVSessionService::DoDisconnectProcessWithMigrate(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    if (localDeviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        DoDisconnectProcessWithMigrateServer(deviceInfo);
    } else {
        DoDisconnectProcessWithMigrateProxy(deviceInfo);
    }
}

void AVSessionService::DoDisconnectProcessWithMigrateServer(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::string networkId = std::string(deviceInfo.networkId);
    SLOGI("DoDisconnectMigrateServer networkId:%{public}s|%{public}d",
        AVSessionUtils::GetAnonySessionId(networkId).c_str(), static_cast<int>(migrateAVSessionServerMap_.size()));
    if (migrateAVSessionServerMap_.find(networkId) != migrateAVSessionServerMap_.end()) {
        std::shared_ptr<MigrateAVSessionServer> migrateAVSessionServer =
            migrateAVSessionServerMap_[networkId];
        if (migrateAVSessionServer != nullptr) {
            MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(MigrateAVSessionManager::migrateSceneNext);
            migrateAVSessionServer->DoPostTasksClear();
        } else {
            SLOGE("get server nullptr");
        }
        migrateAVSessionServerMap_.erase(networkId);
    } else {
        SLOGE("DoDisconnectProcessWithMigrateServer find networkId not exist");
    }
}

void AVSessionService::DoDisconnectProcessWithMigrateProxy(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::string networkId = std::string(deviceInfo.networkId);
    MigrateAVSessionManager::GetInstance().ReleaseRemoteSessionProxy(networkId,
        MigrateAVSessionManager::migrateSceneNext);
    std::lock_guard lockGuard(migrateProxyMapLock_);
    SLOGI("DoDisconnectProcessWithMigrateProxy networkId:%{public}s|%{public}d.",
        AVSessionUtils::GetAnonySessionId(networkId).c_str(), static_cast<int>(migrateAVSessionProxyMap_.size()));
    if (migrateAVSessionProxyMap_.find(networkId) != migrateAVSessionProxyMap_.end()) {
        migrateAVSessionProxyMap_.erase(networkId);
        PublishEvent(remoteMediaNone);
    } else {
        SLOGE("DoDisconnectProcessWithMigrateProxy find networkId not exist");
    }
}
#endif

int32_t AVSessionService::DoHisMigrateServerTransform(std::string networkId)
{
    SLOGI("DoHisMigrateServerTransform size:%{public}d", static_cast<int>(migrateAVSessionServerMap_.size()));
    auto it = migrateAVSessionServerMap_.begin();
    if (it != migrateAVSessionServerMap_.end()) {
        std::shared_ptr<MigrateAVSessionServer> migrateAVSessionServer = it->second;
        CHECK_AND_RETURN_RET_LOG(migrateAVSessionServer != nullptr, AVSESSION_ERROR, "get server nullptr");
        migrateAVSessionServer->DoPostTasksClear();
        migrateAVSessionServer->RefreshDeviceId(networkId);
        it = migrateAVSessionServerMap_.erase(it);
        migrateAVSessionServerMap_.insert({networkId, migrateAVSessionServer});
        SLOGI("DoHisMigrateServerTransform for:%{public}s", AVSessionUtils::GetAnonySessionId(networkId).c_str());
        return AVSESSION_SUCCESS;
    }

    return ERR_SESSION_NOT_EXIST;
}

void AVSessionService::UpdateLocalFrontSession(std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront)
{
    CHECK_AND_RETURN_LOG(sessionListForFront != nullptr, "UpdateLocalFrontSession get sessionListForFront nullptr");
    std::string preloadSessionId;
    if (sessionListForFront->size() <= 0) {
        SLOGI("UpdateLocalFrontSession with empty list");
        preloadSessionId = "";
        NotifyLocalFrontSessionChangeForMigrate(preloadSessionId);
        return;
    }
    if (topSession_ != nullptr && !topSession_->IsCasting()) {
        preloadSessionId = topSession_->GetSessionId();
        NotifyLocalFrontSessionChangeForMigrate(preloadSessionId);
        return;
    }
    for (const auto& session : *sessionListForFront) {
        if (session == nullptr || session->IsCasting()) {
            continue;
        }
        preloadSessionId = session->GetSessionId();
        break;
    }
    NotifyLocalFrontSessionChangeForMigrate(preloadSessionId);
}

void AVSessionService::NotifyLocalFrontSessionChangeForMigrate(std::string localFrontSessionIdUpdate)
{
    SLOGI("notify migrate with sessionId:%{public}s|%{public}s|%{public}d",
        AVSessionUtils::GetAnonySessionId(localFrontSessionIdUpdate).c_str(),
        AVSessionUtils::GetAnonySessionId(localFrontSessionId_).c_str(),
        static_cast<int>(migrateAVSessionServerMap_.size()));
    if (migrateAVSessionServerMap_.size() <= 0) {
        SLOGE("NotifyLocalFrontSessionChangeForMigrate with no migrate");
        localFrontSessionId_ = localFrontSessionIdUpdate;
        return;
    }
    for (auto it = migrateAVSessionServerMap_.begin(); it != migrateAVSessionServerMap_.end(); it++) {
        std::shared_ptr<MigrateAVSessionServer> migrateAVSessionServer = it->second;
        if (migrateAVSessionServer == nullptr) {
            SLOGE("notify session change but get migrateserver null, continue");
            continue;
        }
        if (localFrontSessionId_.empty() && localFrontSessionIdUpdate.length() > 0) {
            DoRemoteAVSessionLoad(deviceIdForMigrate_);
            migrateAVSessionServer->LocalFrontSessionArrive(localFrontSessionIdUpdate);
        } else if (!localFrontSessionId_.empty() && localFrontSessionIdUpdate.length() > 0
            && localFrontSessionId_ != localFrontSessionIdUpdate) {
            migrateAVSessionServer->LocalFrontSessionChange(localFrontSessionIdUpdate);
        } else if (!localFrontSessionId_.empty() && localFrontSessionIdUpdate.empty()) {
            DoRemoteAVSessionLoad(deviceIdForMigrate_);
            migrateAVSessionServer->LocalFrontSessionLeave(localFrontSessionId_);
        }
    }
    localFrontSessionId_ = localFrontSessionIdUpdate;
}

#ifdef DEVICE_MANAGER_ENABLE
bool AVSessionService::CheckWhetherTargetDevIsNext(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    cJSON* jsonData = cJSON_Parse(deviceInfo.extraData.c_str());
    CHECK_AND_RETURN_RET_LOG(jsonData != nullptr, false, "get jsonData nullptr");
    if (cJSON_IsInvalid(jsonData) || cJSON_IsNull(jsonData)) {
        SLOGE("get jsonData invalid");
        cJSON_Delete(jsonData);
        return false;
    }
    if (cJSON_HasObjectItem(jsonData, "OS_TYPE")) {
        cJSON* osTypeItem = cJSON_GetObjectItem(jsonData, "OS_TYPE");
        if (osTypeItem == nullptr || cJSON_IsInvalid(osTypeItem) || !cJSON_IsNumber(osTypeItem)) {
            SLOGE("get osTypeItem invalid");
            cJSON_Delete(jsonData);
            return false;
        }
        if (osTypeItem->valueint > 0 || osTypeItem->valuedouble > 0) {
            cJSON_Delete(jsonData);
            return true;
        }
    }

    cJSON_Delete(jsonData);
    return false;
}
#endif

int32_t AVSessionService::GetDistributedSessionControllersInner(const DistributedSessionType& sessionType,
    std::vector<sptr<IRemoteObject>>& sessionControllers)
{
    std::lock_guard lockGuard(migrateProxyMapLock_);
    if (sessionType != DistributedSessionType::TYPE_SESSION_REMOTE || migrateAVSessionProxyMap_.empty()) {
        SLOGE("GetDistributedSessionControllersInner with err type:%{public}d|proxyEmpty:%{public}d",
            static_cast<int>(sessionType), static_cast<int>(migrateAVSessionProxyMap_.empty()));
        return ERR_REMOTE_CONNECTION_NOT_EXIST;
    }
    for (const auto& pair : migrateAVSessionProxyMap_) {
        std::shared_ptr<MigrateAVSessionProxy> migrateAVSessionProxy =
            std::static_pointer_cast<MigrateAVSessionProxy>(pair.second);
        CHECK_AND_CONTINUE(migrateAVSessionProxy != nullptr);
        migrateAVSessionProxy->GetDistributedSessionControllerList(sessionControllers);
    }
    SLOGI("GetDistributedController size:%{public}d", static_cast<int>(sessionControllers.size()));
    return AVSESSION_SUCCESS;
}

void AVSessionService::NotifyRemoteBundleChange(const std::string bundleName)
{
    std::lock_guard lockGuard(migrateProxyMapLock_);
    if (migrateAVSessionProxyMap_.empty()) {
        SLOGE("not in migrate proxy scene, return");
        return;
    }
    PublishEvent(bundleName.empty() ? remoteMediaNone : remoteMediaAlive);
}
}