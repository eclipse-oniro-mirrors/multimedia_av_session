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

namespace OHOS::AVSession {
void AVSessionService::SuperLauncher(std::string deviceId, std::string serviceName,
    std::string extraInfo, const std::string& state)
{
    SLOGI("SuperLauncher serviceName: %{public}s, state: %{public}s", serviceName.c_str(), state.c_str());

    if (state == "IDLE" && serviceName == "SuperLauncher-Dual") {
        MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(serviceName);
        if (migrateAVSession_ != nullptr) {
            RemoveInnerSessionListener(migrateAVSession_.get());
        }
    } else if (state == "CONNECTING" && serviceName == "SuperLauncher-Dual") {
        if (migrateAVSession_ == nullptr) {
            migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
        }
        migrateAVSession_->Init(this);
        MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(serviceName, migrateAVSession_);
        AddInnerSessionListener(migrateAVSession_.get());
        AudioDeviceManager::GetInstance().InitAudioStateCallback(migrateAVSession_, deviceId);
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if ((serviceName == "HuaweiCast" || serviceName == "HuaweiCast-Dual") &&
        (state == "IDLE" || state == "CONNECT_SUCC")) {
        castServiceNameMapState_[serviceName] = state;
        isSupportMirrorToStream_ = false;
        castDeviceId_ = "0";
        castDeviceName_ = " ";
        castDeviceType_ = 0;
        std::string info;
        std::string::size_type beginPos = 0;
        std::string::size_type endPos = extraInfo.find(seperator);
        while (endPos != std::string::npos) {
            info = extraInfo.substr(beginPos, endPos - beginPos);
            beginPos = endPos + seperator.size();
            endPos = extraInfo.find(seperator, beginPos);
            SplitExtraInfo(info);
        }
        if (beginPos != extraInfo.length()) {
            info = extraInfo.substr(beginPos);
            SplitExtraInfo(info);
        }
        NotifyMirrorToStreamCast();
        int32_t sessionSize = static_cast<int32_t>(GetUsersManager().GetContainerFromAll().GetAllSessions().size());
        if ((sessionSize == 0 || (sessionSize == 1 && CheckAncoAudio())) && !is2in1_ && state == "IDLE") {
            SLOGI("call disable cast for cast idle");
            checkEnableCast(false);
        }
    }
#endif
}

void AVSessionService::NotifyMigrateStop(const std::string &deviceId)
{
    if (migrateAVSession_ == nullptr) {
        SLOGI("NotifyMigrateStop without migrate, create new");
        migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
    }
    std::lock_guard lockGuard(sessionServiceLock_);
    migrateAVSession_->StopObserveControllerChanged(deviceId);
    AudioDeviceManager::GetInstance().UnInitAudioStateCallback();
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
void AVSessionService::SplitExtraInfo(std::string info)
{
    if (info.find("SUPPORT_MIRROR_TO_STREAM") != std::string::npos && info.find("true") != std::string::npos) {
        isSupportMirrorToStream_ = true;
    }
    if (info.find("deviceId") != std::string::npos && info.find(":") != std::string::npos) {
        std::string::size_type idBeginPos = info.find(":");
        castDeviceId_ = info.substr(idBeginPos + beginAddPos,
            info.length() -idBeginPos - endDecPos); // "deviceId" : "xxxx"
    }
    if (info.find("deviceName") != std::string::npos && info.find(":") != std::string::npos) {
        std::string::size_type nameBeginPos = info.find(":");
        castDeviceName_ = info.substr(nameBeginPos + beginAddPos,
            info.length() - nameBeginPos - endDecPos); // "deviceName" : "xxxx"
    }
    if (info.find("deviceType") != std::string::npos && info.find(":") != std::string::npos) {
        std::string::size_type typeBeginPos = info.find(":");
        std::string tmpType = info.substr(typeBeginPos + typeAddPos, info.length()); // "deviceType" : xxx
        castDeviceType_ = atoi(tmpType.c_str());
    }
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

// LCOV_EXCL_START
void AVSessionService::HandleAppStateChange(int uid, int state)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGD("uidForAppStateChange_ = %{public}d, uid = %{public}d, state = %{public}d",
        uidForAppStateChange_, uid, state);
    if (uidForAppStateChange_ == uid) {
        if (state == appState) {
            return;
        }
        if (state == static_cast<int>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND)) {
            SLOGI("enter notifyMirrorToStreamCast by background to foreground state change, and counts = 2");
            NotifyMirrorToStreamCast();
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
    SLOGI("checkEnableCast enable:%{public}d, isInCast:%{public}d", enable, isInCast_);
    if (enable == true && isInCast_ == false) {
        isInCast_ = true;
        return AVRouter::GetInstance().Init(this);
    } else if (enable == false && isInCast_ == true) {
        CHECK_AND_RETURN_RET_LOG(!((GetContainer().GetAllSessions().size() > 1 ||
            (GetContainer().GetAllSessions().size() == 1 && !CheckAncoAudio())) && !is2in1_),
            AVSESSION_SUCCESS, "can not release cast with session alive");
        CHECK_AND_RETURN_RET_LOG(!(castServiceNameMapState_["HuaweiCast"] == deviceStateConnection ||
            castServiceNameMapState_["HuaweiCast-Dual"] == deviceStateConnection),
            AVSESSION_SUCCESS, "can not release cast with casting");
        isInCast_ = AVRouter::GetInstance().Release();
    } else {
        SLOGD("AVRouter Init in nothing change");
    }
    return AVSESSION_SUCCESS;
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
    if (isSourceInCast_) {
        AVSessionRadarInfo info("AVSessionService::CreateSessionByCast");
        AVSessionRadar::GetInstance().StartConnect(info);
        SLOGI("Create Cast in source, return");
        return;
    }
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

int32_t AVSessionService::StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("SessionId is %{public}s", AVSessionUtils::GetAnonySessionId(sessionToken.sessionId).c_str());
    sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionToken.sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, ERR_SESSION_NOT_EXIST, "session %{public}s not exist",
        AVSessionUtils::GetAnonySessionId(sessionToken.sessionId).c_str());
    ReportStartCastBegin("AVSessionService::StartCast", outputDeviceInfo, session->GetDescriptor().uid_);
    int32_t ret = session->StartCast(outputDeviceInfo);
    ReportStartCastEnd("AVSessionService::StartCast", outputDeviceInfo, session->GetDescriptor().uid_, ret);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "StartCast failed");
    SLOGD("StartCast set isSourceInCast");
    isSourceInCast_ = true;

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

void AVSessionService::NotifyMirrorToStreamCast()
{
    for (auto& session : GetContainer().GetAllSessions()) {
        if (session != nullptr && session->GetUid() == uidForAppStateChange_ && isSupportMirrorToStream_ &&
            !AppManagerAdapter::GetInstance().IsAppBackground(session->GetUid(), session->GetPid())) {
            MirrorToStreamCast(session);
        }
    }
    if (castServiceNameMapState_["HuaweiCast"] == deviceStateDisconnection ||
        castServiceNameMapState_["HuaweiCast-Dual"] == deviceStateDisconnection) {
        DeviceInfo localDeviceInfo;
        AVRouter::GetInstance().SetServiceAllConnectState(-1, localDeviceInfo);
    }
}

__attribute__((no_sanitize("cfi"))) int32_t AVSessionService::MirrorToStreamCast(sptr<AVSessionItem>& session)
{
    SLOGI("enter MirrorToStreamCast");
    if (!is2in1_) {
        if (castServiceNameMapState_["HuaweiCast"] == deviceStateConnection ||
            castServiceNameMapState_["HuaweiCast-Dual"] == deviceStateConnection) {
            checkEnableCast(true);
            DeviceInfo deviceInfo;
            deviceInfo.deviceId_ = castDeviceId_;
            deviceInfo.deviceName_ = castDeviceName_;
            deviceInfo.deviceType_ = castDeviceType_;
            deviceInfo.castCategory_ = AVCastCategory::CATEGORY_REMOTE;
            deviceInfo.supportedProtocols_ = ProtocolType::TYPE_CAST_PLUS_STREAM;
            deviceInfo.providerId_ = 1;
            return session->RegisterListenerStreamToCast(castServiceNameMapState_, deviceInfo);
        }
    }
    return AVSESSION_SUCCESS;
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

int32_t AVSessionService::GetLocalDeviceType()
{
    int32_t deviceType = -1;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceType(serviceName, deviceType);
    CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "get local device type failed with ret:%{public}d", ret);
    return deviceType;
}

void AVSessionService::DoTargetDevListenWithDM()
{
    localDeviceType_ = GetLocalDeviceType();
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
}

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

void AVSessionService::DoRemoteAVSessionLoad(std::string remoteDeviceId)
{
    SLOGI("DoRemoteAVSessionLoad with deviceId:%{public}s", remoteDeviceId.c_str());
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGE("DoRemoteAVSessionLoad get SystemAbilityManager fail");
        return;
    }
    abilityLoadCallback_ = new AVSessionSystemAbilityLoadCallback(this);
    int32_t ret = mgr->LoadSystemAbility(AVSESSION_SERVICE_ID, remoteDeviceId, abilityLoadCallback_);
    SLOGI("DoRemoteAVSessionLoad LoadSystemAbility with ret:%{public}d", ret);
}

void AVSessionService::DoConnectProcessWithMigrate(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    if (localDeviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        DoConnectProcessWithMigrateServer(deviceInfo);
    } else {
        DoDisconnectProcessWithMigrateServer(deviceInfo);
    }
}

void AVSessionService::DoConnectProcessWithMigrateServer(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    SLOGI("DoConnectProcessWithMigrateServer with deviceType:%{public}d", deviceInfo.deviceTypeId);
    std::string networkId = std::string(deviceInfo.networkId);
    if (migrateAVSessionServerMap_.find(networkId) == migrateAVSessionServerMap_.end()) {
        std::shared_ptr<MigrateAVSessionServer> migrateAVSessionServer =
            std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT);
        migrateAVSessionServer->Init(this);
        migrateAVSessionServer->LocalFrontSessionArrive(localFrontSessionId_);
        MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(MigrateAVSessionManager::migrateSceneNext,
            migrateAVSessionServer);
        migrateAVSessionServerMap_.insert({networkId, migrateAVSessionServer});
        SLOGI("DoConnectProcessWithMigrateServer create migrate server success");
    } else {
        SLOGE("DoConnectProcessWithMigrateServer find migrate server already alive");
    }
}

void AVSessionService::DoConnectProcessWithMigrateProxy(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    SLOGI("DoConnectProcessWithMigrateProxy with deviceType:%{public}d", deviceInfo.deviceTypeId);
    std::string networkId = std::string(deviceInfo.networkId);
    if (migrateAVSessionProxyMap_.find(networkId) == migrateAVSessionProxyMap_.end()) {
        std::shared_ptr<MigrateAVSessionProxy> migrateAVSessionProxy =
            std::make_shared<MigrateAVSessionProxy>(this);
        MigrateAVSessionManager::GetInstance().CreateRemoteSessionProxy(networkId,
            MigrateAVSessionManager::migrateSceneNext, migrateAVSessionProxy);
        migrateAVSessionProxyMap_.insert({networkId, std::static_pointer_cast<SoftbusSession>(migrateAVSessionProxy)});
        SLOGI("DoConnectProcessWithMigrateProxy create migrate proxy success");
    } else {
        SLOGE("DoConnectProcessWithMigrateProxy find migrate proxy already alive");
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
    SLOGI("DoDisconnectProcessWithMigrateServer with deviceType:%{public}d", deviceInfo.deviceTypeId);
    std::string networkId = std::string(deviceInfo.networkId);
    MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(MigrateAVSessionManager::migrateSceneNext);
    if (migrateAVSessionServerMap_.find(networkId) != migrateAVSessionServerMap_.end()) {
        migrateAVSessionServerMap_.erase(networkId);
    } else {
        SLOGE("DoDisconnectProcessWithMigrateServer find networkId not exist");
    }
}

void AVSessionService::DoDisconnectProcessWithMigrateProxy(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    SLOGI("DoDisconnectProcessWithMigrateProxy with networkId:%{public}s", deviceInfo.networkId);
    std::string networkId = std::string(deviceInfo.networkId);
    MigrateAVSessionManager::GetInstance().ReleaseRemoteSessionProxy(networkId,
        MigrateAVSessionManager::migrateSceneNext);
    if (migrateAVSessionProxyMap_.find(networkId) != migrateAVSessionProxyMap_.end()) {
        migrateAVSessionProxyMap_.erase(networkId);
    } else {
        SLOGE("DoDisconnectProcessWithMigrateProxy find networkId not exist");
    }
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
    SLOGI("NotifyLocalFrontSessionChangeForMigrate with sessionId:%{public}s",
        AVSessionUtils::GetAnonySessionId(localFrontSessionIdUpdate).c_str());
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
            migrateAVSessionServer->LocalFrontSessionArrive(localFrontSessionId_);
        }
    }
    localFrontSessionId_ = localFrontSessionIdUpdate;
}

bool AVSessionService::CheckWhetherTargetDevIsNext(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    Json::Reader reader;
    Json::Value jsonData;
    if (!reader.parse(deviceInfo.extraData, jsonData)) {
        SLOGE("CheckWhetherTargetDevIsNext json parse failed");
        return false;
    }
    if (jsonData.isMember("OS_TYPE")) {
        Json::Value osValue = jsonData["OS_TYPE"];
        if (osValue.isNumeric()) {
            double number = osValue.asDouble();
            if (number > 0) {
                return true;
            }
        }
    }
    return false;
}

int32_t AVSessionService::GetDistributedSessionControllersInner(const DistributedSessionType& sessionType,
    std::vector<sptr<IRemoteObject>>& sessionControllers)
{
    if (sessionType == DistributedSessionType::TYPE_SESSION_REMOTE && !migrateAVSessionProxyMap_.empty()) {
        for (const auto& pair : migrateAVSessionProxyMap_) {
            std::shared_ptr<MigrateAVSessionProxy> migrateAVSessionProxy =
                std::static_pointer_cast<MigrateAVSessionProxy>(pair.second);
            CHECK_AND_CONTINUE(migrateAVSessionProxy != nullptr);
            migrateAVSessionProxy->GetDistributedSessionControllerList(sessionControllers);
        }
    }
    SLOGI("GetDistributedSessionControllersInner with size:%{public}d", static_cast<int>(sessionControllers.size()));
    return AVSESSION_SUCCESS;
}
}